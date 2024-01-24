# Splicecom Vulnerabilities

## Background
Splicecom are a telephony provider providing on-prem and hosted solutions. Their Maximiser S8000 product is a software PBX that can interface with their proprietary phones and apps as well as standard SIP endpoints.

https://www.splicecom.com/products-services/voice-platforms/s8000-soft-pbx

To provide a solution for remote/mobile users they have a product called SSL Gateway (previously iPCS Gateway). 

https://splicecom.com/resources/platforms_&_deployment_2015.pdf

## SSL Gateway
There are a number of weaknesses in this system, so the name SL Gateway is probably more apt.

The SSL gateway runs on a Linux server (usually the same as the Maximiser system) and enables remote users to connect to the Maximiser system to make and receive calls over the internet. 
The client could be a PCS Handset or an Android or iOS device running the iPCS app.

Remote authentication to the system is very basic prior to version 1.5, and accounts are protected by simply the extension number (e.g. 2001) and a passcode (e.g. 1234)

Because the passcode is often input into a desk phone it is likely to be numeric and simple in nature.

### Protocol
The gateway listens on an SSL socket and accepts commands in the form of comma separated ASCII strings.

The default port for SSL Gateway is 5000, although 5020 has also been observed.

Once a client connects they authenticate by sending the following:

```
LOGIN,EXTENSION,PASSCODE,FIXED,CLIENT_NAME,VERSION,DEVICE_GUID,FEATURE_FLAGS,REMOTE_IP,PUSH_TOKEN
```
#### Field definitions

| Field  | Description | Example Value |
| ------------- | ------------- |  ------------- |
| LOGIN  | Command | Fixed Value | 
| EXTENSION | User extension | 2001 |
| PASSCODE | User passcode | 1337 |
| FIXED | Fixed value of 1234 | 1234 |
| CLIENT_NAME | User extension | iPCS 2.7.2 |
| VERSION | Client version | 75 |
| DEVICE_GUID | Client device id | b63576ae-56ae-4cbc-9c1a-5ca72f2b0e2b |
| REMOTE_IP | The servers remote address in hex | 7f000001 |
| PUSH_TOKEN | A valid firebase push notification token | https://push.splicecom.com:8080/device/40ff3a0a06e74de88db8874dd40706ed934ea7fb1ce4ce3051ad172472a7d406?v=1 |

A successful authentication would receive a response of:
```
USER RECORD CHANGED,,00000001,"",""
```

Followed by additional system information (*GUIDs redacted to protect the innocent*):
```
LOGGED IN AS,"00000000-0000-0000-0000-000000000000","2001","1337","127.0.0.1","cn=1,cn=iPCS 00000000-0000-0000-0000-000000000000,cn=Customer Name,cn=Modules","!Customer Name.Customer Name Site Primary/Provider","1.4(166)","uPCS","00000000-0000-0000-0000-000000000000",0,"PUSHOK",0
```

A failure would respond with:
```
NOT LOGGED IN
```

The Firebase push token is required for the authentication to succeed. The easiest way to obtain this is to observe the traffic generated from an installation of the iPCS App. The client will generate this token and send it with their login request.

A push token doesn't last forever and can be invalidated by a number of events. If you are failing to login even with valid credentials then regenerate your token.

## Vulnerabilities

The vulnerabilities below affect the Splicecom Maximiser Soft PBX platform (which can be hosted or on-prem) and users connecting to any Splicecom hosted voice solution.

### CVE-2023-33759 - Lack of brute force protection
If authentication fails to the SSL Gateway the system does not close the connection, so another attempt can be made immediately.

Up until version 1.5 of the Maximiser Soft PBX product there is no rate limiting on failed attempts. Starting with version 1.5 a new "Access Control" feature has been adding, allowing rate limiting and IP banning. However this feature is not advertised or enabled by default, so uptake will be low.

As such all 4 digit PIN combinations could be tried in around 90 seconds.

In order to authenticate to a remote SSL gateway we need 2 things:
 - The IP and port
 - A username/extension number

Available SSL gateways could be enumerated by looking for the subject in the certificate or the default thumbprint. The port is usually 5000.

Usernames are usually 3 or 4 digits. They will often be sequential. For a lot of companies they will simply be the last 4 digits of a users phone number. This is often easy to find using standard OSINT techniques.

I have provided a multi-threaded brute forcer as a proof of concept. This script also makes it easy to generate a valid push token. Further information at the bottom of this page.

### CVE-2023-33757 - No certificate trust checking
The mobile applications do not perform any sort of SSL validation. This is true for certificate trust as well as subject matching.

These applications are used by clients to connection to any Splicecom system providing voice servives.

This affects the following applications:
- Splicecom iPCS (iOS App) v1.3.4
- Splicecom iPCS2 (iOS App) v2.8 and below
- Splicecom iPCS (Android App) v1.8.5 and below

Without trust validation the effectiveness of SSL is drastically reduced. MiTM attacks are easy and effective since authentication credentials are sent in clear text over the TLS connection.

Improvements have been made to trust and name validation in the latest apps but they are not 100% and the default vendor certificate remains trusted by default.

Furthermore certificate name validation and revocation checking do not appear to be fully implemented. 

### CVE-2023-33760 - Default SSL certificate on SSL Gateway
Installations of the SSL Gateway will use a vendor supplied self-signed SSL certificate.

There are no prompts during installation or in the management interface to change this certificate. This is a poor default and of course as a result there are a large number of deployments still using this.

The default certificate has a thumbprint of `f486aa65f6a077a50c9028d34a07216c59d34d29` and it is available in this repo as default.pem.

An older default certificate with thumbprint `ea00c066e3fa1ac2a63c126443c22a42b38cdf32` is also provided as default2.pem.

Starting with Maximiser Soft PBX version 1.5 a "trust default certificate" option has been provided. This can steer newer clients running (iPCS2 for iOS App v2.9 and above and iPCS for Android v1.8.6 and above) to reject the default vendor certificate. I would consider this a partial fix since 1) It is not on by default, 2) A connection needs to be established before this configuration data is downloaded to the app.

Splicecom have not shared when a complete fix for this will be available and the apps will continue to trust these vendor certificates by default due to their wide deployment ¯\\_(ツ)_/¯

### CVE-2023-33758 - XSS / User input not sanitised
In just the login message alone there are two fields that can accept arbitrary data.
This data will be rendered out in the (mostly PHP) management interface in a number of different places.

As a reminder, the login message looks like this:
```
LOGIN,EXTENSION,PASSCODE,FIXED,CLIENT_NAME,VERSION,DEVICE_GUID,FEATURE_FLAGS,REMOTE_IP,PUSH_TOKEN
```

CLIENT_NAME and DEVICE_GUID can both be manipulated to trigger XSS in the portal. Depending on the values set this can also perform a limited denial of service by rendering parts of the portal (and also the backup files) inoperable.
```
LOGIN,2001,1234,1234,RickPhone 2.7.3<img src=http://domain.com/rr.gif>,75,00000000-0000-0000-0000-000000000000,73,7f000001,https://push.splicecom.com:8080/device/40ff3a0a06e74de88db8874dd40706ed934ea7fb1ce4ce3051ad172472a7d406?v=1
```
```
LOGIN,2002,1234,1234,IPCS 2.7.2,75,<img src=x onerror=alert(1) foo= ,73,7f000001,https://push.splicecom.com:8080/device/40ff3a0a06e74de88db8874dd40706ed934ea7fb1ce4ce3051ad172472a7d406?v=1
```
```
LOGIN,2003,1234,1234,IPCS 2.7.2<script>alert('javascript')</script>,75,00000000-0000-0000-0000-000000000000,73,7f000001,https://push.splicecom.com:8080/device/40ff3a0a06e74de88db8874dd40706ed934ea7fb1ce4ce3051ad172472a7d406?v=1
```

This results in:
![CVE-2023-33758](https://github.com/twignet/splicecom/blob/master/CVE-2023-33758.png?raw=true)

This is fixed in Maximiser Soft PBX version 1.5 by escaping the output in the management interface.

## Improvements in future Maximiser versions
Starting with system version 1.5 a number of changes have been made:
 - Unsanitised user data is escaped on some of the mangement pages
 - An access control layer has been implemented to ban IPs with a number of failures over a period of time (configurable). This is not on by default.
 - Client certificate based authentication is available, however:
   - This is not on by default
   - Requires iPCS2 (iOS) v2.9 or iPCS (Android) v1.8.6 or newer
   - A default client certificate is bundled in the Apps (i have extracted this as sslprov.pem in the repo)
   - On first connection this certificate can be replaced with a customer specific secondary certificate, downloaded from the gateway. This certificate is shared amongst all users
   - A server side parameter exists to only trust these "secondary" certificates


## iPCS Brute Forcer

### Overview
This brute forcer demonstrates how quickly and easily an iPCS user can be compromised

Firstly you need to perform reconnaissance and determine your target username and server. This tool does not help with that, although this is not a difficult task based on the contents on this page.

When you run the tool without providing a token it will start a listening service on port 5000 and wait to capture a push token. Simply install the iPCS2 App on iOS or iPCS App on Android and point the config at your local address (assuming you are on the same network and no firewalls block the traffic).

The tool will try a list of the most common 4 digit PINs, included in the file `dictionary.txt`. You can add to this file. 

If no valid PIN is found it will then continue with a sequential brute force up to 999999.


#### Tips

A valid username and passcode may be rejected if:
 - The push token is invalid or has been registered on another system 
 - The brute force speed is too fast and is overwhelming the remote system

3 threads and a speed setting of medium is usually fine. 4 threads and fast is likely fine, depending on target hardware. More than that you may get false negative results.

#### Client Certificates
In Maximiser version 1.5 and above a Client Side Certificate may be required, depending on system configuration. The default Client certificate is bundled with this tool and is automatically used. If "Enable Provisioning" is not enabled on the remote system then this default certificate will be rejected and a connection is not possible.

### Installation
ipcs_brute.py is included in this repo. Clone and run with Python 3. Only standard libraries are required.


### Basic example

```
python ipcs_brute.py --server 1.2.3.4 --user 2001
```

### Advanced example


```
python ipcs_brute.py --server 1.2.3.4:5000 --user 2001 --speed fast --token https://push.splicecom.com:8080/device/40ff3a0a06e74de88db8874dd40706ed934ea7fb1ce4ce3051ad172472a7d406?v=1 --threads 4 --loglevel 2
```
### Options reference

| Argument  | Description | Example |
| ------------- | ------------- |  ------------- |
| --server  | Server IP and optional port | 1.2.3.4:5000 | 
| --user | User extension | 2001 |
| --speed | Time between attempts (fast,medium,slow) | fast |
| --token | Push notification token | https://push.splicecom.com:8080/device/40ff3a0a06e74de88db8874dd40706ed934ea7fb1ce4ce3051ad172472a7d406?v=1 |
| --threads | Number of threads / concurrent connections | 4 |
| --loglevel | Verbosity of output (1 least verbose, 3 most verbose) | 2 |

