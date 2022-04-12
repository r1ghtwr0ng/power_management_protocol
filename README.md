# Power Management Protocol
### About
&nbsp;&nbsp;&nbsp;&nbsp;This project is a Computer Networking coursework using a Python3 implementation of a lightweight but secure power management protocol (PMP).
It allows easily viewing a remote device's power settings and managing its state. This implementation does not currently support NAT punchthrough.

&nbsp;&nbsp;&nbsp;&nbsp;The protocol is build on top of the UDP transport layer protocol and uses Diffie-Hellman key exchange to establish shared secrets, whose SHA256 hash is used as the AES CBC key for encrypting subsequent messages (with the initialization vector of 16 bytes being appended to the encrypted message).

&nbsp;&nbsp;&nbsp;&nbsp;Authentication is performed by issuing an authentication challenge - a 64 byte randomly generated string that has been encrypted with the user's public key and then encoded in Base64. The client is expected to decode and decrypt it using its private key and send it as a response back to the server.

&nbsp;&nbsp;&nbsp;&nbsp;Once authenticated, clients can send one of 6 possible commands (more can easily be added to the pmp_cmd.py module by the user):

`PWR_STAT, BTRY_LVL, SUSPND, REBOOT, PWROFF, END_CONN`

&nbsp;&nbsp;&nbsp;&nbsp;For more detailed information about the protocol users are encouraged to read the `pmp_rfc.txt` RFC file included in this repo.

### Usage
- By default the server will execute the shutdown and reboot commands if an authenticated user sends them. If you do not wish to do that, make sure you run the server with `--debug`

- To allow users to authenticate, first generate an RSA key pair. You can do this by writing:

`ssh-keygen -t rsa`

- Afterwards, create a json configuration file on the server and add the username and public key file to it.

`{"user": "id_rsa.pub"}`

- This config file must be passed to the server script using the `--config` switch and the private RSA key file must be passed to the client script using the `--keyfile` switch.
  
- Since sleep/hibernation commands may differ for non-Windows systems, users are expected to update `suspend.sh` using the necessary commands for their operating system.

Example of running the server script:

`python3 server.py --debug --lport 8888 --config config.json`

Example of running the client script:

`python3 client.py --lport 4444 --keyfile id_rsa --rhost 127.0.0.1 --rport 8888 --user user`