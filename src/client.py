# Module imports
import re
import os
import json
import pyDH
import socket
import binascii
import argparse

TIMEOUT_LIMIT = 10 # If 10 subsequent timeouts occur, SERVER is considered unreachable
RETRY_LIMIT = 25 # If a response to a packet is not received after 25 attempts, server is unreachable
CURRENT_TIMEOUTS = TIMEOUT_LIMIT
BUFFER_SIZE = 4096
PKT_FLAGS = ['SYN', 'RES', 'CRP', 'AUTH']
PKT_NUMBER = 0 # Global variable for packet numbering

def print_banner():
    print(f'\n\n{"-"*50}\n{"<"*19} PMP CLIENT {">"*19}\n{"-"*50}\n\n')

def parse_args():
    # Parse arguments
    parser = argparse.ArgumentParser(description='Client application for Power Management Protocol (PMP).')
    parser.add_argument('-v', default=False, action='store_true', help='Perform verbose output')
    parser.add_argument('--keyfile', help='(Required) Specify RSA private key file')
    parser.add_argument('--rhost', help='(Required) Specify the target IP address')
    parser.add_argument('--rport', default=8888, type=int, help='(Optional) Specify the target port. Default: 8888')
    parser.add_argument('--lhost', default='127.0.0.1', help='(Optional) Specify the local host IP address. Default: 127.0.0.1')
    parser.add_argument('--lport', default=4444, type=int, help='(Optional) Specify the local port. Default: 4444')
    parser.add_argument('--timeout', default=2, type=int, help='(Optional) Set packet timeout in seconds. Default: 2 (sec)')
    parser.add_argument('--modp', default=14, type=int, help='(Optional) Set MODP group used for generating the Diffie-Hellman public key. Default: 14\nValid MODP IDs: 5, 14, 15, 16, 17, 18')
    args = parser.parse_args()
    # Validate IPv4 addresses
    valid_remote = re.search('^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', args.rhost)
    valid_local = re.search('^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', args.lhost)
    if not (valid_local or valid_remote):
        print('[!] Invalid IPv4 address provided') 
        quit()
    elif (args.lport >= 65535 or args.rport >= 65535):
        print('[!] Invalid port provided') 
        quit()
    elif not os.path.isfile(args.keyfile) or not os.access(args.keyfile, os.R_OK):
        print(f'[!] Keyfile {args.keyfile} does not exist or cannot be read')
        quit()
    elif args.modp not in [5, 14, 15, 16, 17, 18]:
        print(f'[!] MODP ID {args.modp} is not valid. Refer to RFC3526 for valid MODP IDs')
    return args

def build_packet(flags, json_data):
    global PKT_NUMBER
    if PKT_NUMBER > 4094:
        print('[+] Maximum number of packets per connection sent.')
        exit()
    header = 0
    for i in range(len(PKT_FLAGS)):
        header += (flags[PKT_FLAGS[i]] << 15-i) # Bitwise shift left to align packet flags
    header += PKT_NUMBER
    hex_header = format(header, 'x') # Format header in hexadecimal
    header = bytes.fromhex(hex_header) # Header in bytes
    data = json.dumps(json_data).encode() # JSON data in bytes
    packet = header + data
    checksum = binascii.crc32(packet).to_bytes(4, byteorder='big') # Calculate packet checksum
    packet = checksum + packet # Prepend checksum to packet
    return packet

# Function used to validate the packet checksum
def verify_integrity(raw_packet):
    # TODO verify integrity of packet
    decoded = raw_packet.decode()
    received_checksum = decoded[:4]
    packet = decoded[3:]
    performed_checksum = binascii.crc32(packet).to_bytes(4, byteorder='big').decode()
    return received_checksum == performed_checksum

def unpack_packet(data):
    # TODO unpack data
    return data

def send_and_receive_packet(socket, args, packet):
    global CURRENT_TIMEOUTS
    for _ in range(RETRY_LIMIT):
        try:
            socket.send(packet)
            socket.settimeout(args.timeout)
            data = socket.recv(BUFFER_SIZE)
            CURRENT_TIMEOUTS = TIMEOUT_LIMIT # Reset timeouts
            if verify_integrity(data):
                return data
        except socket.timeout:
            if CURRENT_TIMEOUTS <= 0:
                print(f'[!] Host {args.rhost} is unreachable on port {args.rport}')
                exit()
            else:
                print(f'[-] Timeout: {CURRENT_TIMEOUTS} remaining  ', end='\r')
                CURRENT_TIMEOUTS -= 1

def diffie_hellman(args, socket):
    # Perform Diffie-Hellman key exchange with server
    client_public_key = pyDH.DiffieHellman(args.modp).gen_public_key()
    flags = {'SYN': True, 'RES': False, 'CRP': False, 'AUTH': False}
    payload = {'modp_id': args.modp, 'pub_key': client_public_key}
    packet = build_packet(flags, payload)
    server_public_key = send_and_receive_packet(socket, args, packet)
    shared_secret = client_public_key.gen_shared_key(server_public_key)
    return shared_secret

def main():
    args = parse_args()
    print_banner()
    # Create UDP socket
    socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    socket.bind((args.lhost, args.lport))
    socket.connect((args.rhost, args.rport))
    if args.v:
        print(f'[+] Attempting to connect to {args.rhost}:{args.rport}')
    shared_secret = diffie_hellman(args, socket)
    if args.v:
        print('[+] Shared secrets established')
 
# Run main function
main()