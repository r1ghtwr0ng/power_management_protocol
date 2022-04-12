# Module imports
import re
import os
import json
import pyDH
import base64
import socket
import hashlib
import argparse
from pmp import *

PKT_NUMBER = 0 # Global variable for packet numbering
COMMANDS = ['PWR_STAT', 'BTRY_LVL', 'SUSPND', 'REBOOT', 'PWROFF', 'END_CONN'] # Available commands

# Print program banner
def print_banner():
    print(f'\n\n{"-"*70}\n{"<"*29} PMP CLIENT {">"*29}\n{"-"*70}\n\n')

# Print all available commands with selection numbers
def print_commands():
    for i in range(len(COMMANDS)):
        print(f'  [{i+1}] {COMMANDS[i]}')
    print('  [Q] Quit')

# Parse arguments provided by the user
def parse_args():
    # Parse arguments
    parser = argparse.ArgumentParser(description='Client application for Power Management Protocol (PMP).')
    parser.add_argument('-v', default=False, action='store_true', help='Perform verbose output')
    parser.add_argument('--keyfile', required=True, help='(Required) Specify RSA private key file')
    parser.add_argument('--user', required=True, help='(Required) Specify username for authentication')
    parser.add_argument('--rhost', required=True, help='(Required) Specify the target IP address')
    parser.add_argument('--rport', default=8888, type=int, help='(Optional) Specify the target port. Default: 8888')
    parser.add_argument('--lhost', default='127.0.0.1', help='(Optional) Specify the local host IP address. Default: 127.0.0.1')
    parser.add_argument('--lport', default=4444, type=int, help='(Optional) Specify the local port. Default: 4444')
    parser.add_argument('--timeout', default=2, type=int, help='(Optional) Set packet timeout in seconds. Default: 2 (sec)')
    parser.add_argument('--modp', choices=[5, 14, 15, 16, 17, 18], default=14, type=int, help='(Optional) Set MODP group used for generating the Diffie-Hellman public key. Default: 14\nValid MODP IDs: 5, 14, 15, 16, 17, 18')
    args = parser.parse_args()
    # Validate IPv4 addresses
    ip_regex = re.compile('^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    if not (bool(ip_regex.match(args.rhost)) and bool(ip_regex.match(args.lhost))):
        print('[!] Invalid IPv4 address provided') 
        exit()
    elif (args.lport >= 65535 or args.rport >= 65535):
        print('[!] Invalid port provided') 
        exit()
    elif not os.path.isfile(args.keyfile) or not os.access(args.keyfile, os.R_OK):
        print(f'[!] Keyfile {args.keyfile} does not exist or cannot be read')
        exit()
    return args

# Auto-increment the packet sequence number by 2
def get_and_increment_pkt():
    global PKT_NUMBER
    current_seq = PKT_NUMBER
    PKT_NUMBER += 2
    return current_seq

# Perform Diffie-Hellman key exchange
def diffie_hellman(args, client):
    # Create packet
    sent_flags = {'SYN': True, 'RES': False, 'CRP': False, 'AUTH': False}
    seq_number = get_and_increment_pkt()
    client_public_key = pyDH.DiffieHellman(args.modp)
    sent_data = {'modp_id': args.modp, 'pub_key': client_public_key.gen_public_key()}
    payload = json.dumps(sent_data).encode() # Encode dictionary to JSON as bytes
    packet = build_packet(sent_flags, seq_number, payload)
    
    # Process response
    recv_data = json.loads(send_and_receive_packet(sent_flags, seq_number, client, args, packet))
    if 'pub_key' not in recv_data:
        if args.v: print('[!] Server response does not contain a public key')
        exit()
    shared_secret = client_public_key.gen_shared_key(recv_data['pub_key'])
    return shared_secret.encode('utf-8')

# Request and solve server authentication challenge
def authenticate(args, client, key):
    sent_flags = {'SYN': False, 'RES': False, 'CRP': False, 'AUTH': True}
    seq_number = get_and_increment_pkt()
    sent_data = {'auth': args.user}
    payload = json.dumps(sent_data).encode()
    packet = build_packet(sent_flags, seq_number, payload, key)

    # Process auth challenge
    recv_data = json.loads(decrypt_aes(send_and_receive_packet(sent_flags, seq_number, client, args, packet), key))
    if handle_errors(recv_data):
        print(f'[!] Unexpected error during authentication sequence {recv_data["err"]}')
        exit()
    elif not 'auth_chal' in recv_data:
        print('[!] Server response does not contain authentication challenge')
        exit()
    
    seq_number = get_and_increment_pkt()
    decrypted = decrypt_rsa(base64.b64decode(recv_data['auth_chal']), args.keyfile)
    chal_response = {'auth_solution': base64.b64encode(decrypted).decode()}
    payload = json.dumps(chal_response).encode()
    packet = build_packet(sent_flags, seq_number, payload, key)

    # Process auth challenge
    recv_data = json.loads(decrypt_aes(send_and_receive_packet(sent_flags, seq_number, client, args, packet), key))
    if handle_errors(recv_data):
        print(f'[!] Unexpected error during authentication sequence {recv_data["err"]}')
        exit()
    elif not 'ok' in recv_data:
        print('[!] Server has not responded with OK or ERR')
        exit()
    return True

# Send a selection of commands to the server and display their responses
def send_commands(client, args, key):
    while True:
        print_commands()
        cmd = input('[?] Select command: ')
        if cmd.strip().upper() == 'Q': return False # Exit if user enters Q
        try:
            cmd = int(cmd)
            if cmd in range(1, len(COMMANDS)+1):
                break
        except ValueError:
            print('[!] Invalid command')

    sent_flags = {'SYN': False, 'RES': False, 'CRP': False, 'AUTH': False}
    seq_number = get_and_increment_pkt()
    sent_data = {'cmd': COMMANDS[cmd-1]}
    payload = json.dumps(sent_data).encode()
    packet = build_packet(sent_flags, seq_number, payload, key)

    # Process command response
    recv_data = json.loads(decrypt_aes(send_and_receive_packet(sent_flags, seq_number, client, args, packet), key))
    if handle_errors(recv_data):
        print(f'[!] Server responded with error: {recv_data["err"]}')
    elif not 'ok' in recv_data:
        print(f'[!] Unexpected server response: {recv_data}')
    else:
        print(f'[+] Server responded with ok: {recv_data["ok"]}')
    if COMMANDS[cmd-1] == 'END_CONN': return False # Break main function loop if last command was END_CONN
    return True
    

def main():
    args = parse_args()
    if args.v: print_banner()
    # Create UDP socket
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind((args.lhost, args.lport))
    if args.v: print(f'[+] Attempting to connect to {args.rhost}:{args.rport}')
    # Calculate AES CBC key as SHA256 hash of the shared secret
    key = hashlib.sha256(diffie_hellman(args, client)).digest()
    if args.v: print('[+] Shared secrets established')

    authenticate(args, client, key)
    if args.v: print(f'[+] Successfully authenticated as {args.user}')
    
    # Slightly more efficient than infinite loop with a break statement in a conditional
    while send_commands(client, args, key):
        pass
    
    client.close()
    if args.v: print('[+] Connection closed')
    return 0        
 
# Run main function
main()