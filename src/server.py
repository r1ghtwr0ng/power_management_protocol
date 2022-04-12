# Module imports
import re
import os
import json
import time
import pyDH
import base64
import socket
import string
import random
import hashlib
import argparse
from pmp import *
from threading import Thread

# No I will not make classes, OOP is lame
CONN_STATES = {}
BUFFER_SIZE = 4096
INACTIVE_TIMEOUT = 120 # If a connection does not send a packet for 120 seconds, its state is wiped
COMMANDS = ['PWR_STAT', 'BTRY_LVL', 'SUSPND', 'REBOOT', 'PWROFF', 'END_CONN'] # Available commands

# Print program banner
def print_banner():
    print(f'\n\n{"-"*70}\n{"<"*29} PMP SERVER {">"*29}\n{"-"*70}\n\n')

# Parse arguments provided by the user
def parse_args():
    # Parse arguments
    parser = argparse.ArgumentParser(description='Server application for Power Management Protocol (PMP).')
    parser.add_argument('-v', default=False, action='store_true', help='Perform verbose output')
    parser.add_argument('--debug', default=False, action='store_true', help='Print debug information (e.g. full packets, AES keys)')
    parser.add_argument('--config', default='auth_config.json',required=True, help='(Optional) Specify JSON file with allowed users and their public keys')
    parser.add_argument('--lhost', default='127.0.0.1', help='(Optional) Specify the local host IP address. Default: 127.0.0.1')
    parser.add_argument('--lport', default=4444, type=int, help='(Optional) Specify the local port. Default: 4444')
    parser.add_argument('--timeout', default=2, type=int, help='(Optional) Set packet timeout in seconds. Default: 2 (sec)')
    args = parser.parse_args()
    # Validate IPv4 addresses
    ip_regex = re.compile('^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    if not bool(ip_regex.match(args.lhost)):
        print('[!] Invalid IPv4 address provided') 
        exit()
    elif args.lport >= 65535:
        print('[!] Invalid port provided') 
        exit()
    elif not os.path.isfile(args.config) or not os.access(args.config, os.R_OK):
        print(f'[!] Configuration file {args.config} does not exist or cannot be read')
        exit()
    return args

# Whenever a new connection state is saved, a deletion thread is spawned
# The thread decrements the connection TTL each second until it reaches 0,
# at which point the state is wiped. TTL is reset upon receival of new
# packets from a connection
def deletion_thread(address, port):
    global CONN_STATES
    # Thread module does not like passing tuples as function arguments
    address = (address, port)
    while True:
        time.sleep(1)
        if CONN_STATES[address]['TTL'] <= 0:
            CONN_STATES.pop(address)
            return
        CONN_STATES[address]['TTL'] -= 1

# Create new conn status or update TTL
def update_conn_status(address):
    global CONN_STATES
    if address in CONN_STATES:
        # Handle race condition if deletion thread gets rid of conn
        try:
            CONN_STATES[address]['TTL'] = INACTIVE_TIMEOUT
            return
        except KeyError:
            update_conn_status(address)
            return
    CONN_STATES[address] = {'key': None, 'authenticated': False, 'TTL': INACTIVE_TIMEOUT}
    Thread(target=deletion_thread, args=(address)).start()
    return

# Perform Diffie-Hellman key exchange
def key_exchange(server, recv_flags, recv_seq, parsed_json, address, args):
    global CONN_STATES
    # Process response
    if ('modp_id' not in parsed_json) or ('pub_key' not in parsed_json):
        if args.v: print('[!] Client has not sent MODP_ID or PUBLIC_KEY for DH key exchange')
        return
    server_public_key = pyDH.DiffieHellman(parsed_json['modp_id'])
    payload = {'pub_key': server_public_key.gen_public_key()}
    server_response(server, recv_flags, recv_seq+1, payload, address, args)
    # Calculate and store encryption key for connection
    shared_secret = server_public_key.gen_shared_key(parsed_json['pub_key'])
    CONN_STATES[address]['key'] = hashlib.sha256(shared_secret.encode('utf-8')).digest()
    return

# Handle authentication requests from a client
def auth_sequence(server, recv_flags, recv_seq, parsed_json, address, args, config):
    global CONN_STATES

    key = CONN_STATES[address]['key']
    # Check initial authentication request
    if 'auth' in parsed_json:
        if parsed_json['auth'] not in config:
            if args.v: print('[!] Client provided a user which is not in config file')
            server_response(server, recv_flags, recv_seq+1, {'err': 'BAD_USER'}, address, args, key)
        
        # Cryptographically secure 64 byte hexadecimal generator
        challenge = ''.join(random.SystemRandom().choice(string.hexdigits) for _ in range(64)).encode()
        CONN_STATES[address]['username'] = parsed_json['auth']
        CONN_STATES[address]['auth_chal'] = base64.b64encode(challenge).decode()
        if args.debug: print(f'[+] PROVIDED AUTH CHALLENGE: {CONN_STATES[address]["auth_chal"]}')
        server_response(server, recv_flags, recv_seq+1, {'auth_chal': base64.b64encode(encrypt_rsa(challenge, config[parsed_json['auth']])).decode()}, address, args, key)
        return
    # Check authentication solution response
    elif 'auth_solution' in parsed_json:
        if 'auth_chal' not in CONN_STATES[address]:
            if args.v: print('[!] Client provided auth solution but challenge was not issued')
            server_response(server, recv_flags, recv_seq+1, {'err': 'BAD_AUTH'}, address, args, key)
            return

        if parsed_json['auth_solution'] != CONN_STATES[address]['auth_chal']:
            if args.v: print('[!] Client did not solve authentication challenge')
            server_response(server, recv_flags, recv_seq+1, {'err': 'BAD_AUTH'}, address, args, key)
            return

        CONN_STATES[address]['authenticated'] = True
        server_response(server, recv_flags, recv_seq+1, {'ok': 'AUTHENTICATED'}, address, args, key)
        return

    if args.v: print('[!] Client did not provide username or authentication challenge solution')
    server_response(server, recv_flags, recv_seq+1, {'err': 'BAD_AUTH'}, address, args, key)
    return

# Perform commands
def cmd_sequence(server, recv_flags, recv_seq, parsed_json, address, args):
    key = CONN_STATES[address]['key']
    if 'cmd' not in parsed_json:
        if args.v: print('[!] Client did not provide command')
        server_response(server, recv_flags, recv_seq+1, {'err': 'BAD_CMD'}, address, args, key)
        return
    elif not parsed_json['cmd'] in COMMANDS:
        if args.v: print('[!] Client provided an invalid command')
        server_response(server, recv_flags, recv_seq+1, {'err': 'BAD_CMD'}, address, args, key)
        return
    server_response(server, recv_flags, recv_seq+1, {'ok': 'COMMAND_RESPONSE'}, address, args, key)
    return

# Determine what action to perform for a given packet
def handle_packet(server, packet, address, args, config):
    # Update connection status
    update_conn_status(address)
    # Unpack received packet
    unpacked = verify_and_unpack(packet, args)
    key = CONN_STATES[address]['key']
    if None in unpacked:
        if recv_seq != None:
            # If the packet sequence number is not corrupted, reply with CRP packet
            flags = {'SYN': False, 'RES': False, 'CRP': True, 'AUTH': False}
            if args.v: print('[!] Corrupted packet')
            server_response(server, recv_flags, recv_seq+1, {'err': 'BAD_PKT'}, address, args, key)
        return
    (recv_flags, recv_seq, unpacked) = unpacked

    if args.debug: print('RECV'); print_packet(recv_flags, recv_seq, unpacked, key)
    try:
        # Handle invalid packets
        if recv_flags['CRP']:
            if args.v: print('[!] Client should retransmit packet instead of sending CRP')
            server_response(server, recv_flags, recv_seq+1, {'err': 'BAD_PKT'}, address, args, key)
            return
        elif (recv_flags['SYN'] and recv_flags['AUTH']) or recv_flags['RES']:
            if args.v: print('[!] Client sent invalid packet')
            server_response(server, recv_flags, recv_seq+1, {'err': 'BAD_PKT'}, address, args, key)
            return
        # Perform Diffie-Hellman key exchange
        elif recv_flags['SYN']:
            key_exchange(server, recv_flags, recv_seq, json.loads(unpacked), address, args)
            return
        elif key == None:
            if args.v: print('[!] Client attempted to authenticate before establishing a connection')
            server_response(server, recv_flags, recv_seq+1, {'err': 'NOT_SYNCED'}, address, args)
            return
        # Perform authentication
        elif recv_flags['AUTH']:
            auth_sequence(server, recv_flags, recv_seq, json.loads(decrypt_aes(unpacked, key)), address, args, config)
            return
        elif not CONN_STATES[address]['authenticated']:
            if args.v: print('[!] Client did not provide username or authentication challenge solution')
            server_response(server, recv_flags, recv_seq+1, {'err': 'BAD_PERM'}, address, args, key)
            return
        cmd_sequence(server, recv_flags, recv_seq, json.loads(decrypt_aes(unpacked, key)), address, args)
        return
    except EOFError as e:
        if args.v: print('[!] Client sent invalid JSON')
        server_response(server, recv_flags, recv_seq+1, {'err': 'BAD_PKT'}, address, args, key)
        return

# Receive datagram and send off for processing
def listen_loop(server, args, config):
    while True:
        packet, address = server.recvfrom(BUFFER_SIZE)
        handle_packet(server, packet, address, args, config)

def main():
    args = parse_args()
    if args.v: print_banner(); print(f'[+] Starting server at {args.lhost}:{args.lport}')
    if args.debug: print('-'*70)
    try:
        config = json.loads(open(args.config).read()) # Load config
    except (UnicodeDecodeError, json.decoder.JSONDecodeError) as e:
        print('[!] Config file is not valid JSON')
        exit(1)
    # Create and bind socket
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((args.lhost, args.lport))
    listen_loop(server, args, config)

main()