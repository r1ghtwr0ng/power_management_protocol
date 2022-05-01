# Module imports
import re
import os
import hmac
import json
import math
import time
import pyDH
import base64
import socket
import string
import random
import hashlib
import argparse
from pmp import *
from pmp_cmd import *
from threading import Thread, Event, Semaphore

# No I will not make classes, OOP is lame
CONN_STATES = {}
BUFFER_SIZE = 4096
INACTIVE_TIMEOUT = 120 # If a connection does not send a packet for 120 seconds, its state is wiped

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

# Allow for modification of connection states without causing race conditions
def modify_conn_states(address, modification={}, delete=False):
    global CONN_STATES
    try:
        CONN_STATES[address]['SEMAPHORE'].acquire()
        # Enter critical region
        if delete:
            semaphore = CONN_STATES[address]['SEMAPHORE']
            thread_event = CONN_STATES[address]['THREAD_EVENT']
            CONN_STATES.pop(address)
            thread_event.set() # Interrupt thread after deletion
            semaphore.release() # The semaphore object will not be accessible anymore but its good practice to release it
            return
        for key in modification:
            CONN_STATES[address][key] = modification[key]
        CONN_STATES[address]['SEMAPHORE'].release()
        return
    except KeyError as e:
        if delete:
            return
        # Create new connection
        CONN_STATES[address] = {'KEY': None, 'AUTHENTICATED': False, 'SEMAPHORE': Semaphore()}
        return

# Fetch info from CONN_STATES when it's not being modified
def get_conn_state(address, key):
    try:
        CONN_STATES[address]['SEMAPHORE'].acquire()
        result = CONN_STATES[address][key]
        CONN_STATES[address]['SEMAPHORE'].release()
        return result
    except KeyError:
        return None

# Whenever a new connection state is saved, a deletion thread is spawned.
# The thread starts a wait event, which if interrupted is started again 
# (or the thread dies if the connection has been deleted).
# If the event times out, the connection state is removed. The event is
# interrupted whenever a new packet is received or the connection is wiped.
def deletion_thread(address, port):
    # Thread module does not like passing tuples as function arguments
    address = (address, port)
    while True:
        thread_event = Event()
        modify_conn_states(address, {'THREAD_EVENT': thread_event})
        if (not thread_event.wait(INACTIVE_TIMEOUT)):
            modify_conn_states(address, {}, True) # Delete the connection state
            print(f'[!] Closed connection {address}')
            return
        elif (address not in CONN_STATES):
            return

# Cause the deletion thread to get interrupted
def interrupt_thread(address):
    thread_event = get_conn_state(address, 'THREAD_EVENT') # Fetch thread event
    if thread_event != None:
        thread_event.set() # Wake up thread
        return True
    return False

# Create new conn status or interrupt thread event
def update_conn_status(address):
    if interrupt_thread(address):
        return
    modify_conn_states(address) # Create connection status
    Thread(target=deletion_thread, args=(address)).start()
    return

# Perform Diffie-Hellman key exchange
def key_exchange(server, recv_flags, recv_seq, parsed_json, address, args):
    # Process response
    if ('modp_id' not in parsed_json) or ('pub_key' not in parsed_json):
        if args.v: print('[!] Client has not sent MODP_ID or PUBLIC_KEY for DH key exchange')
        return
    server_public_key = pyDH.DiffieHellman(parsed_json['modp_id'])
    payload = {'pub_key': server_public_key.gen_public_key()}
    server_response(server, recv_flags, recv_seq+1, payload, address, args)
    # Calculate and store encryption key for connection
    shared_secret = server_public_key.gen_shared_key(parsed_json['pub_key'])
    modify_conn_states(address, {'KEY': hashlib.sha256(shared_secret.encode('utf-8')).digest()})
    return

# Handle authentication requests from a client
def auth_sequence(server, recv_flags, recv_seq, parsed_json, address, args, config):
    key = get_conn_state(address, 'KEY')
    # Check initial authentication request
    if 'auth' in parsed_json:
        if parsed_json['auth'] not in config:
            if args.v: print('[!] Client provided a user which is not in config file')
            server_response(server, recv_flags, recv_seq+1, {'err': 'BAD_USER'}, address, args, key)
        
        # Cryptographically secure 64 byte hexadecimal generator
        challenge = ''.join(random.SystemRandom().choice(string.hexdigits) for _ in range(64)).encode()
        modify_conn_states(address, {'USERNAME': parsed_json['auth']})
        modify_conn_states(address, {'AUTH_CHAL': base64.b64encode(challenge).decode()})
        if args.debug: print(f'[+] PROVIDED AUTH CHALLENGE: {get_conn_state(address, "AUTH_CHAL")}')
        server_response(server, recv_flags, recv_seq+1, {'auth_chal': base64.b64encode(encrypt_rsa(challenge, config[parsed_json['auth']])).decode()}, address, args, key)
        return
    # Check authentication solution response
    elif 'auth_solution' in parsed_json:
        if get_conn_state(address, 'AUTH_CHAL') == None:
            if args.v: print('[!] Client provided auth solution but challenge was not issued')
            server_response(server, recv_flags, recv_seq+1, {'err': 'BAD_AUTH'}, address, args, key)
            return
        # Perform constant time comparison to mitigate timing attacks
        if not hmac.compare_digest(parsed_json['auth_solution'], get_conn_state(address, 'AUTH_CHAL')):
            if args.v: print('[!] Client did not solve authentication challenge')
            server_response(server, recv_flags, recv_seq+1, {'err': 'BAD_AUTH'}, address, args, key)
            return
        # Set client state as authenticated
        modify_conn_states(address, {'AUTHENTICATED': True})
        server_response(server, recv_flags, recv_seq+1, {'ok': 'AUTHENTICATED'}, address, args, key)
        return

    if args.v: print('[!] Client did not provide username or authentication challenge solution')
    server_response(server, recv_flags, recv_seq+1, {'err': 'BAD_AUTH'}, address, args, key)
    return

# Perform commands
def cmd_sequence(server, recv_flags, recv_seq, parsed_json, address, args):
    key = get_conn_state(address, 'KEY')
    if 'cmd' not in parsed_json:
        if args.v: print('[!] Client did not provide command')
        server_response(server, recv_flags, recv_seq+1, {'err': 'BAD_CMD'}, address, args, key)
        return
    elif not parsed_json['cmd'] in COMMANDS:
        if args.v: print('[!] Client provided an invalid command')
        server_response(server, recv_flags, recv_seq+1, {'err': 'BAD_CMD'}, address, args, key)
        return
    elif parsed_json['cmd'] == 'END_CONN':
        server_response(server, recv_flags, recv_seq+1, {'ok': 'CONNECTION CLOSED'}, address, args, key)
        modify_conn_states(address, {}, True) # Delete connection
        return
    elif args.debug:
        server_response(server, recv_flags, recv_seq+1, {'ok': 'COMMAND_RESPONSE'}, address, args, key)
        return
    server_response(server, recv_flags, recv_seq+1, {'ok': run_cmd( parsed_json['cmd'])}, address, args, key)
    return

# Determine what action to perform for a given packet
def handle_packet(server, packet, address, args, config):
    # Update connection status
    update_conn_status(address)
    # Unpack received packet
    unpacked_tuple = verify_and_unpack(packet, args)
    key = get_conn_state(address, 'KEY')
    (recv_flags, recv_seq, unpacked) = unpacked_tuple
    if None in unpacked_tuple:
        if recv_seq != None:
            # If the packet sequence number is not corrupted, reply with CRP packet
            flags = {'SYN': False, 'RES': False, 'CRP': True, 'AUTH': False}
            if args.v: print('[!] Corrupted packet received')
            server_response(server, flags, recv_seq+1, {'err': 'BAD_PKT'}, address, args, key)
        return

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
        elif not get_conn_state(address, 'AUTHENTICATED'):
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
        (packet, address) = server.recvfrom(BUFFER_SIZE)
        handle_packet(server, packet, address, args, config)

def main():
    args = parse_args()
    if args.v: print_banner('PMP SERVER'); print(f'[+] Starting server at {args.lhost}:{args.lport}')
    if args.debug: print('-'*get_terminal_width())
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