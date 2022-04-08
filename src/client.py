# Module imports
import re
import pyDH
import socket
import argparse

# If 10 subsequent timeouts occur, SERVER is considered unreachable
TIMEOUT_LIMIT = 10
CURRENT_TIMEOUTS = TIMEOUT_LIMIT
BUFFER_SIZE = 4096
# Packet number, starting from 0
PACKET_NUMBER = 0

def print_banner():
    print(f'\n\n{"-"*50}\n{"<"*19} PMP CLIENT {">"*19}\n{"-"*50}\n\n')

def parse_args():
    # Parse arguments
    parser = argparse.ArgumentParser(description='Client application for Power Management Protocol (PMP).')
    parser.add_argument('-v', default=False, action='store_true', help='Perform verbose output')
    parser.add_argument('--rhost', help='(Required) Specify the target IP address')
    parser.add_argument('--rport', default=8888, type=int, help='(Optional) Specify the target port. Default: 8888')
    parser.add_argument('--lhost', default='127.0.0.1', help='(Optional) Specify the local host IP address. Default: 127.0.0.1')
    parser.add_argument('--lport', default=4444, type=int, help='(Optional) Specify the local port. Default: 4444')
    parser.add_argument('--timeout', default=2, type=int, help='(Optional) Set packet timeout in seconds. Default: 2 (sec)')
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
    return args

def build_packet(flags, data):
    global PACKET_NUMBER
    if PACKET_NUMBER > 4094:
        print('[+] Maximum number of packets per connection sent.')
        exit()
    # TODO make packet

def send_and_receive_packet(socket, args, packet):
    global CURRENT_TIMEOUTS
    for attempt in range(TIMEOUT_LIMIT):
        try:
            socket.send(packet)
            socket.settimeout(args.timeout)
            data , addr = socket.recv(BUFFER_SIZE)
            CURRENT_TIMEOUTS = TIMEOUT_LIMIT # Reset timeouts
        except socket.timeout:
            if CURRENT_TIMEOUTS <= 0:
                print(f'[!] Host {args.rhost} is unreachable on port {args.rport}')
                exit()
            else:
                print(f'[-] Timeout: {CURRENT_TIMEOUTS} remaining ', end='\r')
                CURRENT_TIMEOUTS -= 1

def diffie_hellman(args):
    # Perform Diffie-Hellman key exchange with server
    client_public_key = pyDH.DiffieHellman().gen_public_key()
    flags = {'SYN': 1, 'RES': 0, 'CRP': 0, 'AUTH': 0}
    packet = build_packet(flags, client_public_key)
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
    
    #   

main()