import re
import json
import socket
import binascii
import textwrap
from pmp_cmd import *
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

BLOCK_SIZE = 16
TIMEOUT_LIMIT = 10 # If 10 subsequent timeouts occur, SERVER is considered unreachable
RETRY_LIMIT = 25 # If a response to a packet is not received after 25 attempts, server is unreachable
CURRENT_TIMEOUTS = TIMEOUT_LIMIT
BUFFER_SIZE = 4096
PKT_FLAGS = ['SYN', 'RES', 'CRP', 'AUTH']

# Encrypt plaintext and append the 16 byte Initialization Vector to it
def encrypt_aes(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    return cipher.encrypt(pad(plaintext, BLOCK_SIZE)) + cipher.iv

# Decrypt AES cyphertext with appended 16 byte Initialization Vector
def decrypt_aes(ciphertext, key):
    try:
        iv = ciphertext[-16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext[:-16]), BLOCK_SIZE)
    except (ValueError, KeyError):
        print('[!] Incorrect decryption or closed connection')
        exit()

# Encrypt the plaintext using an RSA public keyfile
def encrypt_rsa(plaintext, keyfile):
    rsa_public_key = RSA.importKey(open(keyfile).read())
    rsa_public_key = PKCS1_OAEP.new(rsa_public_key)
    return rsa_public_key.encrypt(plaintext)

# Decrypt the ciphertext using an RSA private keyfile
def decrypt_rsa(ciphertext, keyfile):
    rsa_private_key = RSA.importKey(open(keyfile).read())
    rsa_private_key = PKCS1_OAEP.new(rsa_private_key)
    return rsa_private_key.decrypt(ciphertext)

# Set headers and data, calculate CRC32 checksum and prepend it to the packet
def build_packet(flags, seq_number, data, key=None):
    if seq_number > 4094:
        print('[+] Maximum number of packets per connection sent.')
        exit()
    header = 0
    for i in range(len(PKT_FLAGS)):
        header += (flags[PKT_FLAGS[i]] << 15-i) # Bitwise shift left to align packet flags
    header += seq_number
    hex_header = format(header, '04x') # Format header in hexadecimal
    header = bytes.fromhex(hex_header) # Header in bytes
    if key != None: data = encrypt_aes(data, key)
    packet = header + data
    checksum = binascii.crc32(packet).to_bytes(4, byteorder='big') # Calculate packet checksum
    packet = checksum + packet # Prepend checksum to packet
    return packet

# Function used to validate the packet flags and sequence number (for client)
def _validate_headers(sent_flags, sent_seq, recv_flags, recv_seq, args):
    if recv_flags['CRP']:
        return False
    elif not recv_flags['RES']:
        if args.v: print('[!] Response RES flag not set')
        return False
    elif (sent_flags['SYN'] != recv_flags['SYN']) or (sent_flags['AUTH'] != recv_flags['AUTH']):
        if args.v: print('[!] Response header flags SYN or AUTH not matching request')
        return False
    elif sent_seq+1 != recv_seq: # A response should have an incremented sequence number
        if args.v: print('[-] Response sequence does not match request')
        return False
    return True

# Verify packet integrity and unpack the received packet if checksum and packet length is ok
def verify_and_unpack(raw_packet, args):
    if len(raw_packet) < 7:
        if args.v: print(f'[!] Received packet too small ', end='\r')
        return (None, None, None)
    # Fetch checksum at first 4 bytes
    received_checksum = raw_packet[:4]
    performed_checksum = binascii.crc32(raw_packet[4:]).to_bytes(4, byteorder='big')

    # Fetch 2 bytes at offset +4 and convert to binary (save as string)
    header = format(int.from_bytes(raw_packet[4:6], byteorder='big'), '016b')
    recv_seq = int(header[4:], 2) # Received packet sequence number
    if performed_checksum != received_checksum: return (None, recv_seq, None)
    recv_flags_str = header[:4] # Flags are the first 4 bits
    recv_flags = {}
    for i in range(len(PKT_FLAGS)): recv_flags[PKT_FLAGS[i]] = bool(int(recv_flags_str[i]))
    return (recv_flags, recv_seq, raw_packet[6:])

# Sends packet via specified socket and returns decoded packet data.
# Packet corruption, timeouts and retransmissions are automatically handled
def send_and_receive_packet(sent_flags, sent_seq, client, args, packet):
    global CURRENT_TIMEOUTS
    for _ in range(RETRY_LIMIT):
        try:
            client.settimeout(args.timeout)
            client.sendto(packet, (args.rhost, args.rport))
            while True: # Check if the received packet's address is good
                (raw_packet, addr) = client.recvfrom(BUFFER_SIZE)
                if addr == (args.rhost, args.rport):
                    break
            CURRENT_TIMEOUTS = TIMEOUT_LIMIT # Reset timeouts
            unpacked = verify_and_unpack(raw_packet, args)
            if None in unpacked:
                continue
            (recv_flags, recv_seq, unpacked) = unpacked
            if _validate_headers(sent_flags, sent_seq, recv_flags, recv_seq, args):
                return unpacked
        except socket.timeout:
            if CURRENT_TIMEOUTS <= 0:
                print(f'\n[!] Host {args.rhost} is unreachable on port {args.rport}')
                exit()
            else:
                if args.v: print(f'[-] Retransmitted packet due to timeout: {CURRENT_TIMEOUTS} remaining  ', end='\r')
                CURRENT_TIMEOUTS -= 1
    print(f'\n[!] Host {args.rhost} is unreachable on port {args.rport}')
    exit()

# Send response to client
def server_response(server, flags, seq_number, payload, address, args, key=None):
    flags['RES'] = True
    if args.debug: print('SENT'); print_packet(flags, seq_number, payload, key, True)
    payload = json.dumps(payload).encode()
    if key != None:
        payload = encrypt_aes(payload, key)
    packet = build_packet(flags, seq_number, payload)
    server.sendto(packet, address)
    return

# Exit if critical error is received, return True if error exists and False if not
def handle_errors(recv_packet):
    if 'err' in recv_packet:
        error = recv_packet['err']
        print(f'[!] Error received: {error}')
        if error == 'BAD_USER' or error == 'BAD_AUTH' or error == 'NOT_SYNCED':
            exit()
        return True
    return False

# Print entirety of the packet
def print_packet(flags, seq, data, key, skip_decryption=False):
    term_width = get_terminal_width()
    if key != None and not flags['SYN'] and not skip_decryption:
        data = decrypt_aes(data, key)
    packet = []
    packet.append(f'SYN: {int(flags["SYN"])}, RES: {int(flags["RES"])}, CRP: {int(flags["CRP"])}, AUTH: {int(flags["AUTH"])}\n')
    packet.append(f'SEQUENCE: {seq}\n')
    packet.append(f'DATA: {data}\n')
    packet.append(f'AES KEY: {key}\n')
    print('-'*term_width)
    for line in packet:
        for wrapped in textwrap.wrap(line, width=term_width-2):
            print(wrapped)
    print('-'*term_width)
    return
