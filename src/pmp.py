import socket
import binascii
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
    return cipher.encrypt(pad(plaintext, AES.block_size)) + cipher.iv

# Decrypt AES cyphertext with appended 16 byte Initialization Vector
def decrypt_aes(ciphertext, key):
    try:
        iv = ciphertext[-16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext[:-16]), AES.block_size)
    except (ValueError, KeyError):
        print("Incorrect decryption")
        return False

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
def build_packet(seq_number, flags, data):
    if seq_number > 4094:
        print('[+] Maximum number of packets per connection sent.')
        exit()
    header = 0
    for i in range(len(PKT_FLAGS)):
        header += (flags[PKT_FLAGS[i]] << 15-i) # Bitwise shift left to align packet flags
    header += seq_number
    hex_header = format(header, 'x') # Format header in hexadecimal
    header = bytes.fromhex(hex_header) # Header in bytes
    packet = header + data
    checksum = binascii.crc32(packet).to_bytes(4, byteorder='big') # Calculate packet checksum
    packet = checksum + packet # Prepend checksum to packet
    return packet

# Function used to validate the packet checksum and return the data if correct
def _verify_and_unpack(sent_flags, sent_seq, raw_packet, args):
    if len(raw_packet) < 7:
        if args.v:
            print(f'[!] Received packet too small ', end='\r') #TODO remove
        return False
    # Fetch checksum at first 4 bytes
    received_checksum = raw_packet[:4]
    performed_checksum = binascii.crc32(raw_packet[4:]).to_bytes(4, byteorder='big')
    # Fetch 2 bytes at offset +4 and convert to binary (save as string)
    header = format(int.from_bytes(raw_packet[4:6], byteorder='big'), 'b')
    recv_seq = int(header[4:], 2) # Received packet sequence number
    recv_flags_str = header[:4] # Flags are the first 4 bits
    recv_flags = {}
    for i in range(len(PKT_FLAGS)): recv_flags[PKT_FLAGS[i]] = bool(int(recv_flags_str[i]))
    if recv_flags['CRP']:
        return False
    elif not recv_flags['RES']:
        if args.v:
            print('[!] Response RES flag not set')
        return False
    elif (sent_flags['SYN'] != recv_flags['SYN']) or (sent_flags['AUTH'] != recv_flags['AUTH']):
        if args.v:
            print('[!] Response header flags SYN or AUTH not matching request')
        return False
    elif sent_seq != recv_seq:
        if args.v:
            print('[-] Response sequence does not match request')
        return False
    elif received_checksum != performed_checksum:
        if args.v:
            print('[!] Response checksum does not match')
        return False
    return raw_packet[6:]

# Sends packet via specified socket and returns decoded packet data.
# Packet corruption, timeouts and retransmissions are automatically handled
def send_and_receive_packet(sent_flags, seq_number, client, args, packet):
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
            unpacked = _verify_and_unpack(sent_flags, seq_number, raw_packet, args)
            if unpacked:
                return unpacked
        except socket.timeout:
            if CURRENT_TIMEOUTS <= 0:
                print(f'[!] Host {args.rhost} is unreachable on port {args.rport}')
                exit()
            else:
                if args.v:
                    print(f'[-] Timeout: {CURRENT_TIMEOUTS} remaining     ', end='\r')
                CURRENT_TIMEOUTS -= 1
    print(f'[!] Host {args.rhost} is unreachable on port {args.rport}')
    exit()

def handle_errors(recv_packet):
    if 'err' in recv_packet:
        error = recv_packet['err']
        print(f'[!] Error received: {error}')
        if error == 'BAD_USER' or error == 'BAD_AUTH':
            exit()
        return True
    return False
