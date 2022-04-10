# Module imports
import socket
import string
import random
import argparse

def auth_chal():
    # Cryptographically secure 64 byte hexadecimal generator
    challenge = ''.join(random.SystemRandom().choice(string.hexdigits) for _ in range(64))
