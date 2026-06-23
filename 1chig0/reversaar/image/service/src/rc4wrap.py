#!/usr/bin/env python3

import os
import random
import base64
from Cryptodome.Cipher import ARC4

KEY = base64.b64encode(b'ThereIsNoBackdoor')

def wrap_file(input_path, backup_path):
    with open(input_path, 'rb') as f:
        original = f.read()

    if not os.path.exists(backup_path):
        with open(backup_path, 'wb') as f:
            f.write(original)

    encrypted = ARC4.new(KEY).encrypt(original)
    
    pad_len = random.randint(2048, 65535)
    padded = random.randbytes(pad_len) + encrypted + pad_len.to_bytes(4, 'little')

    with open(input_path, 'wb') as f:
        f.write(padded)

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('inputs', nargs='+', metavar='input')
    parser.add_argument('-s', '--suffix', default='.bak')
    args = parser.parse_args()

    for input_file in args.inputs:
        wrap_file(input_file, f"{input_file}{args.suffix}")

if __name__ == '__main__':
    main()
