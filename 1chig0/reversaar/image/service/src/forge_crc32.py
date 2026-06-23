# coding: utf-8
from zlib import crc32

# adapted from https://github.com/resilar/crchack
def crcforge(target_crc:int, msg:bytes, bitmask:bytes):
    # find indices of bits that we may modify
    bits = [i for i in range(len(bitmask)*8) if bitmask[i//8]&(1<<(i%8))]

    # helper function to flip a bit in the message
    def flip_bit(msg:bytes, bit:int):
        m = bytearray(msg)
        m[bit//8] ^= (1<<(bit%8))
        return bytes(m)
    # compute crc of original message
    acc = crc32(msg)
    # compute matrix of crc-xor-difference for each flipped bit (AT[i] = crc(msg ^ (1<<bits[i])) ^ crc(msg))
    AT = [crc32(flip_bit(msg, bit)) ^ acc for bit in bits]
   
    # compute xor-difference to target-crc 
    acc ^= target_crc
    
    # index of the current pivot row
    p = 0
    # walk over all bits of the crc
    for i in range(32):
        # walk over the AT matrix to find a row that has a non-zero bit at this position
        for j in range(p, len(bits)):
            # if we have a non-zero bit, flip matrix row with that of the pivot row
            if AT[j] & (1<<i):
                bits[j], bits[p] = bits[p], bits[j]
                AT[j], AT[p] = AT[p], AT[j]
                break
        else:
            if acc & (1<<i):
                raise ValueError(f"Cannot reach target CRC, too little bits to modify")
            else:
                continue
            
        # We've got a good pivot, now update matrix rows below
        for j in range(p+1, len(bits)):
            if AT[j] & (1<<i):
                AT[j] ^= AT[p] # xor with pivot-row
                AT[j] ^= (1<<p) # flip bit at pivot-index
                
        # update accumulator
        if acc & (1<<i):
            acc ^= AT[p]
            acc |= (1<<p)
            
        # update pivot index
        p += 1
        
    needed_flips = sorted(bits[i] for i in range(32) if acc&(1<<i))
    new_msg = msg
    for bit in needed_flips:
        new_msg = flip_bit(new_msg, bit)
    return new_msg
    
def brute_crc(target_crc:int, allowed_chars:bytes, max_len:int=32, prefix=b'', suffix=b''):
    start_char = min(allowed_chars)
    always_zero = 0x00
    always_one = 0xff
    for x in allowed_chars:
        always_zero |= x
        always_one &= x
    always_zero ^= 0xff
    char_mask = (always_zero|always_one)^0xff
    
    len_prefix = len(prefix)
    len_suffix = len(suffix)
    
    for l in range(max_len):
        try:
            candidate = crcforge(target_crc, prefix+bytes([start_char]*(l+1))+suffix, b'\x00'*len_prefix + bytes([char_mask]*(l+1)) + b'\x00'*len_suffix)
        except ValueError:
            continue
        if all(x in allowed_chars for x in candidate[len_prefix:(-len_suffix) if len_suffix else None]):
            return candidate
    raise ValueError(f"Cannot reach target CRC {target_crc} in {max_len} bytes")

def patch_file(input_path, backup_path):
    import os
    with open(input_path, 'rb') as f:
        original = f.read()

    if not os.path.exists(backup_path):
        with open(backup_path, 'wb') as f:
            f.write(original)
    
    target_crc = int.from_bytes(original[:4], 'little')
    n = 1
    while True:
        try:
            patched = crcforge(target_crc, original + b'\x00'*n, b'\x00'*len(original) + b'\xff'*n)
            with open(input_path, 'wb') as f:
                f.write(patched)
            break
        except ValueError:
            n += 1

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('inputs', nargs='+', metavar='input')
    parser.add_argument('-s', '--suffix', default='.bak')
    args = parser.parse_args()

    for input_file in args.inputs:
        patch_file(input_file, f"{input_file}{args.suffix}")

if __name__ == '__main__':
    main()
