#!/usr/bin/env python3

import os
import re
from zlib import crc32
import random
import codecs

MARKER = '#define OBF_MARKER'

def add_global_defs(code, defs):
    splitloc = code.find('\n', code.find(MARKER))
    
    before, after = code[:splitloc], code[splitloc:]
    return before + '\n' + '\n'.join(defs) + after
    

def obf_strcmp(code, file_id):
    PTN_ARG1_CONST = re.compile(r"strcmp\(\s*\"([^\",]*)\"\s*,\s*([^\",]*)\s*\)")
    def rep_arg1(match):
        arg1, arg2 = match.groups()
        return f"({crc32(arg1.encode()):#0x} != crc32(0, {arg2}, strlen({arg2})))"

    code = PTN_ARG1_CONST.sub(rep_arg1, code)
    code = add_global_defs(code, ["#include <zlib.h>"])

    PTN_ARG2_CONST = re.compile(r"strcmp\(\s*([^\",]*)\s*,\s*\"([^\",]*)\"\s*\)")
    def rep_arg2(match):
        arg1, arg2 = match.groups()
        return f"(crc32(0, (const unsigned char*){arg1}, strlen({arg1})) != {crc32(arg2.encode()):#0x})"

    code = PTN_ARG2_CONST.sub(rep_arg2, code)

    return code

def obf_strings(code, file_id):
    PTN_STRING = re.compile(r"\"(([^\"\\]|\\[rn\"])*)\"")
    strings = ['#include "xorstring.h"']
    def rep_string(match):
        string_data = match.group(1)
        if string_data.endswith(".h"): # hack: do not obfuscate include paths
            return match.group(0)
        if string_data == "default": # hack: do not obfuscate symbol visibility
            return match.group(0)
        string_bytes = codecs.decode(string_data, 'unicode_escape').encode('ascii')
        l = len(string_bytes)
        xor_key = random.randbytes(l)
        k_id = len(strings)
        strings.append(f"char str_{file_id}_{k_id}[{l}] = {{{','.join(hex(c) for c in xor_key)}}};")
        encrypted = bytes(x^y for x,y in zip(string_bytes, xor_key))
        e_id = len(strings)
        strings.append(f"char str_{file_id}_{e_id}[{l}] = {{{','.join(hex(c) for c in encrypted)}}};")
        return f"xor_string(str_{file_id}_{e_id}, str_{file_id}_{k_id}, {l})"

    code = PTN_STRING.sub(rep_string, code)
    code = add_global_defs(code, strings)
    return code

PASSES = [
    obf_strcmp,
    obf_strings
    ]

def obfuscate_file(input_path, backup_path):
    with open(input_path) as f:
        original = f.read()

    if not os.path.exists(backup_path):
        with open(backup_path, 'w') as f:
            f.write(original)

    obfuscated = original
    if MARKER in original:
        for obfuscation_pass in PASSES:
            obfuscated = obfuscation_pass(obfuscated, input_path.replace('/','_').replace('.','_'))
        # lastly, remove marker
        obfuscated = obfuscated.replace(MARKER, '')

    with open(input_path, 'w') as f:
        f.write(obfuscated)

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('inputs', nargs='+', metavar='input')
    parser.add_argument('-s', '--suffix', default='.bak')
    args = parser.parse_args()

    for input_file in args.inputs:
        obfuscate_file(input_file, f"{input_file}{args.suffix}")

if __name__ == '__main__':
    main()
