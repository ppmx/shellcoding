#!/usr/bin/env python3

""" This tool extracts opcodes from a function of a binary.

Example:
./opcodes.py -f _start -b /tmp/hello_world -o /tmp/hello_world.shellcode
"""

import argparse
import subprocess

def extract_opcode(binary, function):
    """ Runs gdb disassemble on the given binary and extract the opcodes from the gdb output.
    Returns the opcodes (hex encoded) or None on errors.
    """

    cmd = f"gdb -batch -ex 'file {binary}' -ex 'disassemble /r {function}'"

    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, check=True)
    except subprocess.CalledProcessError as e:
        print("[!] Error:", e)
        return None

    lines = proc.stdout.decode().split('\n')

    shellcode = []

    print("[+]", lines[0])

    lines = [codeline.split('\t') for codeline in lines[1:-2]]
    maxlen_addr = max([len(address) for address, _, _ in lines])
    maxlen_ops = max([len(ops) for _, ops, _ in lines])
    maxlen_cmd = max([len(cmd) for _, _, cmd in lines])

    for address, ops, cmd in lines:
        #print(address.ljust(maxlen_addr), ops.ljust(maxlen_ops), cmd, sep='|')
        #print('-' * maxlen_addr, '-' * maxlen_ops, '-' * maxlen_cmd, sep='+')

        print(address.ljust(maxlen_addr), ops.ljust(maxlen_ops), cmd)

        shellcode += ops.split(' ')

    shellcode_length = len(bytes.fromhex(''.join(shellcode)))

    print()
    print(f"[+] Opcodes ({shellcode_length} bytes) from function '{function}' of binary '{binary}'")
    print(''.join(shellcode))
    return ''.join(shellcode)


def main():
    """ Cli """

    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--function', default='_start', help='name of function to extract')
    parser.add_argument('-b', '--binary', required=True, help='path to binary file')
    parser.add_argument('-o', '--output', help='path where to store opcodes')
    args = parser.parse_args()

    print("[+] Analyzing:", args.binary)
    print("[+] Extracting:", args.function)

    opcodes = extract_opcode(args.binary, args.function)

    if not opcodes:
        print("[!] extracting opcodes failed")
        return

    if args.output:
        with open(args.output, 'wb') as f:
            f.write(bytes.fromhex(opcodes))


if __name__ == "__main__":
    main()
