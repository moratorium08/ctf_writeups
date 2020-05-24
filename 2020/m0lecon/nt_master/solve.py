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
host = 'challs.m0lecon.it'
port = 10000

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


def gcd(a, b):
    if b > a:
        return gcd(b, a)
    if b == 0:
        return a
    return gcd(b, a % b)

#def lcm(a, b):
#    return a * b / gcd(a, b)


sys.setrecursionlimit(100000)

def factorization(n):

    factors = []

    def get_factor(n):
        x_fixed = 2
        cycle_size = 2
        x = 2
        factor = 1

        while factor == 1:
            for count in range(cycle_size):
                if factor > 1: break
                x = (x * x + 1) % n
                factor = gcd(x - x_fixed, n)

            cycle_size *= 2
            x_fixed = x

        return factor

    while n > 1:
        next = get_factor(n)
        factors.append(next)
        n //= next

    return factors

from primefac import primefac
def gen(n):
    factors = list(primefac(n - 1))
    a = factors[0]
    b = 1
    for f in factors[1:]:
        if gcd(f, a) != 1:
            a *= f
        else:
            b *= f

    if b > a:
        return (b, a)
    return (a, b)

def gen2(n):
    n = n - 1
    a = 1
    for i in [2, 3, 5, 7, 11, 13, 17, 19]:
        if n % i == 0:
            while n % i == 0:
                a *= i
                n //= i
    b = n
    if b > a:
        return (b, a)
    return (a, b)



for i in range(10):
    recvuntil('N = ')
    n = int(recvline())
    print(i, n, end = ' ')
    if i < 0:
        a, b = gen(n)
    else:
        a, b = gen2(n)
    print(a, b)
    sendline('{} {}'.format(a, b))

interactive()

