from __future__ import print_function
from z3 import *


target = 'OOO{xxxx xx xxxxx xxxx xxx xxx xxx xxxx xxxx xxxxxx xxxxx}'

xs = [BitVec("x%d" % i, 8) for i in range(len(target))]

s = Solver()

global_id = 0
def gen_id():
    global global_id
    tmp = global_id
    global_id += 1
    return tmp

class L:
    def __init__(self, char):
        self.id = gen_id()
        self.char = char
        self.y = 1
        self.cnt = 1
        self.fd = None
        self.bk = None

    def to_str(self, printed, space=0):
        if self in printed:
            return 'ommited'
        s = ''
        s = '{}L{}({}, {}, {})\n'.format(' '* space, self.id, self.cnt, self.fd is not None, self.bk is not None)
        if self.fd is not None:
            s += self.fd.to_str(printed + [self], space + 1)
        if self.bk is not None:
            s += self.bk.to_str(printed + [self], space + 1)
        return s


    def __repr__(self):
        return self.to_str(printed = [])

for x, c in zip(xs, target):
    if c != 'x':
        s.add(ord(c) == x)
    else:
        s.add(x >= ord('a'))
        s.add(x <= ord('z'))


insts = list(enumerate(open('copy.txt').read().strip('\n').split('\n')))
start = 67138

insts = insts[start:]


def get_next_inst_w_id():
    global insts
    tmp = insts[0]
    insts = insts[1:]
    return tmp[0], tmp[1][:32]

def get_next_inst():
    return get_next_inst_w_id()[1]

def until(name):
    while True:
        inst = get_next_inst()
        if inst == name:
            return name

def modify_fd(mychar):
    until('82d0a15c53505f9cbe99f6d72683ce27')
    inst = get_next_inst()
    if inst == '3f22294678ad1d8370ac9af2a3313c8f':
        assert mychar.fd is None
    elif inst == '72740ca10ff290d30652b7b96433e230':
        assert mychar.fd is not None
        until('98d38856414f65c192bbf00f01e1a835')
        inst = get_next_inst()
        if inst == 'eeef3e11294110f840d4fc0a1273c089':
            assert mychar.fd.y == mychar.y
            tmp = mychar.fd
            mychar.fd = tmp.bk
            tmp.bk = mychar
            return tmp
        elif inst == '3f22294678ad1d8370ac9af2a3313c8f':
            assert mychar.fd.y != mychar.y
            pass
        else:
            assert False
    else:
        assert False
    return mychar

def modify_bk(mychar):
    until('cdd8d0db80a1e08e0b2f480d2437b45d')
    idx, inst = get_next_inst_w_id()
    if inst == '40e0f0d7c4a81e18cc330857a716b6b0':
        assert mychar.bk is None
    elif inst == '04608c8c42945be650a05ad604ed4e59':
        #print(mychar, idx)
        assert mychar.bk is not None
        until('1d3cd83339084286a1100abe18df6cc3')
        inst = get_next_inst()
        if inst == '01674d2ba41f0138a8e8698cc94236f4':
            assert mychar.bk.bk is not None
            until('df94ae98b0d0af748ec2d249182b86b0')
            inst = get_next_inst()
            if inst == '40e0f0d7c4a81e18cc330857a716b6b0':
                assert mychar.bk.bk.y != mychar.y
            elif inst == '57c4fb55862a54ce50f667af48b390e7':
                assert mychar.bk.bk.y == mychar.y
                tmp = mychar.bk
                mychar.bk = tmp.fd
                tmp.fd = mychar
                tmp.y += 1
                return tmp
        elif inst == '40e0f0d7c4a81e18cc330857a716b6b0':
            assert mychar.bk.bk is None
        else:
            assert False

    else:
        assert False
    return mychar


def gen_linklist(mychar, x):
    until('1ccf67eb90afcbc0a72bda0f51ef585a')
    inst = get_next_inst()
    if inst == '7e8d3d12f9987acc83634394bb225179':
        assert mychar is None
        mychar = L(x)
        until('035619afe13a4b106de53674a406125f')
        return mychar
    elif inst == '62c2cd053dfa2c78589308e078cb3740':
        assert mychar is not None
        until('8fdbe9aa0207d8d43c9cc65f5d1e3bb3')
        inst = get_next_inst()
        if inst == 'b39fabb14ca48dfa222944f6b24fff4b':
            s.add(mychar.char == x)
            mychar.cnt += 1
        elif inst == 'e1e3ec730b3d9aca7cc552d86413a373':
            s.add(mychar.char != x)
            until('c6da03fb51bc6a158efcda7c7bd491c3')
            inst = get_next_inst()
            if inst == '5f694f9d4d0ea82638f21bae6503ee8c':
                until('a2648a849526903f1553126aa4119b79')
                s.add(x > mychar.char)
                mychar.bk = gen_linklist(mychar.bk, x)
            elif inst == 'c622d85d8eac36de71a2da9b7c141eec':
                until('9fd18c435279a11cc106c4933676a7d9')
                s.add(x < mychar.char)
                mychar.fd = gen_linklist(mychar.fd, x)
                #print(mychar)
            else:
                assert False
        else:
            assert False

        until('83558aaf42e5b6c58859338ad3e67ec6')
        mychar = modify_fd(mychar)
        until('7dd2b7931b57d948b675c187dcdb0104')
        mychar = modify_bk(mychar)
    else:
        assert False
    return mychar


mychar = None
for i,x in enumerate(xs[:-1]):
    print(i)
    mychar = gen_linklist(mychar, x)

if sat == s.check():
    m = s.model()
    s = ''.join([chr(m[xs[i]].as_long()) for i in range(len(target))])
    print(s)
else:
    print('fail')
'''
def modify_fd(mychar):
    if mychar.fd is None:
        return mychar

    if mychar.fd.y == mychar.y:
        tmp = mychar.fd
        mychar.fd = tmp.bk
        tmp.bk = mychar
    return mychar


def gen_linklist(mychar, char):
    if mychar is None:
        mychar = L(char)
        return mychar

    if mychar.char != char:
        if char >= mychar.char:
            mychar.bk = gen_linklist(mychar.bk, char)
        else:
            mychar.fd = gen_linklist(mychar.fd, char)
    else:
        mychar.cnt += 1
    mychar = modify_fd(mychar)
    mychar = modify_bk(mychar)
    return mychar
'''
