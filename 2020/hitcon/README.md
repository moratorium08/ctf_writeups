# HITCON CTF 2020 writeup

## Revenge of Pwn

This part is vulnerable since you can inject some assembly code.

```
log.info('sock fd @ ' + fd)

backdoor_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'backdoor')
stage2 = asm(shellcraft.stager(fd, 0x4000))
```

so, we put `#include "/home/deploy/flag"` and see the error log.

[revenge.py](revenge.py)

## tenet

You can create functions for [0, 0xff]

```
mov bl, 0xab
ret
```

Then, read a byte of cookie and call the corresponding function.
By using this bl, you can retrive the cookie after the mid-check.

[tenet.py](tenet.py)


## Dual

`write_bin` is vulnerable if you put the buffer with length 0.

By using this, we can create an arbitrary node object.
Making use of it, you can leak libc address and overwrite stroutol to system.

[dual.py](dual.py)
