# SECCON CTF 2023 Quals

## selfcet (pwn)

CET written by hands

```c
#define INSN_ENDBR64 (0xF30F1EFA) /* endbr64 */
#define CFI(f)                                              \
  ({                                                        \
    if (__builtin_bswap32(*(uint32_t*)(f)) != INSN_ENDBR64) \
      __builtin_trap();                                     \
    (f);                                                    \
  })

...

void read_member(ctx_t *ctx, off_t offset, size_t size) {
  if (read(STDIN_FILENO, (void*)ctx + offset, size) <= 0) {
    ctx->status = EXIT_FAILURE;
    ctx->error = "I/O Error";
  }
  ctx->buf[strcspn(ctx->buf, "\n")] = '\0';

  if (ctx->status != 0)
    CFI(ctx->throw)(ctx->status, ctx->error);
}

...

  read_member(&ctx, offsetof(ctx_t, key), sizeof(ctx));
  read_member(&ctx, offsetof(ctx_t, buf), sizeof(ctx));

```

On `CFI(ctx->throw)(ctx->status, ctx->error);`, we can set any values to throw, status and error, which means we can achieve two function calls arbitrarily.
The functions in the given program do not contain `endbr64`, so the only function that we can utilize is the libc functions that are close to `err`, which is the initial value for `ctx->throw`. (The farther the target function is, the more bruteforce attempts are requied)

My strategy is to leak the libc address first by `warn`, which is near from `throw` (hit rate is 1/16), then do `on_exit(main)`, `gets(0x00404000)` to input `"/bin/sh"`, and `system(0x00404000)`.

PoC: [solve.py](selfcet/solve.py)


## rop-2.35 (pwn)

The source program is very small:
```c
#include <stdio.h>
#include <stdlib.h>

void main() {
  char buf[0x10];
  system("echo Enter something:");
  gets(buf);
}
```

It's just a ROP challenge, so seems trivial.
But we no longer have `__libc_csu_init`, so we don't have `pop rdi; ret` gadget in the binary now. 

If you take a closer look at the binary's assembly, you may notice that
```
  0x0000000000401171 <+27>:	lea    rax,[rbp-0x10]
  0x0000000000401175 <+31>:	mov    rdi,rax
  0x0000000000401178 <+34>:	mov    eax,0x0
  0x000000000040117d <+39>:	call   0x401060 <gets@plt>
  0x0000000000401182 <+44>:	nop
  0x0000000000401183 <+45>:	leave
  0x0000000000401184 <+46>:	ret
```
if you set some value v to `rbp-0x10`, and returns to 0x401171, we obtain gets(v).
Secondly, checksec says the GOT of the binary is rewritable (and no PIE), so we can overwrite `gets` to `system`.
With those in mind, what we have to do is just loads `"/bin/sh"` to somewhere in a fixed address, and overwrite gets to system, then calls `system("/bin/sh")`.

PoC: [solver.py](rop-2.35/solve.py)

## DataStore1 (pwn)

A heap chall that requires you to do heap feng shui, just that.

The given binary provides datastore of values that are comprised of array, string, float and int values.
It distinguishes the value that it focuses on by checking the type tag with the value. So if you can modify it, then we can do type confusion stuff.

```c
typedef enum {
	TYPE_EMPTY = 0,
	TYPE_ARRAY = 0xfeed0001,
	TYPE_STRING,
	TYPE_UINT,
	TYPE_FLOAT,
} type_t;

typedef struct {
	type_t type;

	union {
		struct Array *p_arr;
		struct String *p_str;
		uint64_t v_uint;
		double v_float;
	};
} data_t;

```

The bug exsits in the edit function:
```c
static int edit(data_t *data){
	if(!data)
		return -1;

	printf("\nCurrent: ");
	show(data, 0, false);

	switch(data->type){
		case TYPE_ARRAY:
			{
				arr_t *arr = data->p_arr;

				printf("index: ");
				unsigned idx = getint();
				if(idx > arr->count) # should be >=
					return -1;
```
Here, `if(idx > arr->count)` should be `if(idx >= arr->count)`; we can edit an element out of the array by one.
Everything is allocated in heap, so the remaining part is heap feng shui.
Since we can overflow one `data_t` value, so basically we can overwrite the size and first 8 bytes of the next heap chunk.
Note that if you edit a value with an invalid type tag like 0x21, it abnormally exists, so you have to "delete" the item before you overwrite the next heap chunk.

In the heap feng shui part, I first overwrites the length parameter of a string object. Then we can create an arbitrary values and arbitrary read (AAR/AAW primitive).
By using this primitive, I leaked the [heap base address](https://github.com/moratorium08/ctf_writeups/blob/master/2023/seccon/DataStore1/solve.py#L239-L248), libc base address(https://github.com/moratorium08/ctf_writeups/blob/master/2023/seccon/DataStore1/solve.py#L252-L293), and stack address(https://github.com/moratorium08/ctf_writeups/blob/master/2023/seccon/DataStore1/solve.py#L296-L307). Then finally did ROP to trigger `system("/bin/sh")`.

PoC: [solve.py](rop-2.35/solve.py)



## readme 2023 (misc)

A simple "readme" challenge in Linux.

The challenge source is as follows:
```
import mmap
import os
import signal

signal.alarm(60)

try:
    f = open("./flag.txt", "r")
    mm = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)
except FileNotFoundError:
    print("[-] Flag does not exist")
    exit(1)

while True:
    path = input("path: ")

    if 'flag.txt' in path:
        print("[-] Path not allowed")
        exit(1)
    elif 'fd' in path:
        print("[-] No more fd trick ;)")
        exit(1)

    with open(os.path.realpath(path), "rb") as f:
        print(f.read(0x100))
```

You can read any specified files for any times except for those whose filename contains flag.txt or fd.

My teammate [@m1kit](https://x.com/m1kit) says if you can leak the address of the flag file, then we can leak the content by reading "/proc/self/map_files/...", but how?

Our strategy is to utilize "/proc/self/syscall" to accidentally leak its libc address (actually, we can achieve this with 100%), then read the corresponding map_file.

```python
data = read_file("/proc/self/syscall").decode("ascii")
print(data)
addr = data.split(" ")[-1].split("\\")[0]
print(addr)
target = int(addr, 16) +0xe9f83
flag_lb = target
flag_ub = flag_lb + 0x1000
flag_file = f"{hex(flag_lb)[2:]}-{hex(flag_ub)[2:]}"
flag_file = "/proc/self/map_files/"  + flag_file
flag = read_file(flag_file)
print(flag)
```

We learned before that `/proc/self/syscall` is sometimes strong to break ASLR.

PoC: [solve.py](readme2023/solve.py)