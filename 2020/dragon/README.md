# DragonCTF 

Participated as a member of TSG (28th).

## Heap Hop

This service has two functions

- create a buffer with a specified size and write some data whose size is equal to the given size
- free a buffer by specifing object id

We call the data structured used in this chall "Chunk", which has the following elements

```
        0 +--------+
          +  size  +
        4 +--------+
          +  flags +
       16 +--------+
          + offset +
     size +--------+
          + data[1]+
 2 * size +--------+
          +data[1:]+
          +   ...  +
```

Each chunk contains 96 (= 12 * 8). The first element of each chunk is used for managing each chunk. `size` is 16-bytes aligned. Each bit of `flags` corresponds to each buffer the chunk has.
The program has an array of chunks, and when it is asked to create a buffer with some size S, it search for a chunk whose size is S. 
If it cannot find it, then it creates a new chunk and register it to the array.
Also, when the user frees a buffer, and the program finds the buffer is the last element in a chunk, it frees the chunk. 

### Vulnerabilities

There are two vulnerabilities.
- When the program creates a new chunk, it does not clear the buffer with 0. So, we can leak the libc address by observing `chunk_id`
- We can free the first element of a chunk, which is used for managing each chunk. By using this, we can change `size` and `flags` elements by re-allocating the first element, which leads to heap overflow.

### How to solve

Easily, we can get a libc-address by the first vulnerability.

Since the smallest size we can create is 96 * 0x10, we cannot use some techniques related to tcache/smallbins.

Our approach is to create a mmap buffer on the top of libc-region like

```
0x00007f10ca528000 0x00007f10ca54d000 rw-p	mapped                                      <-- this one
0x00007f10ca54d000 0x00007f10ca572000 r--p	/usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007f10ca572000 0x00007f10ca6ea000 r-xp	/usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007f10ca6ea000 0x00007f10ca734000 r--p	/usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007f10ca734000 0x00007f10ca735000 ---p	/usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007f10ca735000 0x00007f10ca738000 r--p	/usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007f10ca738000 0x00007f10ca73b000 rw-p	/usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007f10ca73b000 0x00007f10ca741000 rw-p	mapped
```


Then we re-allocate the first element of that chunk so that the last element of chunk is in the rw-region of libc-region. 
We can overwrite `__free_hook` by creating a buffer at the last element of that chunk, which leads to getting a shell.


### Solver

[heap.py](heap.py)

## BabyShell

### Observation

There is a qemu-sandbox in which a server is running. We have a shell to connect to the sandbox but we can use only busybox.

### How to solve

I analyzed server application (and busybox, which is not requied for this chall :( ), and found that it was enough to communicate with server application, which was started by `/init`.
This server application uses SSL. We can get the flag by `openssl s_client -connect localhost:4433`

The main challenge is that it is difficult to do an arbitrary since the filesystem is readonly and we cannot send any program to the sandbox.
I asked for help [kcz146](https://twitter.com/kcz146), who is a linux-pro, and he immediately found that we could use nc and gave me a nice command: `cat | xargs -I{} printf '\x{}' | busybox nc localhost 4433 | hexdump -v -e '1/1 "X%02x\n"'`.

So I wrote a proxy and solved it.
