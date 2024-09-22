# ierae CTF writeup


## Intel CET

1. Register `main` as the signal handler for segfault
2. basically, open -> read -> puts

However the second part requires a trick since we can only control two arguments
for each function call, the argument is set to 0.

I utilized `__uflow`, which is a unary-function that takes a FILE pointer, and 
reads a byte.
Since `__uflow` does IO buffering like other IO-related functions, if we call it 
with a specific fake FILE structure, we can read the content into an arbitrary
address.

solver: [cet/solve.py](cet/solve.py)


## Command Recorder

The bug was `strcpy(buf, buf', n)` where buf and buf' are overlapping.
The actual implementation for strcpy on the server uses __strcpy_avx2, and therefore 
we can exploit some optimizations in the function to trigger some undefined behavior.

solver: [command_recorder/solve.py](command_recorder/solve.py)

## Copy & Paste


```
❯ nc 52.231.220.191 5001

1. Create new buffer and load file content
2. Copy some buffer to another
3. Exit
Enter command: 1
Enter file name: /lib/x86_64-linux-gnu/libc.so.6
Read 2105184 bytes from /lib/x86_64-linux-gnu/libc.so.6
1. Create new buffer and load file content
2. Copy some buffer to another
3. Exit
Enter command: 1
Enter file name: /proc/self/fd/0
Read -1 bytes from /proc/self/fd/0
1. Create new buffer and load file content
2. Copy some buffer to another
3. Exit
Enter command: 2
Enter source index: 0
Enter destination index: 1
Well done!
IERAE{7h3_f1rs7_s73p_7o_b3_4_pwn3r_51a7806b}
```

## warmup_pwn

```
Enter number of rows: 4
Enter number of cols: 4611686018427387905
```

## Luz Da Lua

Just decompile it.