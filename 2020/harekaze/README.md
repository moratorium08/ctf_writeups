# Harekaze Mini CTF 2020

## kodama

The binary is as follows:

```c
int main() {
    char buf[0x20];
    for (int i = 0; i < 2; i++) {
        fgets(buf, 0x20, stdin);
        printf(buf);
    }
    return 0;
}
```

We can do format string attack "at least" two times.
First, we leak an address in libc and stack.
Second, we overwrite loop-index variable `i`
on the stack by some negative value (this can be done by overwriting the MSB of the integer variable by some number > 0x7f).

Now, we can do FSB attack arbitrarily. To get the shell, we overwrite the return address of main.

[solver.py](kodama/solver.py)


## NM Game Extreme

We can select almost all the address (where the value of it is not 0) as a pebble's heap, and subtract some numbers from it.
By using this, we can subtract the number of `remaining_game` until it becomes 0.
Then, after you complete the current game, we can get the flag.

[solver.py](nmgame-extreme/solver.py)


## shellcode

The given binary accepts a shellcode and executes it.
The binary is not PIE and contains "/bin/sh",
so, by using it,

```
mov rdi, 0x404060
mov rsi, 0
mov rdx, 0
mov rax, 59
syscall
```
(execve("/bin/sh", NULL, NULL))

will open the shell.

[solver.py](shellcode/solver.py)

## wait

We can replace "call system", which triggers "sleep 3.0",
by "xor rax, rax; nop; nop".
Then, we just did brute force of all the possible inputs
(at most 26^4 tests were required), and got the flag.

