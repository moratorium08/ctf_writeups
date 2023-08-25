#include <stdio.h>
#include<stdlib.h>

typedef unsigned long long u64;
u64 x;

int main(void) {
   u64 systemptr = (u64)((void*)system);
    u64 printfptr = (u64)((void*)printf);
    u64 base = (u64)(&x);
    printf("%llx, %llx\n", base, printfptr);
    for (int i = 0; i < 6; i++) {
        u64 tmp = base - i * 8;
        *(u64*)tmp = systemptr;
        printf("/bin/sh");
    }
    return 0;
}
