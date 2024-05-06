# DEF CON CTF Qualifier 2024

Participated in DEF CON CTF Qual 2024 as a member of undef1ned.
Here I just put my PoCs in this repo for someone's future reference, but there are a lot of cooperations in the team.
(Especially, [ngkz](https://twitter.com/n_g_k_z), [mmxsrup](https://twitter.com/mmxsrup), and [Iwancof_ptr](https://twitter.com/Iwancof_ptr)).

## [chatgpt-wasi](chatgpt-wasi/solve.py) 
 - this wasi's `memory` is not sandboxed. Out of bounds access is available.
 - Especially, if you declare `(memory 0)`, the interpreter tries to allocate a memory region with 0 page with mmap, and it returns an error. However, error handling is not correctly implemented by ChatGPT, so the memory is "mapped" to -1, which is the return value of `mmap`.

## [saferrrust](saferrrust/solve.py)
 - Tons of bugs in the binary. You can refer to the source code in the [official repository](https://github.com/Nautilus-Institute/quals-2024/tree/main/saferrrust) (even though there is only a stripped rust binary during the contest...)
 - The crux of this challenge is to win the game when you have 28 points. It should be your winning situation. However, due to the "off-by-one" bug, it just raises an integer overflow panic (28 + 100 in signed char). The panic is "handled" by some unwinding mechanism, and the program just proceeds as if nothing happend except that it outputs some error message to error.log.
 - Error.log can be mapped (by triggering a bug by `save(0)`) to a readable region in the program which contains the filenames to the save files.
 - So the `error.log` message can overwrite the name of saved files, leading to the access to `/flag` by loading the saved game.
