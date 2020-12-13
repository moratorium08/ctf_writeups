# ASIS Finals 2020

## Vote

I didn't want to reverse it since it was C++ & stripped.
However, by observing the behavior of this binary, we can triger tcache
poisoning.
So, by using this, we can overwrite freehook to system

Solver: [solve.py](vote/solve.py)

## refcnt

The vulnerability is that when you copy a buffer from idX to idX (same),
if the refcnt of idX is 1, then the program first frees it and then
increment the reference count of idX (which is the tcache's next).

So, by using this, we can trigger heap overflow.

solver: [solve.py](refcnt/solve.py)

## Crusoe

By observing the output of the binary, we can easily decode it by bruteforce.

solver: [trans.py](crusoe/trans.py)

### lzzy

Just read the program and reverse it.


## Dream

```
$ djvutxt flag.malformed
ASIS{_DJVU_f1L3 _f0rM4t_iZ _DejaVu}
ASIS{
}
A dream is a succession of images, ideas, emotions, and sensations that
usually occur involuntarily in the mind during certain stages of
sleep.
```

