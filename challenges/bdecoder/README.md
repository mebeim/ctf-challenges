Bdecoder
========

| Release date    | Event                               | Event kind | Category | Solve stats |
|:----------------|:------------------------------------|:-----------|:---------|:------------|
| October 9, 2024 | [ECSC 2024][ecsc-2024] Jeopardy CTF | Jeopardy   | pwn      | 2/37        |

[ecsc-2024]: https://ecsc2024.it/

> I built the fastest and most secure bencode decoder out there. Wanna take it for
> a spin?
>
> ```sh
> nc bdecoder.challs.jeopardy.ecsc2024.it 47006
> ```


Description
-----------

The challenge consists of a Linux AArch64 ELF binary compiled for ARMv8.3a
(`-march=armv8.3-a`) with all protections enabled except for stack canaries.
Additionally, Pointer Authentication is enabled for all functions
(`-mbranch-protection=pac-ret`). The executable is not stripped so symbols for
function names are present.

The Docker container provided in the challenge attachments (see
[`src/Dockefile`](src/Dockerfile) and
[`src/docker-compose.yml`](src/docker-compose.yml)) runs the challenge binary
under QEMU user (`qemu-aarch64`), which is built ad-hoc with a small patch (see
[`src/qemu-9.1.0.patch`](src/qemu-9.1.0.patch)) to deter bruteforce-based
exploits. This patch increases the number of bits used for PAC signatures from 8
to 32. Using this patched QEMU version, PAC signatures are stored in the top 4
bytes of PAC-signed pointers as opposed to only the second MSB.

The program is written in C (see [`src/src/bdecoder.c`](./src/src/bdecoder.c))
and implements a simple [Bencode][bencode] decoder (with some limits on e.g.
integer sizes). The code is simple enough: it accepts one bencode-encoded object
and spits out a more human readable representation similar to JSON.

Bencode objects are very simple and only allow a few types:

- Integers encoded as `i[-]<digits>e` where the `-` is optional and `<digits>`
  are base-10 ASCII digits.
- Strings encoded as `<len>:<content>` where `<len>` is an integer in base-10
  ASCII digits.
- Lists encoded as `l<contents>e` where `<contents>` is an arbitrary amount of
  other objects in order.
- Dictionaries encoded as `d<contents>e` where `<contents>` is an arbitrary
  amount of `<key><value>` pairs where `<key>` is a string and `<value>` can be
  any object. The keys in a dictionary must appear in lexicographical order.

The program implements one `bdecode_xxx()` function for each object type (as
well as other helpers):

- `bdecode_integer()`
- `bdecode_string()`
- `bdecode_list()`
- `bdecode_dict()`

A general `bdecode()` function is used to detect the type based on the next
character read from the input stream and call the appropriate function. Since
Bencode objects can be nested arbitrarily using lists and/or dictionaries,
`bdecode()` is also called to decode list contents and dictionary values.

Decoding is implemented recursively and only a single initial call to
`bdecode()` is made.


Bugs
----

There are two easy-to-spot linear buffer overflow bugs (see also the source code
comments in [`src/src/bdecoder.c`](./src/src/bdecoder.c) for more info):

1. In `bdecode_integer()` a bad bound check allows reading up to 17 bytes past
   the end of a `char` array on the stack of the function, overwriting the saved
   frame pointer and return address of the caller function (the stack frame
   setup convention in AArch64 puts the saved return address and frame pointer
   before the current stack frame, at lower addresses).
2. In `bdecode_string()` an off-by-one in a length check allows reading one more
   byte of input past the end of a `char` array on the stack of the function,
   overwriting the LSB of a local `char *` pointer that is then printed to
   standard output via `fwrite()`.

The 1st bug would normally allow hijacking the execution through overwrite of
the saved return address, however the binary uses PAC, and therefore all
functions use [PACIASP][aarch64-paciasp] in the prolog to sign the return
address (using the stack frame register value as modifier) before saving it to
the stack, and [RETAA][aarch64-retaa] in the epilog to authenticated the saved
return address (again using the stack frame register value as modifier).
Therefore, we cannot simply overwrite the return address with an arbitrary
address as the RETAA authentication would fail and make the program crash
returning to an invalid address.


Solution
--------

The idea is to use bug 2 to leak a valid saved frame pointer and PAC-signed
return address. Then, use bug 1 to overwrite the caller saved frame pointer and
PAC-signed return address with the leaked values. If this is done at the right
(matching) stack depth, the two frame pointers (leaked and overwritten) will be
exactly the same, and RETAA will succeed despite the return address being
different, making the caller of `bdecode_integer()` return to a different
location than the expected one with a corrupted stack frame.

The `bdecode()` function holds a boolean variable on the stack that is set as
follows:

```c
static void bdecode(void) {
 bool debug = false;
 int c;

 if (getenv("DEBUG") && !strcmp(getenv("DEBUG"), "1")) {
  /* This will never happen */
  debug = true;
 }

 if ((c = getchar()) == EOF)
  _exit(0);

 switch (c) {
  // ... chose which bdecode_xxx() func to call
 }

 if (debug)
  system("gdb-multiarch --pid $PPID");
}
```

If we can make a function return where one of the functions called in the
`switch` statement would return, then we may be able to corrupt the value of
`debug` (since we would be returning with an altered stack pointer) and get a
GDB shell.

A stack frame has the following form (addresses increase downwards):

```none
SP        <saved FP=X29>
SP + 0x08 <saved PAC-signed LR=X30> (signed using FP=X29 as modifier)
SP + 0x10 <...locals...>
SP + 0x18 <...locals...>
...
SP + 0xXX <caller stack frame>
```

We will set up the stack as follows by decoding 6 nested lists with the deepest
one containing a string (addresses increase downwards):

```none
     #   FUNCTION        FRAME SIZE      FP=X29 VALUE *ON ENTRY*
     15  bdecode_string  <not relevant>  <not relevant>
     14  bdecode         <not relevant>  <not relevant>
===> 13  bdecode_list    <not relevant>  BASE - 0x140 <===================
     12  bdecode         0x20            BASE - 0x120
     11  bdecode_list    0x20            BASE - 0x100
     10  bdecode         0x20            BASE - 0xe0
     9   bdecode_list    0x20            BASE - 0xc0
     8   bdecode         0x20            BASE - 0xa0
     7   bdecode_list    0x20            BASE - 0x80
     6   bdecode         0x20            BASE - 0x60
     5   bdecode_list    0x20            BASE - 0x40
     4   bdecode         0x20            BASE - 0x20
     3   bdecode_list    0x20            BASE
     2   bdecode         <not relevant>  <not relevant>
     1   bdecode_line    <not relevant>  <not relevant>
     0   main            <not relevant>  <not relevant>
```

Then, trigger the off-by-one bug in `bdecode_string()` (bug 2) and overwrite the
LSB of the local `char *` pointer making it point close enough to the frame 13
(this is the reason for the 6 nested lists). This will leak the saved frame
pointer and PAC-signed return address of frame 13 belonging to `bdecode_list()`.

The PAC-signed return address in frame 13 was signed using the frame pointer (FP
i.e. X29) at the moment of entry in `bdecode_list()`, whose value was exactly
`BASE - 0x140`.

We then only close 3 of the 6 lists we created, so now the stack looks like this
(we are currently inside `bdecode()`, which will decode the next data we send):

```none
     #   FUNCTION        FRAME SIZE      FP=X29 VALUE *ON ENTRY*
     8   bdecode         0x20            BASE - 0xa0
     7   bdecode_list    0x20            BASE - 0x80
     6   bdecode         0x20            BASE - 0x60
     5   bdecode_list    0x20            BASE - 0x40
     4   bdecode         0x20            BASE - 0x20
     3   bdecode_list    0x20            BASE
     2   bdecode         <not relevant>  <not relevant>
     1   bdecode_line    <not relevant>  <not relevant>
     0   main            <not relevant>  <not relevant>
```

Now we can set up the stack like this by sending a couple of nested dictionaries
where the innermost one contains an integer value (we already had half of the
frames):

```none
       #   FUNCTION            FRAME SIZE      FP=X29 VALUE *ON ENTRY*
       15  bdecode_integer     <not relevant>  <not relevant>
 ====> 14  bdecode             <not relevant>  BASE - 0x140 <==============
       13  bdecode_key_value   0x10            BASE - 0x130
       12  bdecode_dictionary  0x20            BASE - 0x110
       11  bdecode             0x20            BASE - 0xf0
       10  bdecode_key_value   0x10            BASE - 0xe0
       9   bdecode_dictionary  0x20            BASE - 0xc0
       8   bdecode             0x20            BASE - 0xa0
       7   bdecode_list        0x20            BASE - 0x80
       6   bdecode             0x20            BASE - 0x60
       5   bdecode_list        0x20            BASE - 0x40
       4   bdecode             0x20            BASE - 0x20
       3   bdecode_list        0x20            BASE
       2   bdecode             <not relevant>  <not relevant>
       1   bdecode_line        <not relevant>  <not relevant>
       0   main                <not relevant>  <not relevant>
```

We are again at the same depth as the first step when we got the leak. This
means that the value of the saved frame pointer (FP i.e. X29) in frame 14 was
again exactly `BASE - 0x140`, i.e. *the same as the one we leaked*. This means
that the PAC-signed saved return address (`LR` i.e. `X30`) in frame 14 and the
one we leaked earlier used the exact same value (`FP` i.e. `X29`) as modifier.

The only thing that changes is the return address: here `bdecode()` in frame 14
wants to return somewhere inside `bdecode_key_value()`. The previously leaked
PAC-signed return address refers to a `bdecode_list()` frame that wanted to
return somewhere inside `bdecode()`. Since both values were signed with the same
key (generated on program exec) and the same modifier (frame pointer), the two
are interchangeable and will both pass the pointer-authenticated RETAA
instruction.

We can now trigger the small linear BOF in `bdecode_integer()` (bug 1) to
overwrite the saved frame pointer and PAC-signed return address of `bdecode()`
in frame 14 with the one we previously leaked. As a result, `bdecode()` will
happily return inside of itself.

Upon return, the stack will contain garbage values. The `bdecode()` function
checks for the value of a local boolean variable at `SP + 0x1f`, which very
conveniently corresponds with the MSB of a PAC-signed saved LR. When this bool
variable is then checked at the end of `bdecode()` to choose whether to spawn
`gdb-multiarch` through `system()`, we will therefore have a 50% chance of
getting a GDB shell.

> [!NOTE]
> **Author's note**: even though the README provided in the challenge
> attachments states that it is possible to exploit the program using both a
> patched and unpatched `qemu-aarch64`, it is actually only possible with the
> patched version because it uses the top 4 bytes of signed pointers to store
> the PAC signature, whereas an unpatched version only uses the second MSB to
> store the PAC signature.


Complete exploit
----------------

See [`checker/__main__.py`](checker/__main__.py) for the complete exploit.

[aarch64-paciasp]: https://developer.arm.com/documentation/dui0801/g/A64-General-Instructions/PACIA--PACIZA--PACIA1716--PACIASP--PACIAZ
[aarch64-retaa]: https://developer.arm.com/documentation/dui0801/g/A64-General-Instructions/RETAA--RETAB
[bencode]: https://en.wikipedia.org/wiki/Bencode
