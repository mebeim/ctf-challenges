No Headache
===========

| Release date   | Event                                  | Event kind           | Category | Solve stats |
|:---------------|:---------------------------------------|:---------------------|:---------|:------------|
| March 18, 2024 | [openECSC 2024][openecsc-2024] Round 1 | Jeopardy, individual | pwn      | 13/500+     |

[openecsc-2024]: https://open.ecsc2024.it/

> All these complicated memory allocators only give me headaches, so I decided to
> go with a much simpler implementation. Simpler code = less bugs = no more
> getting pwned!
>
> This is a remote challenge, you can connect to the service with:
>
> `nc noheadache.challs.open.ecsc2024.it 38004`


Overview
--------

The challenge consists of an interactive binary program (Linux ELF) that
provides a CLI to run simple commands to create and edit "objects". The binary
is dynamically linked with all the usual protections enabled at build time: PIE,
NX, full RELRO, stack canaries, fortify.

The binary implements its own `malloc()`, `calloc()`, `realloc()` and `free()`
functions, with implementation taken from Glibc's
[`dl-minimal-malloc.c`][dl-minimal-malloc].

The CLI offers 5 main commands:

- `n) New object`: allocates a new object and inserts it as the head of a global
  linked list.
- `s) Set object properties`: sets properties as key-value pairs for the object
  currently at the head of the linked list.
- `p) Print object`: pretty-prints an object at a given index in the linked
  list, with properties in JSON-like form.
- `z) Get object size`: prints the size of the properties of an object at a
  given index.
- `d) Delete object`: deletes (frees) an object at a given index.

An object is represented as a `struct` with a flexible `properties` array
member:

```c
struct object {
    size_t size;
    struct object *next;
    char properties[];
};
```

When an object is created, it is initially allocated without properties through
`calloc()` and inserted at the head of a global linked list, updating its
`->next` pointer, but leaving its `->size` to `0`. Indeed, the `size` member
refers to the size of the `properties` array, which is initially empty.

Printing an object (or its size) and deleting an object require specifying an
index, which is used to traverse the global linke list of objects up to the
specified one before performing the operation. When this is done, a sanity check
is made on the size of the objects encountered while traversing the list. This
sanity check is however skipped for the last object (the one at the specified
index).

When setting the properties of an object, they are parsed and stored as
consecutive NUL-terminated strings into the `properties[]` array of the object
(e.g., `foo=bar;baz=123` is represented as `foo\0bar\0baz\0123\0`). When
printing them out, each original key-value pair is printed in JSON notation
(e.g., `"foo": "bar",`).

The "set properties" command allows to input up to 0x1000 bytes representing
object properties in the form `foo=bar;baz=123;...`. When this is done, and the
new properties have a larger size, the object is re-allocated through
`realloc()`. The `realloc()` implementation (`__minimal_realloc()`) makes it so
that only the last allocation can be resized, and thus only the last object that
was allocated can be "edited" to a bigger size.

The `malloc()` implementation (`__minimal_malloc()`) keeps track of the last
allocation and the end of the current heap region with global pointers, and
requests new memory pages on demand through `mmap(2)` when the current heap
region is exhausted, rounding up the requested size to page size plus one more
page to try and limit the amount of `mmap(2)` syscalls.

Given the nature of `malloc()`, `calloc()` does not zero-out memory, as newly
mapped pages are always zeroed by the kernel. Freeing is a no-op except when
freeing the last allocated chunk, in which case the memory is zeored and the
global pointers that keep track of the current heap region are updated.


Bug(s)
------

The vulnerability present in the code is inspired to CVE-2023-4911. The property
parsing code behaves incorrectly when a string of the form `foo=bar=baz` is
encountered: instead of stopping after realizing the malformed key-value pair
(or interpreting as value anything after the first `=`), it first copies the
whole string out (`foo=bar=baz`), then skips the first `=` and copies the second
one (`bar=baz`) as if it was a new key-value pair.

The parsing function is supposed to write out a result that is at most the same
size as its input, the above behavior breaks this assumption, and causes a
linear buffer overflow in the output buffer, which in this case is the
`properties[]` array of an object.


Solution
--------

Due to the linear buffer overflow and the straight-forward behavior of the
allocator, allocated objects can be corrupted in two main ways:

1. Allocating an object *A*, then setting its properties and triggering an
   overflow, writing where the size of the next allocated object should be, then
   allocating a second object *B*. The size of *B* will not be set on creation
   (as it is assumed to be zero) and will remain the one that was set through
   the overflow. This method however cannot be used to corrupt the `->next`
   pointer of *B*, as it will be overwritten on creation when it is inserted as
   head of the global linked list of objects.

   ```text
     o------------o
   A | 0x20       | sz
     | 0x0        | next
     | XXXXXXXXXXXX properties[]
     +------------+
   B | XXXXXX     | sz
     | &A         | next
     | ...        | properties[]
   ```

2. Allocating an object *A* and then allocating more objects until the current
   heap region (of at least 2 pages) is exhausted. After this, the next object
   that is allocated (*C*) will warrant a new `mmap(2)` and, due to `mmap`'s
   behavior, end up before (lower address) the first heap region and contiguous
   to it.

   ```text
     o------------o ---------------- second region (0x2000)
   C | 0xf00      | sz
     | 0x0        | next
     | &B         | properties[]
     +------------+
   D | 0xf00      | sz
     | &C         | next
     | ...        | properties[]
     +------------+
   E | 0x80       | sz
     | &D         | next
     | XXXXXXXXXXXX properties[]
     o------------o ---------------- first region (0x2000)
   A | XXXXXXXXXXXX sz
     | XXXXXX     | next
     | ...        | properties[]
     +------------+
   B | 0xf00      | sz
     | &A         | next
     | ...        | properties[]
   ```

   Allocating a couple more objects to fill the gap in the second heap region
   will make it so that the last object allocated (*E* above) will be right
   before the first one allocated (*A* above). Setting the properties of *E* and
   triggering the overflow, it is possible to corrupt both the size and the
   `->next` pointer of *A* (and potentially also other objects past it,
   depending on the setup).

Using a combination of the above methods it is also possible to end up with an
object *X* with corrupted size right before another (previously allocated)
object *Y*, and therefore corrupt *Y* through the properties of *X* without even
triggering the bug that leads to the overflow (as the size of *Y* is already
broken).

We can obtain an address leak to defeat ASLR and locate libc in memory in two
ways:

- Leaking the `->next` pointer of an existing object. This works because any
  mapped heap region will be at a given static offset from other previously
  mapped regions (including loader and libraries).
- Leaking data past the first heap region, which is mapped (contiguously) right
  before the loader (`ld-linux-x86-64.so.2`).

The second option is very simple: create an object, set its properties and cause
overflow to corrupt the size of the next (future) allocation, then create a
second object and print it. The printing function will scan memory starting from
the `->properties` of the object and print every string it encounters up until
the object size is reached. In the case of a zeroed-out memory region, there
will simply be a bunch of empty key-value pairs printed (in the form `"": "",`).
The data sections of (`ld-linux-x86-64.so.2`) contain various pointers,
including pointers to `libc.so.6`. Leaking any of them will suffice.

We can now corrupt the `->next` pointer of an object as explained in point 2
above. However, we need to be careful while doing so: the size of each object is
checked when traversing the linked list, and we necessarily need to overwrite it
to corrupt `->next` as the overflow is linear. Therefore, in addition to
corrupting `->next` with the value we want, we also need perform multiple "set
properties" operations to zero-out the upper bytes of the size using the NUL
string terminator written as the last byte of the properties. After doing this,
the size sanity check will pass and the code will follow the corrupted `->next`
pointer. This reasoning also applies to any zero bytes present in the pointer
itself.

We now have an object with a `->next` set to an arbitrary address. This can be
used as an arbitrary read/write primitive:

- To read, use the "print object" command or the "get object size" command
  specifying the right index.
- To write, first delete all the objects in the linked list before and including
  the corrupted one to set the linked list head to the address we want to write
  to, then use the "set properties" command.

It's important to notice that "set properties" will fail if an object has a size
that is too small and fails to be resized through `realloc()`, and due to the
`realloc()` implementation only the last allocation can be resized. Therefore,
in order for the arbitrary write to work, the corrupted `->next` pointer will
need to point to a non-zero value, which will be interpreted as a size.

Normally, we would overwrite one of the many function pointers present in
glibc's data section or one of the many glibc's GOT entries with a pointer to a
useful function (`system`) or a magic gadget that gives us a shell. However, in
this case, the binary is protected with a `seccomp(2)` filter that only allows
`open`, `openat`, `read`, `write`, `mmap`, `exit` and `exit_group`. We cannot
therefore spawn a shell through `execve()`. We can, however, write arbitrary
values on the stack and make the `main()` function return to execute a ROP
chain.

After leaking libc as explained above, we can now:

1. Corrupt the `->next` of an object to point to libc's `environ`.
2. Leak the value of `environ` using the "get object size" command, which will
   give us the address of the stack of the program.
3. Corrupt the `->next` pointer of the same object again to point to some
   non-zero value on the stack right before the return address of `main()`,
   which sits at a fixed offset from the `environ` pointer.
4. Delete all the objects before and including the corrupted one, so that the
   linked list head now points to the stack.
5. Use the "set properties" command to write an arbitrary ROP chain to the
   stack, being careful to fill zeroes as needed with multiple "set properties"
   commands.
6. Exit the program through the menu to execute our ROP chain.

In the ROP chain, we can simply execute `open()` + `read()` + `write()` to get
the flag.


Complete Exploit
----------------

See [`checker/__main__.py`](./checker/__main__.py) for the complete exploit
script. The checker can be invoked as `python3 -m checker` from this directory
and needs the `libc.so.6` used by the challenge binary, which is taken from
`src/libs/libc.so.6`.


[dl-minimal-malloc]: https://elixir.bootlin.com/glibc/glibc-2.39/source/elf/dl-minimal-malloc.c
