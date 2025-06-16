BigMistake
==========

| Release date  | Event                                        | Event kind           | Category | Solve stats |
|:--------------|:---------------------------------------------|:---------------------|:---------|:------------|
| June 7, 2025  | [ECSC Team Italy][team-italy] Qualifier 2025 | Jeopardy, individual | pwn      | 5/182+      |

[team-italy]: https://teamitaly.eu/

> Did you know that to correctly sum 64-bit integers you need 65 bits? That always
> annoyed me. That's why I am building a CLI calculator that can sum integers of
> arbitrary size! Wanna try it out? Here's a beta version I have been working on.
>
> `nc bigmistake.challs.quals.teamitaly.eu 38072`


Desctiption
-----------

We are dealing with a simple CLI calculator with support for signed integers of
arbitrary size, written in C++11 and compiled for x86-64 Linux. The ELF
executable is compiled with most modern exploit mitigations enabled (NX, PIE,
full RELRO, stack canaries) and linked against GNU glibc and libstdc++. It is
however compiled without optimizations and with symbols and DWARF debug info.
This makes reverse-engineering its functionality easier than usual for a C++
binary.

Numbers are parsed and handled via a `BigInt` class that can manage signed
integers of arbitrary size. This class only holds two private fields (see
[`BigInt.h`](src/src/BigInt.h)): a `sign_` to hold the integer sign and a
`data_` vector of unsigned 64-bit integers to hold the absolute value of the
integer:

```cpp
class BigInt {
    int sign_;
    std::vector<uint64_t> data_;
}
```

For simplicity, the class constructor that takes a `std::string` only accepts
hexadecimal digits with an optional leading sign (`+` or `-`) and converts them
into integers **60** bits (15 hex digits) at a time, storing their values into
the `data_` vector in little-endian form (the 60 most significant bits are at
the end of the vector).

The calculator functionality is implemented via a `Calculator` class that is
responsible for parsing and evaluating statements taken from the program's
`main()` one line of input at a time.

Two kinds of statements are accepted:

- Expressions: simple mathematical expressions in infix notation consisting of
  numbers in hexadecimal, variable names, and only two operators: `+` and `-`.
- Variable assignments: statements of the form `varname OP expression`, where
  `OP` can be one of `=`, `+=`, or `-=`. The expression is evaluated and
  associated with the specified variable name. In the case of `+=` or `-=` the
  expression result is added or subtracted from the variable if it already
  exists.

Example of interaction:

```none
> x = aaaaaaaaaaaaaaaaaaaaaaaaaaa
> x + 112233440000000011223344
aaabbccddeeaaaaaaaabbccddee
> x + 1234 - 1000
aaaaaaaaaaaaaaaaaaaaaaaacde
```

### Inner Workings of The Calculator

A `Calculator` class, whose only instance is in the `main()` function, holds one
internal `unordered_map` field to store values associated with variables, with
variable names (strings) as keys and raw `BigInt *` pointers as values. It also
implements 3 private and one public methods:

```cpp
class Calculator {
    std::unordered_map<std::string,BigInt *> vars_;

    bool eval_one(const std::string &v, BigInt *&out) const;
    BigInt *eval_expr(const std::deque<std::string> &expr) const;
    void eval_assign(std::deque<std::string> &stmt);
public:
    BigInt *eval(const std::string &stmt);
};
```

The `eval()` method takes a `std::string` statement as input and splits it on
ASCII spaces into a `std::deque<std::string>`, which is then parsed. Depending
on the value of the second element, either `eval_assign()` or `eval_expr()` are
invoked. The result is either a `nullptr` for assignments or a `BigInt *`
pointer to a dynamically allocated `BigInt` for expressions.

All operations on `BigInt` values are performed using public operator methods
implemented by the `BigInt` class. Most notably `Bigint::operator+(other)` and
`BigInt::operator-(other)` implement addition and subtraction: these two
operators always return a new `BigInt` instance.

Assignment (`BigInt::operator=(other)`) is not explicitly implemented as the the
default C++ implicit assignment operator works just fine, while compound
assignment operators `BigInt::operator+=(other)` and `BigInt::operator-=(other)`
implement in-place addition and subtraction modifying the LHS `BigInt` instance
itself.

In `Calculator::eval_assign()`, the variable name is extracted and looked up in
the `vars_` map. If not present, a `BigInt` is dynamically allocated via `new`
and default-constructed to have a value of `0`. A pointer to it is then inserted
into `vars_`. The right-hand side of the statement is parsed via
`Calculator::eval_expr()` like a normal expression and then used to modify the
`BigInt` that was just retrieved or allocated via `=`/`+=`/`-=`.

In `Calculator::eval_expr()` the input `std::deque` of strings is parsed two
elements at a time as it is expected to be of the form `val OP val OP ...`. Each
value is parsed via `Calculator::eval_one()`, performs a lookup into the `vars_`
map, returning a pointer to an existing `BigInt` (if present) or to a newly
dynamically allocated one, constructed parsing the value. Addition/subtraction
is then performed (depending on the encountered operators) via
`BigInt::operator+(other)` or `BigInt::operator-(other)`. After evaluating the
whole expression, a `BigInt *` pointer to the result is returned.

The `main()` program simply calls `std::getline()` and `Calculator::eval(line)`
in a loop displaying the resulting `BigInt` (if any) to standard output
with `std::cout::operator<<` (implemented as a `friend` method by `BigInt`.


Bug
---

There are a few different bugs in the program, of which only one represents an
actual vulnerability.

The `Calculator::eval_one()` method returns a `BigInt *` (via the `BigInt *&out`
reference parameter) that can either be the result of a new allocation or a
pointer to an existing variable value taken directly from the internal `vars_`
map. To inform the caller of the difference, `eval_one()` returns `true` if the
returned pointer represents an existing variable or `false` if it's just a
temporary value that can be safely freed later.

The `Calculator::eval_expr()` partially takes this information into account,
freeing returned values only if needed while iterating through the expression.
However, *in case the expression only consists of a single element*, no check is
performed on the return value of `eval_one()` and the `BigInt *` pointer is
returned as is.

The `Calculator::eval()` method always returns the `BigInt *` pointer obtained
from `eval_expr()` as is. This pointer is then always deleted in `main()`
freeing the underlying `BigInt` object. In the case of a temporary expression
results, this is fine. However, in the case of existing variables, this is
wrong. The deleted pointer still exists in the `vars_` map, and this can easily
lead to Use-After-Free if the same variable is requested again in a future
expression.

Other insignificant bugs include:

- Ignoring operators that are not `+` or `-` in `Calculator::eval_expr()`
  instead of bailing out, resulting in broken expressions like
  `1 . 2 asd 3 xxx 4` with unexpected resulting values.
- Leaking memory in `Calculator::eval_assign()` due to the RHS of the assignment
  returned by `eval_expr()` never being freed.


Solution
--------

We are dealing with a UAF on a `BigInt` class that includes a `std::vector`
field. If corrupted, a `std::vector` can provide a very powerful arbitrary
read/write primitive. First, though, we need a leak to defeat ASLR.

### Leaking a Heap Address

To leak a heap address, we can allocate a bunch `BigInt` objects defining some
variables, then request the variables again with a bunch of single-element
expressions to free the underlying `BigInt` and fill tcache. Once tcache is
filled, we can free some more (at least two) to get them into a fastbin and have
heap pointers on the heap. Heap addresses will then appear inside the backing
store of one of the freed `std::vector` objects. If we request the right
variable we will get a heap pointer nicely printed out for us.

### Leaking a Libc Address

To have a libc address on the heap, we can define a variable with a large value
(at least `0x400` hex digits) to force consolidation of existing fastbin chunks,
move them into the unsorted bin and subsequently into other bins like smallbin
depending on the size. This will put the address of glibc's `main_arena` on the
heap. We can then use the same strategy we used for the heap leak.

Alternatively, now that we know where the heap is located, we can also first
build an arbitrary read/write primitive via UAF on a corrupted `BigInt` (see
below), and then use it to read the `main_arena` pointer.

### Arbitrary Read/Write

To achieve arbitrary r/w, we can reclaim a `BigInt` object (32 bytes) from
tcache with the backing store of a `std::vector` for a new variable of the right
size (at least 181 bits i.e. 46 hex digits). This will lead to the following
situation:

```none
New BigInt                 Victim BigInt
o-----------------o     -->o-----------------o
| sign_           |    /   | sign_           |
| data_.start     |---'    | data_.start     |
| data_.end       |---.    | data_.end       |
| data_.alloc_end |----\   | data_.alloc_end |
o-----------------o     -->o-----------------o
```

The `start`, `end` and `alloc_end` are private fields of `std::vector` (the
internal libstdc++ field names are `_M_impl._M_start`, `_M_impl._M_finish` and
`_M_impl._M_end_of_storage`). They are all pointers: `start` points to the first
element in the backing store, `end` points one past the last one, and
`alloc_end` points one past the last available allocated slot (it is equal to
`end` when the vector is full). If we control their value, then we can
read/write to arbitrary addresses via UAF on the victim variable (whose `BigInt
*` is still in the `vars_` map).

Given that only 60 bits are stored in each `int64_t` of the `data_` vector, some
helper functions to make the conversion easier are needed:

```python
def to_bigint(data: list[int]) -> int:
    value = 0
    shift = 0

    for v in data:
        # Top nibble will be lost
        assert v < (1 << 60)
        value |= v << shift
        shift += 60

    return value


def fake_bigint(data_ptr: int, size: int) -> int:
    return to_bigint([1, data_ptr, data_ptr + size, data_ptr + size])
```

We can now reclaim a previously freed `BigInt` from tcache and fully control its
internal fields with a crafted value:

```python
value = fake_bigint(ADDR, SIZE)
r.sendlineafter(b'> ', f'pwn = {value:x}')
```

```none
pwn BigInt                 Victim BigInt
o-----------------o     -->o-------------------------------o
| sign_ = 1       |    /   | sign_ = 1                     |
| data_.start     |---'    | data_.start     = ADDR        |
| data_.end       |---.    | data_.end       = ADDR + SIZE |
| data_.alloc_end |----\   | data_.alloc_end = ADDR + SIZE |
o-----------------o     -->o-------------------------------o
```

After discovering the name of the corresponding victim variable, we can:

- Read SIZE bytes from ADDR using the victim variable name in an expression. The
  expression must contain more than one element (e.g. `victim + 0`) as
  referencing `victim` alone would double-free the `BigInt` and most likely
  crash the program due to glibc heap sanity checks.
- Write up to SIZE bytes to ADDR easily via `+=` or `-=`. We can also use simple
  `+` and `-` but need to be careful about the implicit object copies.

Similarly, to move around the vector pointers of the victim variable, changing
ADDR and SIZE, we can operate on `pwn` with the `+=` and `-=` operators. We just
need to take care when constructing values to add or subtract, because if we add
or subtract too much, the backing store for the `data_` vector of `pwn` will
increase or decrease in size. To remedy this, we can always first read the
victim's value, then calculate the amount to add or subtract as needed.

### Arbitrary Code Execution

Now that we have achieved ARW, scoring an ACE should be trivial:

- Read `environ` from libc to get the location of the stack.
- Calculate `main()`'s return address location on the stack.
- Write a ROP chain on the stack starting from `main()`'s return address.
- Make the calculator error out with an invalid value to trigger a return from
  `main()`.


Complete Exploit
----------------

See [`expl.py`](./expl.py) for the final automated exploit script.
