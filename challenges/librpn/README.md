librpn
======

| Release date  | Event                          | Event kind           | Category | Solve stats |
|:--------------|:-------------------------------|:---------------------|:---------|:------------|
| June 14, 2025 | ICC Team Europe Qualifier 2025 | Jeopardy, individual | pwn      | ?/??        |

> Since Python is known to be very slow, I'm in the process of converting my
> CLI calculator into a native C library. I'm halfway there, and so far it looks
> pretty solid. I'm hosting the current version here in case you want to play
> with it:
>
> `nc 10.128.16.1 25193`


Description
-----------

The two main components of the challenge are:

- **[`calculator.py`](./src/calculator.py)**: A Python 3 script that implements
  a simple command-line interface for a calculator, accepting mathematical
  formulas with common infix oprators (`+`, `-`, `*`, `/`, `%`), parentheses
  (`(`, `)`) and support for function calls (`fn(...)`).

  This script is manages user input/ouput, parsing and validating expressions
  taken from standard input (one per line). Input is passed through a simple
  tokenizer, which instantiates Python classes for each token. Tokens are then
  parsed using the [shunting yard algorithm][wiki-shunting-yard] to convert
  expressions from infix notation into [reverse Polish notation][wiki-rpn] (RPN)
  and then forwarded as strings to a native `librpn.so` C library (via
  [`ctypes`][py-ctypes] FFI) for evaluation.

- **`librpn.so`** ([`librpn.c`](./src/librpn.c)): A simple library that only
  exposes two functions:

  - `eval_expression()`: computes the value of a RPN expression, yielding a
    64-bit signed integer as result.
  - `create_function()`: parses a function definition given by a function name,
    a list of parameter names and a RPN expression and remembers it for later
    use in an expression.

The calculator accepts two kinds of statements as input (one per line):

- Function definitions: functions can be defined via the `fn` keyword (which is
  also the only accepted special keyword).

  ```none
  > fn foo(a, b, c) { a * (b + c) }
  ```

- Simple expressions: any statement that does not start with `fn` is treated as
  an expression.

  ```none
  > (1 + 2) / 3 * 100 - foo(4, 5, (3 + 3))
  -38
  ```

Statements are tokenized into 5 main kinds of tokens:

- `Keyword`: only `fn`
- `Op` for `+`, `-`, `*`, `/`, `%`
- `Delimiter` for `(`, `)`, `{`, `}`, `,`
- `Number` for sequences of ASCII decimal digits
- `Name` for sequences of ASCII letters

Furthermore, any `Name` token will become either a `Parameter` or a `Function`
token at parsing time, depending on the context. Names that appear in bare
expressions become `Function` and are treated as function names to invoke
functions, while names that appear in expressions inside function definitions
become `Parameter` and are treated as parameter names (they will be transformed
into actual values only at function evaluation time).

After parsing, the Python frontend passes the tokens in RPN order as C strings
to librpn for evaluation. Within librpn, numeric tokens are recognized checking
whether the first character is an ASCII decimal digit, and are converted to
64-bit signed integers via `strtoll()`.

RPN expressions are evaluated by librpn using a simple stack based machine:

- Numeric values are recognized checking whether the first character is an ASCII
  decimal digit, then converted to 64-bit signed integers via `strtoll()` and
  pushed on the stack.
- Operators pop the top two values from the stack and push one value: the result
  of the operation.
- Functions pop as many values as the number of parameters needed and push one
  value: the result of the expression associated with the function.
- Anything that is not recognized as a numeric value or an operator is
  considered either a function name (when evaluating an expression) or a
  parameter name (when evaluating a function within an expression).

> [!NOTE]
> **Author's note**: the `%` operator is (mistakenly) not implemented in librpn
> and thus ends up being parsed as a 64-bit integer via `strtoll()`, becoming a
> zero value. This is unintended, but doesn't affect the challenge.


Bug
---

As said above, RPN expression evaluation in librpn is implemented via a stack
based machine. The `eval_expression()` function allocates the initial value
stack via `calloc()` and does the appropriate bound checking on any operation to
avoid reading or writing values out of bounds. If the stack grows too big, it is
enlarged via `calloc()` plus `free()`.

When it comes to functions however, the stack is pre-allocated by
`create_function()` at function creation time, and its size is calculated based
on the tokens in the function expression, emulating their behavior and keeping
track of the maximum stack size needed. Here's the relevant snippet of code
decompiled by IDA Free 8.4 after bit of reversing:

```c
stack_size = 0LL;
max_stack_size = 0LL;
for ( j = 0LL; j < fn->expr_len; ++j )
{
  v7 = (char *)expr[j];
  if ( *v7 - (unsigned int)'0' > 9 )
  {
    if ( stack_size )
      --stack_size;
  }
  else
  {
    ++stack_size;
  }
  if ( max_stack_size < stack_size )
    max_stack_size = stack_size;
  v4 = &fn->expr[j];
  *v4 = strdup(v7);
  if ( !fn->expr[j] )
    errx(1, "Memory allocation failure");
}
fn->stack = (int64_t *)calloc(max_stack_size, 8uLL);
if ( !fn->stack )
  errx(1, "Memory allocation failure");
```

The stack size calculation is wrong, because it considers `Number` tokens as the
only tokens that can push values on the stack, while in reality `Parameter`
tokens behave the same way. Any `Parameter` token encounteresd is treated like a
binary operator instead, with a net result of decreasing the current stack size
by one. This means that any function defined with an expression that involves
parameters can potentially result in a stack allocation that is too small.

The routine responsible for function evaluation only performs bound checking
when popping values from the function stack, but not when pushing, as it assumes
a large enough stack. This results in a **linear heap buffer overflow** when
pushing values (numbers or parameters) on the function stack when a function is
called during the evaluation of an expression.

For example the expression in the following function definition:

```
> fn foo(a, b) { 1 + (a + b) }
```

Is into RPN and passed to `create_function()` as:

```c
char *expr[] = {"1", "a", "b", "+", "+", NULL};
```

The calculated maximum stack size will be 1 slot (8 bytes). Evaluating an
expression like `foo(1, 2)` will result in OOB writes past the end of the
heap-allocated function stack (3 writes to be precise, because after parameter
values are pushed, the first `+` operator will also write out of bounds).


Solution
--------

*TL;DR: look at the comments in [`./expl.py`](./expl.py) for a quick explanation
of the exploit*.

The heap buffer overflow already provides for a powerful memory corruption
vulnerability, but it cannot be used to leak values from memory, as it only
occurs when *writing* to memory (pushing a number or parameter value).

The memory corruption happens in the heap of the CPython interpreter itself,
which is isolated from the heap used by the interpreter to allocate Python
objects (except for rare cases). Even though we can find references (pointers)
to Python objects in the interpteter heap, we cannot in general easily find the
Python objects themselves. Furthermore, we don't have a lot of control over the
interpreter behavior when it comes to heap allocations, as we cannot allocate
arbitrary Python objects. While corrupting Python objects *might be* a viable
solution, it is not the way to go. Instead, we need to focus on simpler objects
on the interpreter heap, like the ones allocated by librpn.

### Memory corruption

User-defined functions in librpn are saved in a global linked list and are
represented like this:

```c
struct Function {
    struct Function *next;
    char *name;
    int64_t *stack;
    size_t n_params;
    char **param_names;
    size_t expr_len;
    char **expr;
};

static struct Function *functions = NULL;
```

The program is running in an Alpine Linux system, which uses [musl libc][musl],
whose heap implementation (mallocng) is simple enough (much simpler than glibc)
and groups allocations by size in slab style.

With the help of a debugger like GDB we can check where the `struct Function`
and the `->stack` of each defined function end up in the heap by inserting a
breakpoint in the right place:

```none
pwndbg> b *($base("librpn") + 0x14a0)
pwndbg> command
        printf "%s: %p, stack: %p\n", *(char**)($rax + 8), $rax, $rdx
        end
```

Defining a few identical dummy functions we can see that the allocations can
become at times very predictable, with groups of functions close together in
memory. Creating functions with a stack that is roughly the same size as the
`struct Function` itself gives a very high chance to get *both* allocations
close together:

```none
a: 0x7f114ad96220, stack: 0x7f114ad96260 <--- a->stack right before b
b: 0x7f114ad962a0, stack: 0x7f114ad962e0
c: 0x7f114ad96320, stack: 0x7f114ad96360 <--- c->stack right before a
d: 0x7f114ad963a0, stack: 0x7f114ad96df0
e: 0x7f114ad96e30, stack: 0x7f114ad96e70 <--- e->stack righe before f
f: 0x7f114ad96eb0, stack: 0x7f114ad96ef0
```

Given the above, we can predict the right offset and corrupt the contents of a
`struct Function` by overflowing the `->stack` of another function (assuming the
latter is allocated at a lower address).

The first 3 fields of `struct Function` are:

- `next`: it can either be set to `0` (`NULL`) or point to another function.
- `name`: used when searching in the linked list when a function is invoked; it
  needs to point to a valid NUL-terminated C string.
- `stack`: the function value stack, which has no special constraint and only
  needs to point to RW memory.

### ASLR leak

Controlling the `->stack` pointer of a function gives us an arbitrary write
primitive when the function is evaluated, but we need to know where to point it.

We are operating in the address space of the CPython interpreter. The `python3`
binary itself is compiled as position independent (take notes, Debian and
Ubuntu...) and linked against a few dynamic libraries that are by definition
also position independent. The same goes for `librpn.so`, loaded at runtime via
`ctypes.CDLL()`. Due to ASLR, we do not know any valid virtual address a priori.

There are two main ways to go about leaking some interesting address to defeat
ASLR: either make use of the memory corruption vulnerability we have to corrupt
objects in the right way to obtain a leak, or... take a closer look and see if
we already have one available. Spoiler: yes, we do.

The `calculator.py` script handles runtime exceptions with a couple of
`try...except` blocks in `eval_stmt()`, the seconf of which is:

```py
try:
    res = fn(*args)
except EvalError as e:
    print(f'Eval error in {fn}: {e}') # <=== Interesting!
    return None
```

The interesting line marked above prints the Python function (`fn`) responsible
for an `EvalError` as well as the error string. Here `fn` can be one of
`librpn_create_function()` and `librpn_eval_expression()`, which are Python
wrappers that convert their arguments and invoke `librpn.so` functions. As with
any other Python user-defined object that does not explicitly define its own
`__repr__()` method, the default representation is a string that includes the
name of the object followed by its ID (as returned by the `id()` built-in). This
is interesting because in CPython an object's ID corresponds to *the address of
the object itself*:

```none
>>> def f():
...     return
...
>>> print(f)
<function f at 0x7f732525bd80>
```

Therefore, if we cause an `EvalError` in one of `librpn_create_function()` or
`librpn_eval_expression()`, we will get their address printed out. Looking at
the Python code, `EvalError` is only raised in case the underlying `librpn.so`
functions `create_function()` and `eval_expression()` return error. There are a
few ways to achive this, and they can be identified by looking for places where
these functions return negative error values to the caller.

1. Performing division by zero.
2. Calling a function whose expression references a non-existing parameter.
3. Calling a function without enough parameters.

Any of the above gives us a nice and easy ASLR leak:

```none
> 1/0
Eval error in <function librpn_eval_expression at 0x7fc0e641b240>: Failed to evaluate expression: error -2
> fn foo() {x}
> foo()
Eval error in <function librpn_eval_expression at 0x7fc0e641b240>: Failed to evaluate expression: error -4
> fn bar(a) {1}
> bar()
Eval error in <function librpn_eval_expression at 0x7fc0e641b240>: Failed to evaluate expression: error -5
```

The address we get resides in a RW mapping just before dynamic libraries:

```none
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
    0x55e91fd68000     0x55e91fd69000 r--p     1000      0 /usr/local/bin/python3.12
    0x55e91fd69000     0x55e91fd6a000 r-xp     1000   1000 /usr/local/bin/python3.12
    0x55e91fd6a000     0x55e91fd6b000 r--p     1000   2000 /usr/local/bin/python3.12
    0x55e91fd6b000     0x55e91fd6c000 r--p     1000   2000 /usr/local/bin/python3.12
    0x55e91fd6c000     0x55e91fd6d000 rw-p     1000   3000 /usr/local/bin/python3.12
    0x55e946f3f000     0x55e946f40000 ---p     1000      0 [heap]
    0x55e946f40000     0x55e946f44000 rw-p     4000      0 [heap]
    0x7fc0e61ce000     0x7fc0e62ce000 rw-p   100000      0 [anon_7fc0e61ce]
    0x7fc0e6374000     0x7fc0e6474000 rw-p   100000      0 [anon_7fc0e6374] <<<<<<<<<<<<<< HERE
    0x7fc0e663b000     0x7fc0e663f000 rw-p     4000      0 [anon_7fc0e663b]
    0x7fc0e66b2000     0x7fc0e66b4000 rw-p     2000      0 [anon_7fc0e66b2]
    0x7fc0e66f9000     0x7fc0e66fd000 rw-p     4000      0 [anon_7fc0e66f9]
    0x7fc0e66fe000     0x7fc0e66ff000 r--p     1000      0 /home/user/librpn.so
    0x7fc0e66ff000     0x7fc0e6700000 r-xp     1000   1000 /home/user/librpn.so
    0x7fc0e6700000     0x7fc0e6701000 r--p     1000   2000 /home/user/librpn.so
    0x7fc0e6701000     0x7fc0e6702000 r--p     1000   2000 /home/user/librpn.so
    0x7fc0e6702000     0x7fc0e6703000 rw-p     1000   3000 /home/user/librpn.so
    0x7fc0e6703000     0x7fc0e670d000 rw-p     a000      0 [anon_7fc0e6703]
    0x7fc0e670f000     0x7fc0e6735000 rw-p    26000      0 [anon_7fc0e670f]
    0x7fc0e6735000     0x7fc0e6738000 r--p     3000      0 /usr/local/lib/python3.12/lib-dynload/_struct.cpython-312-x86_64-linux-musl.so
    ...
```

The address itself is going to have a decent amount of entropy due to ASLR, but
its offset from `librpn.so` is quite stable, with only a few bits of randomness.
The offset from `librpn.so` to any other other dynamic library is fixed as they
are mapped contiguously, so this means we know the position of all of them.

### Arbitrary write

Arbitrary write can now be achieved as follows:

1. Cause an `EvalError` to get the ASLR leak.
2. Define a few functions to get a known stable heap layout with a function `X`
   whose stack (`X->stack`) is close to the `struct Function` of another
   `victim` function.

   As previously discussed, allocating functions that have identical definitions
   helps as musl heap is slab-based. To get `struct Function` of `victim` and
   `X->stack` close together we can make sure the calculated stack size for `X`
   is the same as the one of `struct Function`.

3. Call `X` with the right parameters to overwrite `victim->next`,
  `victim->name` and `victim->stack` with arbitrary values. In particular set
   `->next` to `0`, `->name` to the address of a known C string, and `->stack`
   to the address where we want to write.

4. Call the victim function to write on its `->stack` (which now points where we
   want).

In order for point 3 to succeed, the X function can be defined using an
expression that when converted to RPN will cause the parameters to be pushed
last (so that the stack size calculation will be wrong). This is trivial to do:

```none
fn X(a,b,c) {0+(0+(0+(0+(0+(0+(0+(a+(b+(c+z)))))))))}
```

This function will have a stack size of 7 slots, but at runtime 10 values will
be pushed (7 zeroes plus the parameters). The stack size will be 7*8 = 56,
exactly the same as the size of `struct Function`. As a bonus, the `z` at the
end of the expression references a non-existing parameter, which will make
librpn bail out early without actually computing the sums on the function stack
(doing actual math is boring) keeping the pushed parameter values unchanged.

Likewise, the victim function can also be defined with one parameter,
referencing it in its expression so that it will be written via in its corrupted
`->stack` pointer later. Something trivial like `fn victim(a) {a}` will suffice.
Alternatively, even a "hardcoded" static value should work (without parameters).

The last small quirk to consider is the fact `calculator.py` keeps track of the
names of defined functions and ensures that function names referenced in
expressions are known. In order to successfully call the victim function after
corrupting it, its new `->name` must be already known. This is easy to satisfy
by simply creating a function with the name we need first.

After calling `X` to corrupt `victim` pointing `victim->stack` where we want, we
can then call `victim` *using its new name* and trigger the arbitrary write.

### Code execution

The `python3` ELF and all the dynamic libraries it loads are compiled with full
RELRO, so their Global Offset Tables are all read-only. However, `librpn.so` is
not. We can target the GOT entry for `free` in `librpn.so`, which is then called
to free the stack allocated by `eval_expression()` after evaluation is done.
Overwriting librpn's GOT entry for `free` with the address of `system` will give
us `system(controlled_stack)` at the end of `eval_expression()`. We can either
use the actual `system` symbol from `ld-musl-x86_64.so.1` or one of the PLT
stubs for it in other dynamic libraries, e.g. libpython.

Setting aside some heap grooming setup that should be straighforward, assuming
we get `X->stack` to sit right before the `struct Function` of `victim`, all we
need for code execution is something like this:

```none
> fn new_name() {1}
> fn X(a,b,c) {0+(0+(0+(0+(0+(0+(0+(a+(b+(c+z)))))))))}
> fn victim(a) {a}
> X(0, new_name_ptr, librpn_free@GOT)
> <64bit_value> + new_name(system)
```

And we'll get `system("<64bit_value>")`.


Complete exploit
----------------

See [`expl.py`](./expl.py) for the complete exploit script.


[musl]: https://www.musl-libc.org/
[py-ctypes]: https://docs.python.org/3/library/ctypes.html
[wiki-rpn]: https://en.wikipedia.org/wiki/Reverse_Polish_notation
[wiki-shunting-yard]: https://en.wikipedia.org/wiki/Shunting_yard_algorithm
