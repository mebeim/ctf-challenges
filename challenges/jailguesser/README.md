Jailguesser
===========

| Release date    | Event                  | Event kind | Category          | Solve stats |
|:----------------|:-----------------------|:-----------|:------------------|:------------|
| October 9, 2024 | ECSC 2024 Jeopardy CTF | Jeopardy   | misc, programming | 1/37        |

> Wanna play a guessing game?
>
> ```sh
> nc jailguesser.challs.jeopardy.ecsc2024.it 47019
> ```


Overview
--------

This is a system programming challenge disguised as a "guessing" game where the
user must submit an executable program able to correctly guess (detect) the
randomized [NsJail][nsjail] configuration under which it is being run.

The [`jailguesser.py`](./src/jailguesser.py) script is launched for each
connection to the challenge and asks for Base64-encoded data as input. The data
is then written to a file that is marked executable and is mounted and executed
inside a NsJail jail:

```python
    p = Popen((
        'nsjail',
        '--really_quiet',
        '--config', cfg, # randomized config here
        '--bindmount_ro', f'{exe}:/jail/exe',
        '--',
        '/jail/exe'
    ), text=True, stdin=PIPE, stdout=PIPE, stderr=stderr_file, bufsize=1 << 20)
```

The provided program is run 32 times in a row. Each time, it needs to first read
some random input string from standard input and output it to standard output as
is. Then it needs to output the exact NsJail configuration being used. If this
is correctly done for all 32 runs, the challenge flag is given as a reward.

A `RandNSJailConfig()` class is responsible for generating the config, where the
following things are randomized:

- Hostname set inside the jail.
- UID/GID under which the program runs inside the jail.
- Personality bits (see [`man 2 personality`][man-personality]), particularly
  only `ADDR_COMPAT_LAYOUT` and `ADDR_NO_RANDOMIZE`.
- The seccomp BPF filter under which the program runs.

The randomized seccomp filter is configured through the NsJail `seccomp_string`
config option, which accepts the policy language defined by [Kafel][kafel]. This
is the annoying part of the challenge.

The Kafel seccomp policy string defines:

- A default action of `ERRNO(ENOSYS)`, meaning that any syscall for which an
  action is not explicitly defined will fail with `-ENOSYS`.
- A base set of syscalls that are always allowed. This includes `clone()`, but
  only to start threads, not child processes (`CLONE_THREAD` must be set).
- One of `read`, `readv`, `vmsplice`, or all the `io_xxx` AIO syscalls is
  allowed for reading.
- One of `write`, `writev`, `vmsplice`, or all the `io_xxx` AIO syscalls is
  allowed for writing.
- Some syscalls (randomly chosen from an "optional" set) with actions that can
  be any of:
  - `ALLOW`: allow the syscall normally.
  - `ERRNO(x)`: make the syscall return a (randomized) value of `-x` (between
    `-4095` and `-150`).
  - `TRAP(x)`: deliver a `SIGSYS` signal with a (randomized) `si_errno` value of
    `x` (between `150` and `4095`).
  - `KILL`: kill the calling thread.


Solution
--------

The first thing that needs to be done is detecting which syscalls are available
and which aren't. This can be done using the `syscall()` libc function called
with bogus arguments (e.g. `syscall(nr, 0, 0, 0, 0, 0, 0)`).

The problem is that executing a syscall can also kill the calling thread, so
each test must be done in a new thread spawned via `clone()`. Cloning can be
either done by hand with `clone()` plus `futex()` to wait, or more easily with
`pthread_create()` and `pthread_join()`. Furthermore, the binary needs to be
compiled statically as linking dynamically will invoke the dynamic loader at
runtime, which will try reading configuration and library files, failing if
`read` is not allowed.

The strategy to detect the syscalls is then as follows.

1. Set up a signal handler to catch `SIGSYS`.
2. For each syscall to test, start a thread (`clone` or `pthread_crate()`).
3. In the child thread, perform the syscall and check what happened upon return:
   - If the `SIGSYS` signal handler was already called then the chosen action
     was `TRAP(x)`. The signal handler can detect `x` through `si_errno` and
     save it in a global variable.
   - If the returned `errno` is larger than `150` then the chosen action was
     `ERRNO(x)` where `x == errno`.
   - If the `errno` is smaller (e.g. `EFAULT`) the chosen action was `ALLOW` and
     the syscall simply failed (makes sense as we pass all zeroes as
     parameters).
4. In the main thread, wait for the child thread (`futex` or `pthread_join()`).
   If the child thread did not already detect any action for the syscall
   currently being tested, then it must have been killed, meaning that the
   chosen action was `KILL`.

After this is done, it's just a matter of programming:

- A generic read can be implemented by choosing one of `read`, `readv`,
  `vmsplice`, or the AIO syscalls `io_xxx` depending on which syscall was
  detected as allowed.
- A generic write can be implemented likewise.
- The current UID/GID cannot be detected with any of the `get*id` family of
  syscalls as none of them is allowed, but can be detected either via
  [`getauxval()`][man-getauxval] (`AT_EUID` and `AT_EGID`) or via a
  [`stat`][man-stat] syscall on `/jail/exe` itself.
- The personality bits `ADDR_COMPAT_LAYOUT` and `ADDR_NO_RANDOMIZE` cannot be
  detected via the `personality` syscall, but can be detected by looking at the
  memory layout with a few calls to `mmap()` and `malloc()`.

A funny note on [`vmsplice`][man-vmsplice]: this syscall only works on *pipes*,
so running `nsjail` locally for testing (without `jailguesser.py`) it's
impossible to use it to read/write because `stdin` and `stdout` point to the
TTY. It works using `jailguesser.py` because [`Popen()`][py-popen] creates a
pipe for `stdin` and `stdout` of the child process.


Solver
-------

See [`solver/solve.c`](solver/solve.c) for the complete solver C program and
[`checker/__main__.py`](checker/__main__.py) for the automated solution script
that uploads the compiled executable to the challenge remote to get the flag.

[nsjail]: https://github.com/google/nsjail
[kafel]: https://github.com/google/kafel
[man-personality]: https://manned.org/man/personality
[man-getauxval]: https://manned.org/man/getauxval
[man-stat]: https://manned.org/man/stat.2
[man-vmsplice]: https://manned.org/man/vmsplice
[py-popen]: https://docs.python.org/3/library/subprocess.html#subprocess.Popen
