Broken Telemetry
================

| Release date     | Event                                    | Event kind | Category | Solve stats |
|:-----------------|:-----------------------------------------|:-----------|:---------|:------------|
| November 4, 2025 | [Ctrl+Space CTF][ctrl-space] Finals 2025 | Jeopardy   | pwn      | 3/5         |

[ctrl-space]: https://ctrl-space.gg/

*Co-Authored by: Matteo Porta (@0000matteo0000)*


> Here at the Ker... Ctrl+Space Center, we just launched our latest satellite to
> actual space! The first without any RUD or attacks from the Kraken!
>
> But readings from the Mystery Goo are coming out weird. I wonder if some of it
> leaked into the Probodobodyne's computer core or if Wernher wrote its code with ChatMonolith.
>
> Either way, can you patch it?


Description
-----------

*TL;DR: see the `test_exploit()` in [`src/test/test.py`](src/test/test.py) for a
quick explanation of the exploit*.

The challenge consists of a Linux ELF executable running in a remote Alpine
Linux x86-64 environment. It is compiled with symbols and links libcrypto for
some simple ED25519 signature operations.

The peculiarity of this challenge comes from the fact that it runs remotely and
does not allow interaction session. The input should be provided as a single
blob of data to standard input, and the output collected and sent back all at
once.

The program is a service to query telemetry from a satellite. It takes binary
commands from standard input and provides textual output to standard output. One
peculiarity that stands out immediately by looking at the `main()` function of
the is that the entire logic runs on a separate child thread with a custom,
manually mmapp'd stack frame created at the start of the program. The main
thread simply starts and then waits for the child thread to terminate.

The functionality implemented via commands is as follows:

- A few (6) different commands to retrieve different kinds of telemetry data.
  These consist of a single byte of opcode followed by a 4-byte unsigned integer
  indicating an index for telemetry data reading. The telemetry is stored in a
  file that is indexed by records, and the index is used to extract and print
  data from a specific record.

  The opcodes for these telemetry commands are from `0x00` to `0x05`. Each of
  them extracts different values from the selected record.

  When telemetry data is requested for the first time, a page of data is
  `mmap`'d into memory from file, and the requested index is remembered.
  Subsequent telemetry commands requesting the same index will be serviced via
  the same mapped data, and will not re-open and map the file.

- A "reset" command, consistsing of a sigle `0xff` byte. This command simulates
  a reset by resetting the global variables used to keep track of the mapped
  telemetry data and restarting the target function of the child thread.

- A "patch" command, consistsing of: a `0xfe` byte, a 4-byte offset, a 1-byte
  patch size, a payload and a 64-byte signature.

  This is the most interesting command: it allows patching memory at runtime
  (via `mprotect` RWX + write) with arbitrary data, given that a valid signature
  for the data is given.

  The signature is a 64-byte ED25519 signature, and is verified against a known
  public key. If verification succeeds, the patch is applied to memory.
  Otherwise, it is rejected.

  Verification is done via libcrypto functions such as `EVP_DigestVerify()`, and
  the public key is mapped into memory from file via `mmap`. This is only done
  once, and subsequent patch requests will not re-map the pubkey file.


Bugs
----

Although the design of the whole program is... questionable to say the least,
there is only one real bug in the program:

The "reset" command re-starts the program logic (after resetting global
telemetry-related variables) with a *recursive call*. The entry function of the
child thread simply recursively calls itself to restart. This causes the thread
stack pointer to move up. If this is done too many times, the initial (fixed)
size reserved by `main()` is exceeded and the stack pointer can end up pointing
to unmapped memory or other existing data.


Solution
--------

The file-mapping functionality of the program plays nicely into the exploitation
of the bug. We have:

- The patch functionality, which maps the key to memory via `mmap`
- The telemetry functionality, which maps pages from the telemetry file to
  memory, again via `mmap`.
- The command loop in the child thread function reading data directly on the
  thread stack.
- The recursive call moving the stack (more or less) as much as we want.

By abusing the above operations in the correct order, we can cause the thread
stack to overflow into the mmapped public key in memory and overwrite it with
controlled data.

The exploitation steps are as follows:

1. Map the pubkey above thread stack with a random patch attempt that will fail.
   Additionally, make sure the attempt fails at offset validation before
   invoking libcrypto, so that libcrypto does not map its own stuff into memory
   above the pubkey, to keep offsets stable.

2. Map telemetry pages as cushion right above pubkey issuing a telemetry
   command, so that they act as a cushion for the thread stack to overflow into.

3. Invoke the "reset" command a bunch of times to overflow thread stack and
   point the stack pointer right before pubkey, into telemetry data.

4. Request a new patch overwriting pubkey with patch data. Again, the patch
   does not need to pass signature verification, just overwrite the pubkey.

   Given how data is aligned on the stack, the first two bytes of signature we
   pass will occupy the last two bytes of pubkey, while the first 30 bytes of
   pubkey will be entirely controlled.

5. Now that the pubkey used by the program to verify patches is overwritten,
   move the stack frame up one more time a single "reset" command to avoid
   messing it up.

6. Finally, send a valid patch that passes validation with the crafted public
   key. With the right offset, overwrite a piece of code that will be hit later
   to gain arbitrary code execution.


Complte Exploit
---------------

The exploit at [`src/expl.bin`](src/expl.bin) consists of a static binary blob
that should be fed to the program's standard input.

See the `test_exploit()` function in [`src/test/test.py`](src/test/test.py) for
a step-by-step commented version.
