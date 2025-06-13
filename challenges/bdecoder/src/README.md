Bdecoder
========

A realistic take on PAC bypass: reusing a PAC-signed saved return address
*as is* to make another function called at the exact same stack depth return to
the wrong address and with a corrupted stack frame.


Custom QEMU build
-----------------

QEMU's PAC implementation seems to only use 8 bits for PAC signatures in the top
VA bits of signed pointers (excluding MSB if TBI is ON). Such a small value
makes the challenge prone to simple brute-force solutions.

A small patch [`qemu-9.1.0.patch`](./qemu-9.1.0.patch) is provided to build a
custom QEMU version that produces 32-bit PAC signatures using the top 4 bytes of
signed pointers, making things less prone to bruteforce. Of course, this custom
build can only run very specific binaries (where PAC-enabled functions do not
use addresses higher than 4GiB).


Building
--------

Simply run `make` to create `build/bdecoder`, the binary for the challenge. You
will need an AArch64 compiler. Set `CC=` appropriately when running `make`. By
default `CC=aarch64-linux-gnu-gcc`.

Run `make archive` to generate the `bdecoder.tar.gz` archive to distribute to
players.

The custom QEMU is automatically built by the Docker container using the
provided [`Dockerfile`](./Dockerfile).


Running
-------

Run in Docker with `docker compose up -d`.


Exploit
-------

See [`../checker/__main__.py`](../checker/__main__.py) for the complete exploit.
