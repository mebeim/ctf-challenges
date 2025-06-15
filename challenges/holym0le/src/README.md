[PWN] HolyM0le
==============

This is an x86-64 pwnable challenge written for TempleOS in HolyC.
[TinkerOS](https://github.com/tinkeros/TinkerOS) was chosen as base for the
simplicity of its setup.

The actual source code for the challenge, written in HolyC, is at
[`files/IsoRoot/InstallHome/Challenge.HC`](files/IsoRoot/InstallHome/Challenge.HC)
(the weird amount of intermediate folders is due to the build system requiring
multiple steps to build the final VM disk).

The [`Once.HC`](files/IsoRoot/InstallHome/Once.HC) file in the same directory is
automatically executed on boot by TempleOS: it includes `Challenge.HC` and runs
the `Challenge` function.

The challenge runs inside a QEMU VM and takes input through serial port 1
(COM1). The [`run.py`](./run.py) script (see **Running** section below) can be
used to easily run the challenge as intended.


Building
--------

Build dependencies: the Python modules in `requirements.txt`.

Use `make` to build the challenge and also the final `holym0le.tar.gz` archive
to distribute to players.

The [`build.py`](./build.py) script is responsible for the actual build (see
`./build.py --help` for more info). The final product of the build are **two**
QEMU disks containing the TempleOS bootloader, the OS and its filesystem,
including the challenge files:

- `build/disk.qcow2` will contain the real flag;
- `build/disk-players.qcow2` will contain a redacted flag.

**NOTE** that the timeouts in `build.py` used to wait for some installation
steps are hardcoded and based on my machine. You may have to increase them if
your machine is too slow. Run with `--display` to see the installation progress
and check for yourself.

After building, the files in
[`files/IsoRoot/InstallHome`](files/IsoRoot/InstallHome) will be in the `/Home`
directory of the filesystem, with the `.HC` files compressed to `.HC.Z`.
TempleOS transparently handles compressed/uncompressed files, this is just to
add a little bit of spice making extraction attempts from the final QCOW2 disks
not so trivial.

The files that should be distributed to the players are:

- `build/disk-players.qcow2` renamed to `build/disk.qcow2`
- `Dockerfile`
- `docker-compose.yml`
- `run.py`

And they will be compressed into `holym0le.tar.gz` after building with `make`.


Running
-------

The [`run.py`](./run.py) script can be used to run the challenge through QEMU
(`qemu-system-x86_64`) on the host even without Docker. It accepts a few useful
flags for debugging/performance purposes (see `./run.py --help`). To run using
Docker, simply use `docker compose up -d --build`.


Exploit
-------

The full exploit can be found in [`expl.py`](./expl.py).
