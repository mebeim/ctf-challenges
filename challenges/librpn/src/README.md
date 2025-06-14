librpn
======

This is a x86-64 pwnable challenge with a medium difficulty level target. It
consists of an interactive Python script ([`calculator.py`](./calculator.py))
that provides a CLI for a calculator, and a native C library
([`librpn.c`](./librpn.c)) invoked by the script via ctypes C FFI to evaluate
mathematical expressions. The expressions are parsed by the Python front-end and
transformed into Reverse Polish Notation (RPN), then evaluated by librpn.


Building
--------

Use `make` to build `librpn.so`. You will need `musl-gcc` for this, as the
challenge should run in an Alpine Linux system.

Use `make archive` to build the `librpn.tar.gz` archive to distribute to the
players. The archive's contents should look like this:

```none
$ tar tf librpn.tar.gz
librpn/
librpn/librpn/
librpn/librpn/librpn.so
librpn/calculator.py
librpn/docker-compose.yml
```

*Note: the flag in `docker-compose.yml` is automatically redacted when building
the archive.*


Running
-------

After building, run with `docker compose up -d` from this directory. The
[`docker-compose.yml`](./docker-compose.yml) file uses
[cybersecnatlab/challenge-jail](https://hub.docker.com/r/cybersecnatlab/challenge-jail)
as base image and runs the challenge in a forking server with a 30s
per-connection timeout.


Exploit
-------

See complete exploit script in [`../expl.py`](../expl.py).
