BigMistake
==========

This is a x86-64 Linux glibc pwnable challenge with a easy/medium difficulty
level target. It consists of a C++ CLI calculator with support for integers of
arbitrary size (BigInt).


Building
--------

Use `make` to build the challenge, the result will be at `build/BigMistake`.

Use `make archive` to build the `BigMistake.tar.gz` archive to distribute to
players. *Note: the flag in `docker-compose.yml` is automatically redacted when
building the archive.*


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
