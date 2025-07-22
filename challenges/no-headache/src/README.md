No Headache
===========

This is a Linux x86-64 custom heap pwnable challenge with bug inspired by
CVE-2023-4911. It consists of an interactive CLI program written in C that
manages heap allocations using the "minimal malloc" heap implementation of glibc
ld.so.


Building
--------

Use `make` to build the final challenge binary at `build/no-headache`.

Use `make archive` to build the `no-headache.tar.gz` archive to distribute to
players.


Running
-------

After building, run with `docker compose up -d` from this directory. The
[`docker-compose.yml`](./docker-compose.yml) file uses
[cybersecnatlab/challenge-jail](https://hub.docker.com/r/cybersecnatlab/challenge-jail)
as base image and runs the challenge in a forking server, using the glibc loader
and libc SO in [`libs/`](./libs/).
