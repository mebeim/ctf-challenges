Cosmic Ray
==========

This is a x86-64 pwnable challenge with a medium difficulty level target. It
consists of a Python application running through the [PyPy](https://pypy.org/)
interpreter, which is known for its runtime JIT capability.

The application itself provides a simple CLI to create and execute Python
lambdas consisting of simple expressions involving integers. The goal of the
challenge is to exploit a single memory bit flip (functionality explicitly
provided by the program) to achieve arbitrary code execution.


Building
--------

The challenge itself is source-only and no build step is necessary. The Docker
container to run the challenge can be built with `docker compose build`.

Run `make` to generate the `cosmic-ray.tar.gz` archive to distribute to players.

*Note: the flag in `Dockerfile` is automatically redacted when building the
archive with `make`.*


Running
-------

Run with Docker compose: `docker compose up -d`.


Exploit
-------

See [`../expl.py`](../expl.py) for complete exploit script.
