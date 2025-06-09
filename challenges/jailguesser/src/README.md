Jailguesser
===========

A system programming challenge disguised as a "guessing" game where the user
must submit a program that can correctly guess (detect) and output the
randomized [NsJail](https://github.com/google/nsjail) configuration under which
it is being run.


Building
--------

The challenge itself is source-only and no build step is necessary.

Run `make` to generate the `jailguesser.tar.gz` archive to distribute to
players.


Running
-------

Run in Docker with `docker compose up -d`.


Solution
--------

See [`../solver/solve.c`](../solver/solve.c) for the complete solver C program
and [`../checker/__main__.py`](checker/__main__.py) for the automated solution
script that uploads the compiled executable to the challenge remote to get the
flag.
