Snek
====

This is a Linux x86-64 pwnable/misc challenge consisting of a simple video game
similar to the famous "Snake" game. The intended solution does not involve
achieving arbitrary code execution, but rather tricking the program into
embedding the flag into the game screen as a texture.

The game is written using [libSDL](https://www.libsdl.org/) and can be played
with keyboard arrows or WASD keys. It also offers functionality to record inputs
saving them to a text file and load previously saved inputs to replay them
automatically.

A game server runs remotely and accepts replay files uploaded via TCP, running
the game in headless mode and sending back a PNG screenshot of the last frame of
the game after the uploaded replay is completed (or game over is reached).


Building
--------

Buil dependencies:

- `libSDL2` and `libSDL2_image` libs and development headers: available on
  Ubuntu/Debian via APT as `libsdl2-dev` and `libsdl2-image-dev`.
- Python 3 `pillow`: `pip install pillow`.

Run `make` to build the challenge executable and the few "texture" files it
needs to run. Build output will be in `game/` along with `game/server.py`
(already present).

Run `make test` to test the exploit (`../expl.py`) against the built challenge
as a sanity check.

Run `make archive` to generate the `snek.tar.gz` archive to distribute to
players. *Note: the archive will contain a redacted flag.*


Running
-------

After building, run with Docker compose: `docker compose up -d`.


Exploit
-------

See [`../expl.py`](../expl.py) for the complete exploit script.
