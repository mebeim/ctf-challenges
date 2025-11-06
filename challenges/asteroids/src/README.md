Asteroids
=========

A reverse engineering CTF challenge in the form of a remake of the famous 1979
Atari game, built with [Godot Engine](https://godotengine.org/).

The goal of the game is to complete a series of hidden achievements, whose logic
is implemented in a native C++ GDExtension (`asteroids-gdextension`) distributed
in the form of a shared library along with the game. The achievements perform
various checks during the game and unlock pieces of the flag, which is displayed
at the bottom of the screen.

Main game logic is implemented via GDScripts (`asteroids/scripts`) which are
embedded (almost) plaintext in the final game executable. Game assets (sprites,
audio, etc.) are small enough so they are all contained in this repo
(`asteroids/assets`).

The game can be built for multiple platforms: Linux (x86-64/arm64/riscv64),
Windows, iOS, macOS, Android. The target platform should not make much of a
difference. At the end of the day, the goal is to reverse-engineer the
GDExtension shared library distributed with the game, implementing the
achievements' logic.


Building
--------

I built and tested on Linux Debian 12 targeting Linux and on Ubuntu 24.04
targeting both Linux and Windows, using Godot 4.4 and 4.5. The following build
instructions assume you are also building on Linux (Ubuntu 24) and targeting
either Linux or Windows. If you want to build on another system or for another
target platform... good luck!

### Build Dependencies

You will need:

- Godot 4.5 (download from godotengine.org, it should consist of a single
  self-contained executable).
- Godot export templates (open Godot -> Editor -> Export Templates -> Download
  and Install). Refer to Godot doc for more info.

Additionally (to build `asteroids-gdextension`) you will also need:

- Python 3.7+ (really hope you have this).
- C++ compiler and binutils for the target platform. If building on Linux and
  targeting Windows, you can use mingw-w64 (i.e. `mingw-w64` pkg on Ubuntu 24).
- GNU Make (i.e., `make` pkg on Ubuntu 24).
- [SConstruct](https://scons.org/) (`pip install scons`).

### Building the GDExtension

The `asteroids-gdextension` directory contains the source code for a C++
[GDExtension](https://docs.godotengine.org/en/4.4/tutorials/scripting/gdextension/what_is_gdextension.html),
which is a fancy word for a native shared library linking other native Godot
libs. Build this first, or the game (which specifies it as requirement) won't
even launch in the Godot editor.

Choose `PLATFORM` between `linux` and `windows`. Choose `TARGET` between
`template_debug` (for game launched from within Godot editor) and
`template_release` (for final game build/export).

**To build using Docker** (easier):

```sh
docker build -f Dockerfile.gdextension \
    --target=out --output type=local,dest=asteroids/bin \
    --build-arg PLATFORM=windows --build-arg TARGET=template_release .

# Adjust permissions if you run Docker as root
sudo chown -R $USER:$USER asteroids/bin
```

**To build on the host**:

1. clone the correct branch of the `godot-cpp` repo for this (I hate submodules
   sorry):

   ```sh
   # Here I use 4.5 because I build with Godot 4.5, change as needed
   git clone --depth 1 --single-branch --branch 4.5 https://github.com/godotengine/godot-cpp
   ```

2. Build with `make`:

   ```sh
   cd asteroids-gdextension
   make PLATFORM=windows TARGET=template_release
   ```

   The [`Makefile`](asteroids-gdextension/Makefile) simply invokes `scons` with
   the right platform and template you provide, but it also generates some C++
   files needed for the build first
   ([`asteroids-gdextension/gen_achievements.py`](asteroids-gdextension/gen_achievements.py)).

In any case (Docker build or not), output files (`.so`/`.dll`) will be placed in
`asteroids/bin`, and will then automatically be used by Godot to run (debug) and
export (release) the game.

**NOTE**: if, for whatever reason, the GDExtension build fails with the error
*"sh: Argument list too long"* then you should consider moving this repository
closer to the root of your filesystem. This happens because `godot-cpp` needs to
`ar`-link *a lot* of files and SCons uses absolute paths to do so, which may
exceed the system's maximum argv size limits. Funny.

### Building the Game

The hard part is over. The `asteroids` directory contains a Godot project and
the actual source/assets/etc for the game. You can build the game from
command-line as follows:

```sh
# Note: ../Asteroids here is relative to project path
/path/to/Godot_v4.5-stable_linux.x86_64 --headless \
	--path asteroids \
	--export-release 'Windows Desktop' \
	../Asteroids.exe 
```

Choose either `Windows Desktop` or `Linux` for release type (these are the two
I have configured). For a debug build, use `--export-debug` instead.

To build via Godot editor GUI, open Godot editor and import it, then open the
project. Navigate to "Project" -> "Export..." -> select target (Linux/Windows)
-> "Export Project..." -> choose save location -> "Save". 

In any case, if all goes well, you should now have an `Asteroids.x86_64`
(or `Asteroids.exe`) executable along with a `libachievementmanager.xxx.so`
(or `.dll`) library in this directory.

### Files to Distribute to Players

Players will only need the two final build artifacts: the game executable and
the "libachievementmanager" GDExtension shared library.


Running
-------

After building, the game can simply be run like any other executable. The only
important thing is that the "libachievementmanager" GDExtension shared library
should be present as well in the same directory of the game.


Author's Notes
--------------

Additional tools used:

- Game over win/lose sounds design: https://www.aisongmaker.io/midi-editor
- Sound editing/resampling: https://www.audacityteam.org/
- SVG/PNG design (progress/achievement icon, game icon, special asteroids): https://inkscape.org/

Assets used:

- Asteroid/ship sprites: https://hat-tap.itch.io/asteroids-asset-pack
- Bullet/thruster/explosion sounds: https://classicgaming.cc/classics/asteroids/sounds
- Font: https://github.com/keshikan/DSEG

Helpful Godot docs pages/tutorials:

- GDExtension tutorial: https://docs.godotengine.org/en/4.4/tutorials/scripting/gdextension/what_is_gdextension.html
- Tween animations: https://docs.godotengine.org/en/4.4/classes/class_tween.html
- Shaders (for flag text color/movement): https://docs.godotengine.org/en/stable/tutorials/shaders/your_first_shader/your_first_2d_shader.html

Miscellaneous helpful YouTube tutorials:

- https://www.youtube.com/watch?v=FmIo8iBV1W8
- https://www.youtube.com/watch?v=7IxwZgepCdY
- https://www.youtube.com/watch?v=lWQPT1uk_Vk
- https://www.youtube.com/watch?v=7IxwZgepCdY
- https://www.youtube.com/watch?v=jGI2XQRWdZw
- https://www.youtube.com/watch?v=ZuWUzlb1TmM
