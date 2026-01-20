Broken Telemetry
================

Linux executable implementing a patch-as-a-service functionality that allows
modifying its own code via specific commands signed with a known Ed25519 key.

The challenge is designed to run and to be exploited without interaction, only
with a fixed input provided from standard input to the binary.

Player will need to provide the input that successfully exploits the binary in
order to get the flag back at a later time, as this challenge is meant to run on
a remote machine without user interaction (i.e., a satellite).


Building
--------

Although the challenge can be built with `make`, it is meant to run in an Alpine
Linux system, therefore `Dockerfile.builder` is provided to build in Alpine
(musl libc, gcc etc).

Build the challenge via Docker. Output will be in `build/`. The final executable
is meant to run in an Alpine Linux system.

```sh
docker build -f Dockerfile.builder --target=out --output=type=local,dest=build .
# Adjust permissions if you run Docker as root
sudo chown -R $USER:$USER build
```

After building via Docker, run `make archive` to generate the
`broken-telemetry.tar.gz` to distribute to players. This will include a dummy
key pair and the player Dockerfile to run the challenge within an Alipne
environment.

NOTE that the `Dockerfile.player` is not meant to be buildable as is: only the
one shipped in the player archive will be usable.


Running
-------

The challenge itself is supposed to run inside an Alpine Linux container (hosted
on a satellite). Deployment setup/configuration is not provided here.

You can however run tests (including an exploit test) within Docker as follows:

```sh
docker build -f Dockerfile.tester -t tester .
docker run --rm tester
```


Exploit
-------

The exploit [`expl.bin`](./expl.bin) consists of a static binary blob that
should be fed to the program's standard input.

See the `test_exploit()` function in [`test/test.py`](test/test.py) for a
step-by-step commented version.
