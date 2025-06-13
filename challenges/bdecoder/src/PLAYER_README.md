# Bdecoder

**DISCLAIMER**: This challenge uses a custom QEMU user 9.1.0 build. The provided
`Dockerfile` will automatically build `qemu-aarch64` version 9.1.0 from source
after applying `qemu-9.1.0.patch`. **This patch is out of scope for exploitation
purposes!** It is only provided for transparency and is not intended to
introduce any vulnerability in QEMU. It should be possible to solve the
challenge on both a patched and unpatched `qemu-aarch64` 9.1.0 regardless.

If you wish to use the exact same QEMU binary locally, you can extract it after
building and starting the container:

```sh
docker compose up -d --build
docker cp bdecoder:/usr/local/bin/qemu-aarch64 .
env -i PATH=/usr/local/bin:/usr/bin:/bin ./qemu-aarch64 ./bdecoder
```

## Debugging

To enable debugging for the challenge running under `qemu-aarch64` inside the
Docker container, uncomment all the commented lines in `docker-compose.yml` and
restart with `docker compose up -d`.

Once started, connect to the challenge and QEMU will wait for a debugger on port
1234 before running the binary. To connect to QEMU's GDB server you can then run
`gdb-multiarch` *inside the container* like this:

```sh
docker compose exec chall bash
# Now you have a shell in the container
gdb-multiarch -ex 'target remote :1234' -ex 'file bdecoder'
```

You can also try from outside the container, if you wish. YMMV.

Use only one connection at a time when debugging. Multiple QEMU instances won't
be able to listen on the same debug port at the same time.
