FROM cybersecnatlab/challenge-jail@sha256:c6ca5b83f35e1c3bc63b08db1ceecd8d10e4a1a46d4f24ee45e9f12bdbac990b

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
	apt-get install -y binutils gcc gdb-multiarch make git python3 python3-pip ninja-build pkg-config libglib2.0-dev && \
	apt-get clean

RUN pip3 install tomli

# Get QEMU 9.1.0
WORKDIR /
RUN git clone --depth 1 --single-branch --branch v9.1.0 'https://github.com/qemu/qemu'

# Patch, build and install QEMU
WORKDIR /qemu
RUN --mount=type=bind,source=qemu-9.1.0.patch,target=qemu-9.1.0.patch \
	patch -p1 < qemu-9.1.0.patch

RUN ./configure --target-list=aarch64-linux-user --static --disable-tools \
	--disable-debug-info --disable-slirp --disable-lto --disable-werror \
	--disable-plugins
RUN make -C build -j install
RUN rm -rf /qemu

WORKDIR /home/user
