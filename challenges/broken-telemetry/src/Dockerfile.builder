FROM alpine:3.22.2@sha256:4b7ce07002c69e8f3d704a9c5d6fd3053be500b7f1c69fc0d80990c2ad8dd412 AS builder

RUN apk add --no-cache gcc make musl-dev openssl-dev py3-pip
RUN pip3 install --break-system-packages cryptography~=46.0.2

WORKDIR /app

COPY src /app/src
COPY Makefile genkey.py /app/
RUN make -j


FROM scratch AS out
COPY --from=builder /app/build/* /
