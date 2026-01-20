#!/bin/bash

set -e

if id -nG "$USER" | grep -qw docker; then
	MAYBE_SUDO=
else
	MAYBE_SUDO=sudo
fi

$MAYBE_SUDO docker build -f Dockerfile.builder --target=out --output=type=local,dest=build .
$MAYBE_SUDO chown -R $USER:$USER build
