#!/bin/bash

set -e

if id -nG "$USER" | grep -qw docker; then
	MAYBE_SUDO=
else
	MAYBE_SUDO=sudo
fi

$MAYBE_SUDO docker build -f Dockerfile.tester -t tester .
$MAYBE_SUDO docker run --rm -it tester
