#!/bin/sh
set -eu

# Build-only gate for a Linux worker with nsjail's documented protobuf/libnl
# dependencies. No binary is launched and no namespace, TUN, or network setup
# is performed by this script.
make -j2 nstun/nstun.o net.o subproc.o
