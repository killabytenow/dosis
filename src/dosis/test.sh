#!/bin/sh

set -x

./dosis -v -c 4         \
        -s 192.168.1.19  \
        -d 192.168.1.122 \
        -D 80 -H 1.0 -l 1 -p 10 -T 10 \
        tcpopen a
