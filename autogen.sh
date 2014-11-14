#!/bin/sh
libtoolize -c -i --quiet
autoreconf -i --force
#libtoolize -c -i --quiet --no-warn && automake --add-missing --copy && autoreconf --install

