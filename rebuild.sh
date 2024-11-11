#!/bin/bash

./kill.sh
rm -rf ./build
meson build --prefix=`pwd`/install
ninja -C build