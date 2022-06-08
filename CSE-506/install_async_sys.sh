#!/bin/sh
set -x
make clean
make
rmmod async_sys
insmod async_sys.ko
