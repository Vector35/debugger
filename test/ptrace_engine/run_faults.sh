#!/bin/bash
set -e
cd /work
gcc -O0 -no-pie -fno-omit-frame-pointer -o progs progs.c -pthread -ldl
g++ -std=c++20 -O1 -g -I/src -o fault_driver fault_driver.cpp faultwrap.cpp /src/ptraceengine.cpp /src/ptracearch.cpp \
	-pthread -Wl,--wrap=ptrace -Wl,--wrap=pwrite -Wl,--wrap=open
timeout 30 ./fault_driver
