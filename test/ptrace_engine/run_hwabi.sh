#!/bin/bash
set -e
cd /work
g++ -std=c++20 -O2 -I/src -o hwabi hwabi.cpp /src/ptracearch.cpp
./hwabi
