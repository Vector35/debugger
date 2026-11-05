FROM ubuntu:24.04
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    g++ clang cmake ninja-build python3-pytest binutils && rm -rf /var/lib/apt/lists/*
