#!/bin/bash
set -u
cd /work

gcc -O0 -no-pie -fno-omit-frame-pointer -o progs progs.c -pthread -ldl || exit 1
g++ -std=c++20 -O1 -g -I/src -o event_exception_demo event_exception_demo.cpp \
	/src/ptraceengine.cpp /src/ptracearch.cpp -pthread || exit 1

mode=${1:-task}
if [[ "$mode" != "task" && "$mode" != "handler" ]]; then
	echo "usage: $0 task|handler" >&2
	exit 2
fi

echo "Running the $mode exception demo. The child is expected to abort."
set +e
timeout 10 ./event_exception_demo "$mode"
status=$?
set -e

echo "demo exit status: $status"
if [[ $status -eq 134 ]]; then
	echo "Confirmed: the uncaught event-thread exception invoked std::terminate and SIGABRT."
	exit 0
fi

echo "Unexpected result: wanted exit status 134 (SIGABRT)." >&2
exit 1
