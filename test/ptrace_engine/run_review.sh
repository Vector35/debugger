#!/bin/bash
# The repros of the findings in PTRACE_REVIEW_FINDINGS.md. Every test fails while its finding stands.
# PTRACE_TEST_DIR is where progs is built and run from, and defaults to this directory.
set -u
DIR="${PTRACE_TEST_DIR:-$(cd "$(dirname "$0")" && pwd)}"
SRC="${PTRACE_SRC_DIR:-$(cd "$(dirname "$0")/../../core/adapters" && pwd)}"
export PTRACE_TEST_DIR="$DIR"
cd "$DIR" || exit 1

gcc -O0 -no-pie -fno-omit-frame-pointer -o progs progs.c -pthread -ldl || exit 1
ENGINE="$SRC/ptraceengine.cpp $SRC/ptracearch.cpp $SRC/ptracestep.cpp"
WRAP="-Wl,--wrap=ptrace -Wl,--wrap=pwrite -Wl,--wrap=open -Wl,--wrap=waitpid"

g++ -std=c++20 -O1 -g -I"$SRC" -o review_driver review_driver.cpp faultwrap.cpp $ENGINE -pthread $WRAP || exit 1
echo "== repros"
timeout 300 ./review_driver "$@"
status=$?

# The teardown finding is a use after free, so it is worth seeing what AddressSanitizer makes of it as well. It needs
# the sanitizer runtime, which is not installed everywhere.
if g++ -std=c++20 -O1 -g -fsanitize=address,undefined -I"$SRC" -o review_driver_asan review_driver.cpp faultwrap.cpp \
	$ENGINE -pthread $WRAP 2>/dev/null; then
	echo "== teardown_order under AddressSanitizer"
	timeout 300 ./review_driver_asan teardown_order 2>&1 |
		grep -E "ERROR|SUMMARY|READ of size|WRITE of size|freed by thread|previously allocated|FAIL|failure" | head -20
else
	echo "== teardown_order under AddressSanitizer: SKIP, no sanitizer runtime"
fi
exit $status
