cd /work
SRC="driver.cpp /src/ptraceengine.cpp /src/ptracearch.cpp /src/ptraceelf.cpp /src/ptracemodule.cpp /src/ptracestep.cpp /src/ptracesignal.cpp"
echo "== ASan+UBSan build"; g++ -std=c++20 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -I/src -I/bnapi -o driver_asan $SRC -pthread || exit 1
export ASAN_OPTIONS=detect_leaks=1:abort_on_error=0 UBSAN_OPTIONS=print_stacktrace=1
timeout 900 ./driver_asan 2>&1 | grep -v "REPRO\|^  ok\|^\[" | tail -40
echo "== ASAN DONE"
