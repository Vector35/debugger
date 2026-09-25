cd /work
gcc -O0 -no-pie -fno-omit-frame-pointer -o progs progs.c -pthread -ldl || exit 1
gcc -O0 -no-pie -fno-omit-frame-pointer -DPAD -o progs_pad progs.c -pthread -ldl
gcc -shared -fPIC -o libtest.so libtest.c
SRC="driver.cpp /src/ptraceengine.cpp /src/ptracearch.cpp /src/ptraceelf.cpp /src/ptracemodule.cpp /src/ptracestep.cpp /src/ptracesignal.cpp"
g++ -std=c++20 -O2 -g -I/src -I/bnapi -o driver $SRC -pthread || exit 1
NEW="redirect_parse redirect_stdout redirect_stdin redirect_stderr_merge redirect_other_fds redirect_append_readwrite redirect_relative redirect_errors redirect_leaks attach_threads attach_breakpoint attach_step_at_breakpoint attach_exit attach_kill attach_dtor_detaches attach_errors attach_churn attach_syscall"
echo "== full"; timeout 900 ./driver | grep -v "REPRO\|PERF" | grep -E "FAIL|^[0-9]+ failure"
echo "== new x20"; for i in $(seq 1 20); do for t in $NEW; do timeout 120 ./driver $t | grep -q "^0 failure" || echo "FAIL $t iter $i"; done; done
echo "== 1cpu"; for i in $(seq 1 5); do for t in $NEW; do timeout 120 taskset -c 0 ./driver $t | grep -q "^0 failure" || echo "1CPU FAIL $t iter $i"; done; done
echo "== asan"; g++ -std=c++20 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -I/src -I/bnapi -o driver_asan $SRC -pthread || exit 1
for t in $NEW; do out=$(ASAN_OPTIONS=detect_leaks=1 timeout 180 ./driver_asan $t 2>&1); echo "$t: $(echo "$out" | grep -c 'ERROR: AddressSanitizer\|runtime error') sanitizer errors, $(echo "$out" | grep '^[0-9]* failure')"; done
echo "== tsan"; g++ -std=c++20 -O1 -g -fsanitize=thread -I/src -I/bnapi -o driver_tsan $SRC -pthread || exit 1
for t in $NEW; do out=$(TSAN_OPTIONS="halt_on_error=0" timeout 180 ./driver_tsan $t 2>&1); n=$(echo "$out" | grep -c "WARNING: ThreadSanitizer"); echo "$t: $n race warnings, $(echo "$out" | grep '^[0-9]* failure')"; if [ "$n" != 0 ]; then echo "$out" | grep -A14 "WARNING: ThreadSanitizer" | head -40; fi; done
echo ALLDONE
