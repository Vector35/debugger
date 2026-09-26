cd /work
gcc -O0 -no-pie -fno-omit-frame-pointer -o progs progs.c -pthread -ldl || exit 1
gcc -O0 -no-pie -fno-omit-frame-pointer -DPAD -o progs_pad progs.c -pthread -ldl || exit 1
gcc -shared -fPIC -o libtest.so libtest.c
SRC="driver.cpp /src/ptraceengine.cpp /src/ptracearch.cpp /src/ptraceelf.cpp /src/ptracemodule.cpp /src/ptracestep.cpp /src/ptracesignal.cpp /src/ptracesyscall.cpp"
g++ -std=c++20 -O2 -g -I/src -I/bnapi -o driver $SRC -pthread || exit 1
STEP="stepover_basic stepover_user_breakpoint stepover_interrupt stepover_recursion stepreturn_sites stepreturn_address stepreturn_recursion stepover_threads"
OTHER="hello step interrupt threads signal detach kill_running relaunch regs_step memory bp_basic bp_step_remove bp_write bp_threads bp_interrupts bp_remove_running bp_detach hw_watch hw_thread hw_exec hw_detach modules symbols frames loader processes"
echo "== full"; timeout 600 ./driver | tail -1
echo "== step x30"; for i in $(seq 1 30); do for t in $STEP; do timeout 60 ./driver $t | grep -q "^0 failure" || echo "FAIL $t iter $i"; done; done
echo "== others x4"; for i in $(seq 1 4); do for t in $OTHER; do timeout 90 ./driver $t | grep -q "^0 failure" || echo "FAIL $t iter $i"; done; done
echo "== 1cpu"; for i in $(seq 1 8); do for t in $STEP; do timeout 90 taskset -c 0 ./driver $t | grep -q "^0 failure" || echo "1CPU FAIL $t iter $i"; done; done
echo "== 2cpu"; for i in $(seq 1 8); do for t in stepover_threads stepover_recursion stepreturn_recursion; do timeout 90 taskset -c 0,1 ./driver $t | grep -q "^0 failure" || echo "2CPU FAIL $t iter $i"; done; done
echo "== fault injection"; bash /work/run_faults.sh
echo "== x86 ptrace ABI"; bash /work/run_hwabi.sh
echo ALLDONE
