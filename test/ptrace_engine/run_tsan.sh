cd /work
SRC="driver.cpp /src/ptraceengine.cpp /src/ptracearch.cpp /src/ptraceelf.cpp /src/ptracemodule.cpp /src/ptracestep.cpp"
g++ -std=c++20 -O1 -g -fsanitize=thread -I/src -o driver_tsan $SRC -pthread 2>&1 | grep -E "error"
export TSAN_OPTIONS="halt_on_error=0 report_signal_unsafe=0 second_deadlock_stack=1"
for t in hello step interrupt threads signal detach kill_running relaunch regs_step memory bp_basic bp_threads bp_interrupts bp_remove_running bp_detach hw_watch hw_thread modules frames loader stepover_basic stepover_recursion stepover_threads stepreturn_sites; do
  out=$(timeout 120 ./driver_tsan $t 2>&1); n=$(echo "$out" | grep -c "WARNING: ThreadSanitizer"); echo "$t: $n race warnings, $(echo "$out" | grep '^[0-9]* failure')"
  if [ "$n" != "0" ]; then echo "$out" | grep -A14 "WARNING: ThreadSanitizer" | head -60; fi
done
echo TSANDONE
