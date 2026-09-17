"""Watchdog regressions; no Binary Ninja installation or debugger privileges needed."""

import subprocess
import sys
import time
import unittest
from unittest.mock import patch

from attach_test_runner import run_attach_test


class AttachTimeoutTest(unittest.TestCase):
    def run_case(self, worker_source, timeout=3):
        self.processes = []
        real_popen = subprocess.Popen

        def record_process(*args, **kwargs):
            proc = real_popen(*args, **kwargs)
            # subprocess.run(taskkill) also uses Popen on Windows; track only
            # the target/worker, not the cleanup utility itself.
            if args[0][0] == sys.executable:
                self.processes.append(proc)
            return proc

        with patch('attach_test_runner.subprocess.Popen', side_effect=record_process):
            try:
                run_attach_test([sys.executable, '-c', 'import time; time.sleep(120)'],
                                lambda pid: [sys.executable, '-c', worker_source], timeout=timeout)
            finally:
                for proc in self.processes:
                    self.assertIsNotNone(proc.poll(), f'leaked process {proc.pid}')

    def test_timeout_fails_and_reaps_target_and_worker(self):
        started = time.monotonic()
        with self.assertRaisesRegex(AssertionError, 'exceeded 0.5 seconds'):
            self.run_case('import time; time.sleep(120)', timeout=0.5)
        self.assertLess(time.monotonic() - started, 15)
        self.assertEqual(len(self.processes), 2)

    def test_failure_reaps_target(self):
        with self.assertRaisesRegex(AssertionError, 'exit code 7'):
            self.run_case('import sys; sys.exit(7)')

    def test_success_reaps_target(self):
        self.run_case('pass')

    def test_worker_start_failure_reaps_target(self):
        with patch('attach_test_runner.sys.path', [None]):
            # Invalid inherited environment fails after starting the target.
            with self.assertRaises(TypeError):
                self.run_case('pass')
        self.assertEqual(len(self.processes), 1)


if __name__ == '__main__':
    unittest.main()
