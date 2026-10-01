"""Exercise the real macOS launcher without installing packages or building."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


@unittest.skipUnless(os.name == 'posix', 'macOS launcher uses bash')
class MacOSLauncherTest(unittest.TestCase):
    def launch(self, interpreter, fail_sync=False, fail_run=False):
        launcher = Path(__file__).resolve().parents[1] / 'scripts' / 'build_macosx'
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'uv.log'
            selected = Path(directory) / 'selected-python'
            selected.write_text('''#!/bin/bash
if [ "$1" = -I ] && [ "$2" = -c ]; then echo "$0"; exit 0; fi
if [ "$1" = --version ]; then echo 'Python 3.12 (test double)'; exit 0; fi
exit 99
''')
            selected.chmod(0o755)
            env = os.environ.copy()
            env.update(DEBUGGER_CI_PYTHON=str(selected) if interpreter else '/nonexistent/ci-python',
                       CI_TEST_LOG=str(log),
                       CI_TEST_FAIL_SYNC='1' if fail_sync else '0',
                       CI_TEST_FAIL_RUN='1' if fail_run else '0', VIRTUAL_ENV='/old/python39',
                       CONDA_PREFIX='/old/conda', UV_PROJECT_ENVIRONMENT='/old/venv')
            wrapper = '''
uv() {
    [ -z "${VIRTUAL_ENV-}${CONDA_PREFIX-}${UV_PROJECT_ENVIRONMENT-}" ] || return 12
    [ "$2" = --locked ] && [ "$3" = --python ] && [ "$4" = "$DEBUGGER_CI_PYTHON" ] || return 15
    printf 'uv %s\\n' "$*" >> "$CI_TEST_LOG"
    if [ "$1" = sync ] && [ "$CI_TEST_FAIL_SYNC" = 1 ]; then
        echo 'uv sync underlying failure (test double)' >&2
        return 7
    fi
    if [ "$1" = run ]; then
        [ "$5" = python ] && [ "$6" = scripts/build.py ] && [ "$7" = 'two words' ] && [ "$#" = 7 ] || return 16
        if [ "$CI_TEST_FAIL_RUN" = 1 ]; then
            echo 'uv run underlying failure (test double)' >&2
            return 8
        fi
    fi
    return 0
}
export -f uv
exec bash "$1" "two words"
'''
            result = subprocess.run(['bash', '-c', wrapper, 'launcher-test', str(launcher)],
                                    cwd=directory, env=env, capture_output=True, text=True, timeout=10)
            calls = log.read_text().splitlines() if log.exists() else []
            calls = [call.replace(str(selected), '<selected-python>') for call in calls]
            return result, calls

    def test_selects_interpreter_before_install_and_run(self):
        result, calls = self.launch(True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, ['uv sync --locked --python <selected-python>',
                                'uv run --locked --python <selected-python> python scripts/build.py two words'])

    def test_sync_failure_stops_build(self):
        result, calls = self.launch(True, fail_sync=True)
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertIn('uv sync underlying failure', result.stderr)
        self.assertEqual(calls, ['uv sync --locked --python <selected-python>'])

    def test_build_failure_is_visible(self):
        result, calls = self.launch(True, fail_run=True)
        self.assertEqual(result.returncode, 8, result.stderr)
        self.assertIn('uv run underlying failure', result.stderr)
        self.assertEqual(len(calls), 2)

    def test_invalid_override_stops_before_uv(self):
        result, calls = self.launch(False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('DEBUGGER_CI_PYTHON must name', result.stderr)
        self.assertEqual(calls, [])


if __name__ == '__main__':
    unittest.main()
