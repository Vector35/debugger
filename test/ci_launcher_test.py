"""Exercise the real macOS launcher without installing packages or building."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(os.name == 'posix', 'macOS launcher uses bash')
class MacOSLauncherTest(unittest.TestCase):
    def launch(self, interpreter, fail_env=False):
        launcher = Path(__file__).resolve().parents[1] / 'scripts' / 'build_macosx'
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'poetry.log'
            env = os.environ.copy()
            env.update(DEBUGGER_CI_PYTHON=interpreter, CI_TEST_LOG=str(log),
                       CI_TEST_FAIL_ENV='1' if fail_env else '0', VIRTUAL_ENV='/old/python39',
                       CONDA_PREFIX='/old/conda', POETRY_ACTIVE='1')
            # An exported function intercepts Poetry even if /usr/local/bin has it.
            wrapper = '''
poetry() {
    [ -z "${VIRTUAL_ENV-}${CONDA_PREFIX-}${POETRY_ACTIVE-}" ] || return 12
    [ "$POETRY_VIRTUALENVS_IN_PROJECT" = 1 ] || return 13
    printf '%s\n' "$*" >> "$CI_TEST_LOG"
    if [ "$1" = env ] && [ "$CI_TEST_FAIL_ENV" = 1 ]; then return 7; fi
    return 0
}
export -f poetry
exec bash "$1" "two words"
'''
            result = subprocess.run(['bash', '-c', wrapper, 'launcher-test', str(launcher)],
                                    env=env, capture_output=True, text=True, timeout=10)
            calls = log.read_text().splitlines() if log.exists() else []
            return result, calls

    def supported_python(self):
        if not (3, 10) <= sys.version_info[:2] < (3, 15):
            self.skipTest('launcher success tests require a supported host interpreter')
        return sys.executable

    def test_selects_interpreter_before_install_and_run(self):
        result, calls = self.launch(self.supported_python())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, [f'env use {sys.executable}', 'install --sync --no-root',
                                 'run python scripts/build.py two words'])

    def test_env_selection_failure_stops_install(self):
        result, calls = self.launch(self.supported_python(), fail_env=True)
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertEqual(len(calls), 1)

    def test_invalid_override_stops_before_poetry(self):
        result, calls = self.launch('/nonexistent/ci-python')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('DEBUGGER_CI_PYTHON must name', result.stderr)
        self.assertEqual(calls, [])


if __name__ == '__main__':
    unittest.main()
