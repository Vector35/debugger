"""Exercise the real macOS launcher without installing packages or building."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


@unittest.skipUnless(os.name == 'posix', 'macOS launcher uses bash')
class MacOSLauncherTest(unittest.TestCase):
    def launch(self, interpreter, fail_env=False):
        launcher = Path(__file__).resolve().parents[1] / 'scripts' / 'build_macosx'
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'poetry.log'
            selected = Path(directory) / 'selected-python'
            tool = Path(directory) / 'tool-python'
            selected.write_text('''#!/bin/bash
if [ "$1" = -I ] && [ "$2" = -c ]; then echo "$0"; exit 0; fi
if [ "$1" = --version ]; then echo 'Python 3.12 (test double)'; exit 0; fi
if [ "$1" = -I ] && [ "$2" = -m ] && [ "$3" = venv ]; then
    mkdir -p "$4/bin"
    cp "$CI_TEST_TOOL" "$4/bin/python"
    exit 0
fi
exit 99
''')
            tool.write_text('''#!/bin/bash
[ -z "${VIRTUAL_ENV-}${CONDA_PREFIX-}${POETRY_ACTIVE-}" ] || exit 12
[ "$POETRY_VIRTUALENVS_IN_PROJECT" = 1 ] || exit 13
[ "$1" = -I ] && [ "$2" = -m ] || exit 14
shift 2
printf '%s\\n' "$*" >> "$CI_TEST_LOG"
if [ "$1" = poetry ] && [ "$2" = env ] && [ "$CI_TEST_FAIL_ENV" = 1 ]; then exit 7; fi
exit 0
''')
            selected.chmod(0o755)
            tool.chmod(0o755)
            env = os.environ.copy()
            env.update(DEBUGGER_CI_PYTHON=str(selected) if interpreter else '/nonexistent/ci-python',
                       CI_TEST_TOOL=str(tool), CI_TEST_LOG=str(log),
                       CI_TEST_FAIL_ENV='1' if fail_env else '0', VIRTUAL_ENV='/old/python39',
                       CONDA_PREFIX='/old/conda', POETRY_ACTIVE='1')
            # The legacy/global Poetry must never be invoked, even for env use.
            wrapper = '''
poetry() { echo 'legacy Poetry was invoked' >&2; return 99; }
export -f poetry
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
        self.assertEqual(calls, ['pip install --disable-pip-version-check poetry==2.4.1',
                                'poetry --version', 'poetry env use <selected-python>',
                                'poetry install --sync --no-root',
                                'poetry run python scripts/build.py two words'])

    def test_env_selection_failure_stops_install(self):
        result, calls = self.launch(True, fail_env=True)
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertEqual(len(calls), 3)

    def test_invalid_override_stops_before_poetry(self):
        result, calls = self.launch(False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('DEBUGGER_CI_PYTHON must name', result.stderr)
        self.assertEqual(calls, [])


if __name__ == '__main__':
    unittest.main()
