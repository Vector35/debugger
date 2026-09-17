#!/bin/bash
# Print a supported interpreter for `poetry env use`; do not trust python3 or a
# cached Poetry environment to have migrated when pyproject.toml changed.
set -e

probe_python() {
    "$1" -I -c 'import sys; sys.exit(1) if not (3, 10) <= sys.version_info[:2] < (3, 15) else None; print(sys.executable)' 2>/dev/null
}

if [ -n "${DEBUGGER_CI_PYTHON:-}" ]; then
    if probe_python "$DEBUGGER_CI_PYTHON"; then
        exit 0
    fi
    echo "DEBUGGER_CI_PYTHON must name a working Python 3.10–3.14 interpreter: $DEBUGGER_CI_PYTHON" >&2
    exit 1
fi

# Jenkins' non-login shell may omit Homebrew and python.org installations from
# PATH. Prefer 3.12, then other supported versions, probing the actual executable.
for version in 3.12 3.13 3.11 3.10 3.14; do
    candidate=$(command -v "python$version" || true)
    if [ -n "$candidate" ] && probe_python "$candidate"; then
        exit 0
    fi
    for prefix in /opt/homebrew/bin /usr/local/bin "/Library/Frameworks/Python.framework/Versions/$version/bin"; do
        candidate="$prefix/python$version"
        if [ -x "$candidate" ] && probe_python "$candidate"; then
            exit 0
        fi
    done
done
candidate=$(command -v python3 || true)
if [ -n "$candidate" ] && probe_python "$candidate"; then
    exit 0
fi
echo 'No Python 3.10–3.14 found. Install one on the worker or set DEBUGGER_CI_PYTHON to its executable.' >&2
exit 1
