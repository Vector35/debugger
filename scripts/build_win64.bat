@echo off
set PYTHONUNBUFFERED=1
rem Migrate cached Poetry environments before invoking current BN API tools.
for /f "delims=" %%P in ('py -3.12 -c "import sys; print(sys.executable)"') do set "DEBUGGER_CI_PYTHON=%%P"
if defined DEBUGGER_CI_PYTHON goto python_ready
rem Download only into this build workspace; do not modify shared runtimes.
py -3.10 -m venv .ci-python-bootstrap
if errorlevel 1 exit /b %errorlevel%
.ci-python-bootstrap\Scripts\python.exe -m pip install --disable-pip-version-check uv==0.8.22
if errorlevel 1 exit /b %errorlevel%
set "UV_PYTHON_INSTALL_DIR=%CD%\.ci-python"
set "UV_PYTHON_BIN_DIR=%CD%\.ci-python-bin"
.ci-python-bootstrap\Scripts\uv.exe python install 3.12
if errorlevel 1 exit /b %errorlevel%
for /f "delims=" %%P in ('.ci-python-bootstrap\Scripts\uv.exe python find --managed-python 3.12') do set "DEBUGGER_CI_PYTHON=%%P"
if not defined DEBUGGER_CI_PYTHON exit /b 1
:python_ready
poetry env use "%DEBUGGER_CI_PYTHON%"
if errorlevel 1 exit /b %errorlevel%
poetry install --sync --no-root
if errorlevel 1 exit /b %errorlevel%
rem Use Poetry's interpreter, not the Windows launcher (which can escape the venv).
poetry run python scripts\build.py %*
exit /b %errorlevel%
