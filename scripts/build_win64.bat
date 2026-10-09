@echo off
set PYTHONUNBUFFERED=1
rem Migrate cached Poetry environments before invoking current BN API tools.
for /f "delims=" %%P in ('py -3.12 -c "import sys; print(sys.executable)"') do set "DEBUGGER_CI_PYTHON=%%P"
if not defined DEBUGGER_CI_PYTHON exit /b 1
poetry env use "%DEBUGGER_CI_PYTHON%"
if errorlevel 1 exit /b %errorlevel%
poetry install --sync --no-root
if errorlevel 1 exit /b %errorlevel%
rem Use Poetry's interpreter, not the Windows launcher (which can escape the venv).
poetry run python scripts\build.py %*
exit /b %errorlevel%
