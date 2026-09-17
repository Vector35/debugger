@echo off
set PYTHONUNBUFFERED=1
poetry install --sync --no-root
if errorlevel 1 exit /b %errorlevel%
rem Use Poetry's interpreter, not the Windows launcher (which can escape the venv).
poetry run python scripts\build.py %*
exit /b %errorlevel%
