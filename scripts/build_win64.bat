@echo off
set PYTHONUNBUFFERED=1
uv sync --locked
if errorlevel 1 exit /b %errorlevel%
rem Use uv's interpreter, not the Windows launcher (which can escape the venv).
uv run --locked python scripts\build.py %*
exit /b %errorlevel%
