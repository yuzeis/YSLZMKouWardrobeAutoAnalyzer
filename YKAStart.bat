@echo off
setlocal
cd /d "%~dp0"
python YKAApp.py
if errorlevel 1 (
  echo.
  echo Program exited with an error.
  pause
)
