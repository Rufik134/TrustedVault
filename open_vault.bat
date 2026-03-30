@echo off
REM Change to the project directory and invoke TrustedVault on the selected .vault file.
cd /d "%~dp0"
py main.py "%~1"
