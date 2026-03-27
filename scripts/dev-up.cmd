@echo off
setlocal

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0dev-up.ps1"
exit /b %errorlevel%
