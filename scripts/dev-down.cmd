@echo off
setlocal

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0dev-down.ps1"
exit /b %errorlevel%
