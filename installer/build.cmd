@echo off
setlocal
pwsh -File "%~dp0build.ps1" %*
exit /b %errorlevel%
