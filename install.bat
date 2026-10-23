@echo off
setlocal
cd /d "%~dp0"
title PHP Migration Analyzer - Install

where node >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Node.js is not installed. Download it from https://nodejs.org/ ^(version 18 or newer^).
  pause
  exit /b 1
)

for /f "tokens=1 delims=." %%v in ('node -p "process.versions.node"') do set NODE_MAJOR=%%v
if %NODE_MAJOR% LSS 18 (
  echo [ERROR] Node.js 18 or newer is required. Found:
  node --version
  pause
  exit /b 1
)

echo Using Node.js
node --version
echo.
echo Installing dependencies...
call npm install --omit=dev
if errorlevel 1 (
  echo [ERROR] npm install failed.
  pause
  exit /b 1
)

echo.
echo Install complete. Run start.bat to launch PHP Migration Analyzer.
choice /c YN /m "Start it now"
if errorlevel 2 exit /b 0
call "%~dp0start.bat"
