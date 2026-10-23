@echo off
setlocal
cd /d "%~dp0"
title PHP Migration Analyzer

where node >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Node.js is not installed. Download it from https://nodejs.org/ ^(version 18 or newer^).
  pause
  exit /b 1
)

if not exist "node_modules\" (
  echo Installing dependencies...
  call npm install --omit=dev
  if errorlevel 1 (
    echo [ERROR] npm install failed.
    pause
    exit /b 1
  )
)

if "%PORT%"=="" set PORT=3000
echo Starting PHP Migration Analyzer on http://localhost:%PORT%
start "" "http://localhost:%PORT%"
node server.js
pause
