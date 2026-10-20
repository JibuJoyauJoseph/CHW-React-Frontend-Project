@echo off
setlocal
cd /d "%~dp0server"
if not exist node_modules npm install
if not exist .env copy .env.example .env
start "Rwanda CHW Node API" cmd /k "npm run dev"
timeout /t 3 >nul
cd /d "%~dp0rwanda-chw-react"
if not exist node_modules npm install
start "Rwanda CHW React" cmd /k "npm run dev"
endlocal
