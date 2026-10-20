@echo off
chcp 65001 >nul
cd /d "%~dp0"
python manter_sast.py --cloudflare
if errorlevel 1 pause
