@echo off
cd /d "%~dp0"
python manter_sast.py
if errorlevel 1 pause
