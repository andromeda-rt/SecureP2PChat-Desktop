@echo off
chcp 65001 >nul
title Secure P2P Chat
cd /d "%~dp0"
echo Pornire client...
python -m client.main
if errorlevel 1 pause
