@echo off
chcp 65001 >nul
title Signal Server + Relay
cd /d "%~dp0"
echo ========================================
echo  Server semnalizare + relay criptat
echo  Port: 37422
echo  Deschide 37422/TCP in firewall
echo ========================================
python signaling_server.py
pause
