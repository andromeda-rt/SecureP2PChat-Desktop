@echo off
chcp 65001 >nul
title Secure P2P Chat - Build Signaling Server
echo ========================================
echo   Compilare Server Semnalizare + Relay
echo ========================================
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo [EROARE] Python nu este in PATH.
    pause
    exit /b 1
)

echo [1/3] Dependente...
python -m pip install --upgrade pip >nul
python -m pip install -r requirements.txt
python -m pip install pyinstaller

echo.
echo [2/3] Compilare PyInstaller (onedir - stabil)...
if exist build_signal rmdir /s /q build_signal
if exist dist\SignalServer rmdir /s /q dist\SignalServer

python -m PyInstaller --noconfirm --onedir --console ^
    --name "SignalServer" ^
    --distpath dist ^
    --workpath build_signal ^
    --specpath build_signal ^
    --hidden-import=nacl ^
    --hidden-import=nacl.signing ^
    --hidden-import=shared ^
    --hidden-import=shared.constants ^
    --collect-all nacl ^
    signaling_server.py

echo.
if exist dist\SignalServer\SignalServer.exe (
    echo [3/3] GATA!
    echo.
    echo Ruleaza: dist\SignalServer\SignalServer.exe
    echo Port implicit: 37422
    echo Deschide portul 37422 TCP in firewall / router.
) else (
    echo [EROARE] Compilarea a esuat.
)
echo.
pause
