@echo off
chcp 65001 >nul
title Secure P2P Chat - Build Client
echo ========================================
echo   Secure P2P Chat - Compilare CLIENT
echo ========================================
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo [EROARE] Python nu este instalat sau nu este in PATH.
    pause
    exit /b 1
)

echo [1/4] Instalare dependente...
python -m pip install --upgrade pip >nul
python -m pip install -r requirements.txt
python -m pip install pyinstaller

echo.
echo [2/4] Alegere...
echo   1. Client PyInstaller --onedir  (RECOMANDAT)
echo   2. Client PyInstaller --onefile
echo   3. Doar server semnalizare (vezi build_signaling_server.bat)
echo.
set /p choice="Alege (1 sau 2): "

if "%choice%"=="2" goto onefile
goto onedir

:onedir
echo.
echo [3/4] Compilare CLIENT onedir...
python -m PyInstaller --noconfirm --onedir --windowed ^
    --name "SecureP2PChat" ^
    --hidden-import=argon2 ^
    --hidden-import=nacl ^
    --hidden-import=nacl.signing ^
    --hidden-import=cryptography ^
    --hidden-import=customtkinter ^
    --hidden-import=PIL ^
    --hidden-import=tkinter ^
    --hidden-import=client ^
    --hidden-import=shared ^
    --collect-all customtkinter ^
    --collect-all tkinter ^
    --collect-all nacl ^
    --collect-data tkinter ^
    client/main.py
echo.
echo [4/4] Gata: dist\SecureP2PChat\SecureP2PChat.exe
echo Ruleaza din folderul dist\SecureP2PChat\ (nu muta doar .exe)
goto end

:onefile
echo.
echo [3/4] Compilare CLIENT onefile...
python -m PyInstaller --noconfirm --onefile --windowed ^
    --name "SecureP2PChat" ^
    --hidden-import=argon2 --hidden-import=nacl --hidden-import=nacl.signing ^
    --hidden-import=cryptography --hidden-import=customtkinter --hidden-import=PIL ^
    --hidden-import=tkinter --collect-all customtkinter --collect-all tkinter --collect-all nacl ^
    --collect-data tkinter ^
    client/main.py
echo.
echo [4/4] Gata: dist\SecureP2PChat.exe

:end
echo.
echo Pentru SERVER: ruleaza build_signaling_server.bat
echo.
pause
