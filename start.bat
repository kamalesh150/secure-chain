@echo off
echo Installing cryptography library...
py -m pip install cryptography --quiet
echo Starting BlockDocs HTTPS server...
cd /d C:\Users\gkama\Desktop\secure-chain-main
start "" cmd /k "py server.py"
timeout /t 3 /nobreak >nul
start "" "chrome.exe" "https://localhost:8443/blockdocs.html"
echo Done! Keep the server window open.
