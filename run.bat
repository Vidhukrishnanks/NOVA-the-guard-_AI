@echo off
REM ===== URLGuard AI - start the web app =====
cd /d "%~dp0"
if not exist .venv\Scripts\activate.bat (
  echo Virtual environment not found. Run setup.bat first.
  pause
  exit /b 1
)
call .venv\Scripts\activate.bat
start "" /b cmd /c "timeout /t 4 >nul & start http://127.0.0.1:5000"
python app.py
pause
