@echo off
REM ===== URLGuard AI - one-time setup for Windows =====
cd /d "%~dp0"
echo.
echo [1/4] Creating virtual environment (.venv)...
python -m venv .venv
if errorlevel 1 (
  echo ERROR: Python not found. Install Python 3.11-3.13 from python.org and tick "Add python.exe to PATH".
  pause
  exit /b 1
)
call .venv\Scripts\activate.bat
echo.
echo [2/4] Upgrading pip...
python -m pip install --upgrade pip
echo.
echo [3/4] Installing dependencies (this can take a few minutes)...
pip install -r requirements.txt
if errorlevel 1 (
  echo ERROR: Dependency installation failed. See README "Troubleshooting".
  pause
  exit /b 1
)
echo.
echo [4/4] Training the model...
python train_model.py
echo.
echo Setup complete. Start the app with run.bat
pause
