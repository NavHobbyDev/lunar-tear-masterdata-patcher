@echo off
:: Change directory to the folder where this batch script is located
cd /d "%~dp0"

:: Execute Python script
python run_patches.py

:: Keep window open after execution
pause