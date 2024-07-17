@echo off
echo Starting Flask application with Waitress...
start "" "http://127.0.0.1:5000"
python run_waitress.py
pause
