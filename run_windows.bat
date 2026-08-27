@echo off
setlocal
cd /d "%~dp0"

if not exist .venv (
  py -3.12 -m venv .venv 2>nul || py -3 -m venv .venv
)

call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -e .

if not exist data\sample\demo_network_flows.csv (
  python scripts\generate_demo_data.py --rows 5000
)

echo.
echo Dashboard: http://localhost:8501
echo API docs:  http://localhost:8000/docs
echo Default login: admin@threatguard.local / ChangeMe123!
echo Change the password in .env before a real deployment.
echo.

start "ThreatGuard API" cmd /k "call .venv\Scripts\activate.bat && uvicorn threatguard.api:app --reload --port 8000"
call .venv\Scripts\activate.bat
streamlit run dashboard\app.py

