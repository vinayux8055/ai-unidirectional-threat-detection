#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -e .

if [[ ! -f data/sample/demo_network_flows.csv ]]; then
  python scripts/generate_demo_data.py --rows 5000
fi

uvicorn threatguard.api:app --port 8000 &
api_pid=$!
trap 'kill "$api_pid" 2>/dev/null || true' EXIT
streamlit run dashboard/app.py --server.port 8501

