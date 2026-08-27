#!/bin/sh
set -eu

if [ ! -f /app/data/sample/demo_network_flows.csv ]; then
  python /app/scripts/generate_demo_data.py --rows 5000
fi

exec "$@"

