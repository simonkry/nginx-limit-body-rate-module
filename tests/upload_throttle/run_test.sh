#!/bin/bash

cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1

# generate a 0.5GiB file for upload testing
"../../docker/tmp_file/generate_tmp_file.sh" 500M

# initialize CSV files for results
mkdir --parents "results"
if [ ! -f "results/upload_results.csv" ]; then
  echo "CLIENT, REQUEST, START_TIMESTAMP, HTTP_CODE, CONNECT_TIME, START_TRANSFER_TIME, RTT, SIZE_UPLOAD, SPEED_UPLOAD" >> "results/upload_results.csv"
fi

if [ ! -f "results/resource_usage.csv" ]; then
  echo "TIMESTAMP, CPU_USED, MEM_USED" >> "results/resource_usage.csv"
fi

docker compose down
docker compose build
docker compose up -d --scale client=20