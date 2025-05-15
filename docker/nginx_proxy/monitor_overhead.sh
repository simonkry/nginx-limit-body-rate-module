#!/bin/bash

set -o errexit -o nounset -o pipefail


OUTPUT_FILE="/mnt/results/resource_usage.csv"
INTERVAL="0.1"  # 100 ms


read_cpu_usage() {
  awk '/usage_usec/ { print $2 }' /sys/fs/cgroup/cpu.stat
}


read_cpu_quota() {
  CPU_MAX=$(cat /sys/fs/cgroup/cpu.max)
  if [[ "$CPU_MAX" == "max "* ]]; then
    NPROC=$(nproc)
    echo "$NPROC"
  else
    QUOTA=$(echo "$CPU_MAX" | awk '{print $1}')
    PERIOD=$(echo "$CPU_MAX" | awk '{print $2}')
    echo "$((QUOTA / PERIOD))"
  fi
}


PREV_CPU_USEC=$(read_cpu_usage)
PREV_TIME_NS=$(date +%s%N)

CPU_CORES=$(read_cpu_quota)


while true; do
  sleep "$INTERVAL"

  TIMESTAMP=$(date +%s.%N)

  CPU_USEC=$(read_cpu_usage)
  CURR_TIME_NS=$(date +%s%N)

  DELTA_CPU_USEC=$((CPU_USEC - PREV_CPU_USEC))
  DELTA_TIME_NS=$((CURR_TIME_NS - PREV_TIME_NS))

  if (( DELTA_TIME_NS > 0 )); then
    CPU_PERCENT=$(LC_NUMERIC=C awk "BEGIN {
      if ($DELTA_TIME_NS > 0 && $CPU_CORES > 0) {
        printf \"%.2f\", ($DELTA_CPU_USEC * 100.0) / (($DELTA_TIME_NS / 1000.0) * $CPU_CORES)
      } else {
        print \"0.00\"
      }
    }")
  else
    CPU_PERCENT="0.00"
  fi

  PREV_CPU_USEC=$CPU_USEC
  PREV_TIME_NS=$CURR_TIME_NS

  echo "$TIMESTAMP, $CPU_PERCENT, $(cat /sys/fs/cgroup/memory.current)" >> "$OUTPUT_FILE"
done