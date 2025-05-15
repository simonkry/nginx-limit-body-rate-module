#!/bin/bash

set -o errexit


if [ $# -ne 1 ]; then
  echo "Usage: $0 size[K|M|G]"
  exit 1
fi


input="$1"
size_value=$(echo "$input" | sed --regexp-extended 's/[^0-9]//g')
size_unit=$(echo "$input" | sed --regexp-extended 's/[0-9]+//')


case "$size_unit" in
  k|K) size_bytes=$((size_value * 1024));;
  m|M) size_bytes=$((size_value * 1048576));;
  g|G) size_bytes=$((size_value * 1073741824));;
  "")  size_bytes=$((size_value));;
  *) echo "Error: Unknown size unit '$size_unit'. Use K, M, G, or no unit."; exit 1;;
esac


SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UPLOAD_FILE="$SCRIPT_DIR/tmp_file.bin"


if [ -f "$UPLOAD_FILE" ]; then
  actual_size=$(stat --format="%s" "$UPLOAD_FILE")
  if [ "$actual_size" -eq "$size_bytes" ]; then
    echo "Temporary file already exists with correct size: $UPLOAD_FILE (${size_bytes} bytes)"
    exit 0
  else
    echo "Existing temporary file size differs. Regenerating..."
  fi
else
  echo "Temporary file does not exist. Generating..."
fi


count=$((size_bytes / 1048576))
remainder=$((size_bytes % 1048576))


dd if=/dev/urandom of="$UPLOAD_FILE" bs=1M count="$count" status=none

if [ "$remainder" -gt 0 ]; then
  dd if=/dev/urandom of="$UPLOAD_FILE" bs=1 count="$remainder" seek="$count" status=none
fi


echo "File created: $UPLOAD_FILE (${size_bytes} bytes)"