#!/bin/bash

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <output_file>"
    exit 1
fi

OUTPUT=$1
TMP_MANUFACTURERS=$(mktemp)
TMP_DEVICES=$(mktemp)

echo "Saving manufacturers to $TMP_MANUFACTURERS"
./scripts/create-manufacturer-list.py > "$TMP_MANUFACTURERS"

echo "Saving cisco devices to $TMP_DEVICES"
./scripts/create-cisco-device-list.sh > "$TMP_DEVICES"

echo "Merging manufacturers and devices to $OUTPUT"
./scripts/merge_yaml.py "$TMP_MANUFACTURERS" "$TMP_DEVICES" > "$OUTPUT"

echo "Cleaning up"
rm "$TMP_MANUFACTURERS" "$TMP_DEVICES"

echo "Done"
