#!/bin/bash

set -e

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

if [ -z "$1" ]; then
    echo "Usage: $0 <output_file>"
    exit 1
fi

OUTPUT=$1
TMP_MANUFACTURERS=$(mktemp)
TMP_DEVICES=$(mktemp)

echo "Saving manufacturers to $TMP_MANUFACTURERS"
"$SCRIPT_DIR/create-manufacturer-list.py" > "$TMP_MANUFACTURERS"

echo "Saving cisco devices to $TMP_DEVICES"
"$SCRIPT_DIR/create-cisco-device-list.sh" > "$TMP_DEVICES"

echo "Merging manufacturers and devices to $OUTPUT"
"$SCRIPT_DIR/merge_yaml.py" "$TMP_MANUFACTURERS" "$TMP_DEVICES" > "$OUTPUT"

echo "Cleaning up"
rm "$TMP_MANUFACTURERS" "$TMP_DEVICES"

echo "Done"
