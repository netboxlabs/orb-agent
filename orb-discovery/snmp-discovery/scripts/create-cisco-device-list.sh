#!/bin/bash

set -e

# Set variables
MIB_URL="https://raw.githubusercontent.com/cisco/cisco-mibs/05dbf50226f7df5f52fd2dd1a9c17759273fa0d0/oid/CISCO-PRODUCTS-MIB.oid"
TMPFILE=$(mktemp)

# Download the OID file
curl -sS "$MIB_URL" -o "$TMPFILE"

# Start YAML
echo "devices:"

# Removed line count output to maintain YAML structure

# Parse each matching line and append to YAML
grep "1\.3\.6\.1\.4\.1\.9\.1\." "$TMPFILE" | while read -r line; do
  OID=$(echo "$line" | awk '{print $2}')
  NAME=$(echo "$line" | awk '{print $1}')
  ID=$(echo "$OID" | awk -F. '{print $NF}')
  echo "  - id: $ID"
  echo "    oid: $OID"
  echo "    name: \"$NAME\""
done

# Clean up
rm "$TMPFILE"
