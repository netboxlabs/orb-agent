#!/usr/bin/env python3
import urllib.request
import re
import sys

# Step 1: Download the file
url = "https://www.iana.org/assignments/enterprise-numbers.txt"
try:
    with urllib.request.urlopen(url) as response:
        content = response.read().decode('utf-8')
except Exception as e:
    print(f"Error fetching file: {e}", file=sys.stderr)
    sys.exit(1)

lines = content.splitlines()

# Step 2: Stream parse and print YAML
print("manufacturers:")

pen = None
name = None

for line in lines:
    line = line.rstrip()
    if re.match(r'^\d+$', line):
        if pen is not None and name is not None:
            print(f"- name: {name}")
            print(f"  pen: {pen}")
        pen = line
        name = None
    elif pen is not None and name is None and line.strip():
        name = line.strip()

# Print last entry
if pen is not None and name is not None:
    print(f"- name: {name}")
    print(f"  pen: {pen}")
