#!/usr/bin/env python3
import sys
import re

def parse_simple_yaml(file_path):
    """Parses a simple YAML file into a dictionary of lists using only built-in tools."""
    result = {}
    current_key = None
    current_item = {}
    in_item = False

    with open(file_path, 'r') as f:
        for line in f:
            line = line.rstrip()

            if not line.strip():
                continue

            # Top-level key
            if re.match(r'^\w+:$', line):
                current_key = line[:-1]
                result.setdefault(current_key, [])
                in_item = False
                continue

            # Start of list item
            if line.strip().startswith("- "):
                if current_item:
                    if not isinstance(result.get(current_key), list):
                        raise ValueError(f"Key '{current_key}' is not a list or wasn't set properly.")
                    result[current_key].append(current_item)
                current_item = {}
                line = line.strip()[2:]
                if ": " in line:
                    k, v = line.split(": ", 1)
                    current_item[k.strip()] = parse_value(v.strip())
                in_item = True

            elif in_item and ": " in line:
                k, v = line.strip().split(": ", 1)
                current_item[k.strip()] = parse_value(v.strip())

        # Final item
        if current_item:
            result[current_key].append(current_item)

    return result

def parse_value(val):
    # Try to convert to int if possible
    if re.match(r'^\d+$', val):
        return int(val)
    return re.sub(r'[^a-zA-Z0-9\s]', '', val)

def merge_dicts(dicts):
    merged = {}
    for d in dicts:
        for key, val in d.items():
            if isinstance(val, list):
                merged.setdefault(key, []).extend(val)
    return merged

def dump_yaml(data):
    for key, items in data.items():
        print(f"{key}:")
        for item in items:
            print("  -", end="")
            first = True
            for k, v in item.items():
                if first:
                    print(f" {k}: {v}")
                    first = False
                else:
                    print(f"    {k}: {v}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python merge_yaml.py file1.yaml file2.yaml ...")
        sys.exit(1)

    inputs = sys.argv[1:]
    parsed = [parse_simple_yaml(f) for f in inputs]
    merged = merge_dicts(parsed)
    dump_yaml(merged)
