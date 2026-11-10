#!/usr/bin/env python3
"""Repo rules check. Fails if a file holds something this repo must never publish.

Checks:
  1. Subscription or tenant IDs (a GUID next to the word subscription or tenant).
  2. Public IPv4 addresses that are not defanged. Private, loopback and
     documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) are allowed.
     Defanged form 1.2.3[.]4 is allowed.
     Version numbers after a key ending in "version" (contentVersion) are skipped.

Scans tracked files and new files. Files in .gitignore are skipped.
Run it before you commit:  python3 .github/scripts/repo_rules.py
"""
import ipaddress
import re
import subprocess
import sys

GUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
ID_NEAR_WORD = re.compile(r"(subscription|tenant)[\w\"' :=/.-]{0,30}" + GUID, re.IGNORECASE)
IPV4 = re.compile(r"(?<![\d.\[])(?:\d{1,3}\.){3}\d{1,3}(?![\d\]])")
# NEW: finds "...version": "1.0.0.0" and keeps only the number
VERSION_FIELD = re.compile(r"""\w*version["']?\s*[:=]\s*["']?((?:\d+\.){3}\d+)""", re.IGNORECASE)

files = subprocess.run(
    # NEW: --others --exclude-standard adds new files that are not tracked yet
    ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
    capture_output=True, text=True, check=True,
).stdout.split("\0")

problems = []
for path in filter(None, files):
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.readlines()
    except (UnicodeDecodeError, IsADirectoryError, FileNotFoundError):
        continue  # binary or removed file
    for num, line in enumerate(lines, 1):
        if ID_NEAR_WORD.search(line):
            problems.append(f"{path}:{num}: subscription or tenant ID. Use --query or -o none, or subscription().id in Bicep.")
        version_values = set(VERSION_FIELD.findall(line))  # NEW
        for match in IPV4.findall(line):
            if match in version_values:  # NEW: a version number, not an address
                continue
            try:
                ip = ipaddress.ip_address(match)
            except ValueError:
                continue
            if ip.is_global:
                problems.append(f"{path}:{num}: public IP {match}. Defang it (1.2.3[.]4) or remove it.")

if problems:
    print("Repo rules check FAILED:")
    print("\n".join(problems))
    sys.exit(1)
print(f"Repo rules check passed ({len([f for f in files if f])} files).")