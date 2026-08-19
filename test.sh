#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

# The detection core is Foundation-only so it can be compiled and exercised
# without an app bundle or any TCC permissions.
OUT="$(mktemp -d)/pasteguard-tests"
swiftc -O -o "$OUT" Sources/Detectors.swift Sources/Redactor.swift Tests/main.swift
"$OUT"
