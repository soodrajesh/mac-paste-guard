#!/bin/bash
set -euo pipefail

# One-time setup: creates a local self-signed code-signing certificate and
# imports it into the login keychain. build.sh uses it instead of ad-hoc
# signing (--sign -), because an ad-hoc signature is just a hash of the raw
# binary with no identity string — so every rebuild produces a different
# CDHash, and macOS silently drops any TCC grant keyed to it. The app keeps
# its row in System Settings with the toggle still on, but
# AXIsProcessTrusted() returns false and the tap never arms.
#
# That failure mode matters more for PasteGuard than for most tools: it looks
# exactly like protection being on while nothing is being checked.
#
# Safe to re-run — skips creation if the cert already exists.

IDENTITY="PasteGuard Local Dev"

if security find-certificate -c "$IDENTITY" -a login.keychain-db >/dev/null 2>&1; then
    echo "✓ '$IDENTITY' already exists in the login keychain — nothing to do."
    exit 0
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

openssl req -x509 -newkey rsa:2048 -keyout "$TMP/key.pem" -out "$TMP/cert.pem" -days 3650 -nodes \
    -subj "/CN=$IDENTITY" \
    -addext "keyUsage=critical,digitalSignature" \
    -addext "extendedKeyUsage=critical,codeSigning" >/dev/null 2>&1

PASS=$(openssl rand -base64 24)
# -legacy: macOS's Security framework doesn't support OpenSSL 3's default
# PKCS12 encryption; without this, `security import` fails MAC verification.
openssl pkcs12 -export -legacy -out "$TMP/cert.p12" -inkey "$TMP/key.pem" -in "$TMP/cert.pem" -passout "pass:$PASS" >/dev/null 2>&1

security import "$TMP/cert.p12" -k ~/Library/Keychains/login.keychain-db -P "$PASS" \
    -T /usr/bin/codesign -T /usr/bin/security

# codesign will happily sign with an untrusted self-signed cert by name, but
# TCC needs the identity to actually pass code-signing trust validation to
# treat it as stable across rebuilds — without this step,
# `security find-identity -v -p codesigning` reports 0 valid identities and
# grants keep dropping exactly like ad-hoc. Scoped to the codeSign policy
# only, not full SSL/browser trust. Prompts for admin credentials.
security add-trusted-cert -d -r trustRoot -p codeSign -k ~/Library/Keychains/login.keychain-db "$TMP/cert.pem"

echo "✓ Created and imported '$IDENTITY'. Future ./build.sh runs will sign with it."
echo "  Note: this changes the app's identity once — macOS will ask you to"
echo "  re-grant Accessibility and Input Monitoring one more time after the"
echo "  next build, then it'll stick across all rebuilds going forward."
