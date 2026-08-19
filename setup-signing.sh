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
KEYCHAIN=~/Library/Keychains/login.keychain-db

# The real question is whether a *valid signing identity* exists, not whether
# some certificate is sitting in the keychain. Note that
# `security find-certificate -a` exits 0 even when it matches nothing — an
# empty "find all" is not an error — so guarding on its exit code makes this
# script claim the identity already exists and do nothing, forever.
if security find-identity -v -p codesigning 2>/dev/null | grep -qF "$IDENTITY"; then
    echo "✓ '$IDENTITY' is already a valid signing identity — nothing to do."
    exit 0
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# A certificate can exist while still being an invalid identity — that is what
# a missing or cleared trust setting looks like. Re-trust the existing one
# rather than importing a second copy with the same name.
EXISTING=$(security find-certificate -c "$IDENTITY" -a -p "$KEYCHAIN" 2>/dev/null || true)
if [ -n "$EXISTING" ]; then
    echo "Certificate exists but is not a valid signing identity — re-applying trust…"
    printf '%s\n' "$EXISTING" > "$TMP/existing.pem"
    security add-trusted-cert -d -r trustRoot -p codeSign -k "$KEYCHAIN" "$TMP/existing.pem"
    if security find-identity -v -p codesigning 2>/dev/null | grep -qF "$IDENTITY"; then
        echo "✓ '$IDENTITY' is now a valid signing identity."
        exit 0
    fi
    echo "Re-trusting did not take; creating a fresh certificate instead."
fi

openssl req -x509 -newkey rsa:2048 -keyout "$TMP/key.pem" -out "$TMP/cert.pem" -days 3650 -nodes \
    -subj "/CN=$IDENTITY" \
    -addext "keyUsage=critical,digitalSignature" \
    -addext "extendedKeyUsage=critical,codeSigning" >/dev/null 2>&1

PASS=$(openssl rand -base64 24)
# -legacy: macOS's Security framework doesn't support OpenSSL 3's default
# PKCS12 encryption; without this, `security import` fails MAC verification.
openssl pkcs12 -export -legacy -out "$TMP/cert.p12" -inkey "$TMP/key.pem" -in "$TMP/cert.pem" -passout "pass:$PASS" >/dev/null 2>&1

security import "$TMP/cert.p12" -k "$KEYCHAIN" -P "$PASS" \
    -T /usr/bin/codesign -T /usr/bin/security

# codesign will happily sign with an untrusted self-signed cert by name, but
# TCC needs the identity to actually pass code-signing trust validation to
# treat it as stable across rebuilds — without this step,
# `security find-identity -v -p codesigning` reports 0 valid identities and
# grants keep dropping exactly like ad-hoc. Scoped to the codeSign policy
# only, not full SSL/browser trust. Prompts for admin credentials.
security add-trusted-cert -d -r trustRoot -p codeSign -k "$KEYCHAIN" "$TMP/cert.pem"

# Verify rather than assume. Every failure mode this script has had so far
# reported success and left nothing behind.
if ! security find-identity -v -p codesigning 2>/dev/null | grep -qF "$IDENTITY"; then
    echo "✗ '$IDENTITY' was imported but is still not a valid signing identity."
    echo "  Check: security find-identity -v -p codesigning"
    echo "  build.sh will keep falling back to ad-hoc signing until this is fixed."
    exit 1
fi

echo "✓ '$IDENTITY' created, imported and trusted. ./build.sh will sign with it."
echo "  Note: this changes the app's identity once — macOS will ask you to"
echo "  re-grant Accessibility and Input Monitoring one more time after the"
echo "  next build, then it'll stick across all rebuilds going forward."
