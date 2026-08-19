#!/bin/bash
# Shared by build.sh and setup-signing.sh. Sourced, not executed directly.
#
# The identity-validity check was previously duplicated in three places
# (build.sh once, setup-signing.sh twice) and already drifted once — a fix
# to how validity was determined (df90060) had to be applied to each copy by
# hand. One function, sourced by both, so a future correction only has to
# happen once.

SIGN_IDENTITY_NAME="PasteGuard Local Dev"

# The real question is whether a *valid signing identity* exists, not
# whether some certificate is sitting in the keychain — `find-certificate -a`
# exits 0 even when it matches nothing, so guarding on its exit code alone
# (an earlier version of this script did) silently does nothing forever on a
# machine with no certificate at all.
has_valid_signing_identity() {
    security find-identity -v -p codesigning 2>/dev/null | grep -qF "$SIGN_IDENTITY_NAME"
}
