# PasteGuard

A menubar app that checks what you're about to paste into an AI tool — **before** it leaves your Mac.

Press ⌘V into Claude, ChatGPT, Cursor, Copilot or an AI site in your browser, and if the clipboard
contains credentials, payment details or personal data, the paste is stopped and you get a choice:
redact, paste anyway, or cancel.

**PasteGuard makes no network connections.** Not for telemetry, not for detection, not for updates.
Detection runs entirely on-device. This is verifiable, not a promise:

```
$ otool -L PasteGuard.app/Contents/MacOS/PasteGuard | grep -i -E "network|cfnetwork"
$ nm -u PasteGuard.app/Contents/MacOS/PasteGuard | grep -i -E "URLSession|socket|getaddrinfo"
```

Both return nothing. The binary links AppKit, CoreGraphics, ApplicationServices, IOKit and
Foundation — no networking framework is present.

## Status

Proof of concept. The detection core is covered by 49 tests; the interception path works but has
had limited real-world use. See [Known gaps](#known-gaps).

## Why this exists

77% of workers paste sensitive data into gen-AI tools, and 82% of those pastes go through
unmanaged personal accounts. Every product solving this — Zscaler, Wiz, Forcepoint, Sentra — is
enterprise-priced, network-layer, and requires routing your traffic through a vendor's cloud. That
is a strange answer to "we don't want our data leaving the building."

PasteGuard is the opposite shape: local, small, and useless to anyone who wants your data, because
it never has a way to send it anywhere.

## What it detects

| Severity | Detector | Validation |
|---|---|---|
| Critical | Private key blocks | PEM header/footer |
| Critical | AWS access key ID | Prefix + charset |
| Critical | AWS secret access key | Requires the key name nearby, plus Shannon entropy ≥ 3.5 |
| Critical | Anthropic / OpenAI / GitHub / Slack / Google keys | Vendor prefixes |
| Critical | JWT | Three-segment base64url |
| Critical | `password=` / `api_key=` assignments | Placeholder rejection |
| High | IBAN | **mod-97 checksum + per-country length** |
| High | Payment card | **Luhn checksum**, 13–19 digits |
| High | Irish PPSN | **Check-character algorithm** |
| Medium | Email address | — |
| Medium | Irish mobile number | Mobile ranges only |

The checksums are the point. A 16-digit order reference is not a card number, and `GB99…` with the
wrong check digits is not an IBAN. Flagging those trains people to click through the warning, which
is the failure mode that kills tools in this category. The test suite spends as much effort on
false positives (documentation placeholders, `.env.example` files, stack traces, version numbers)
as on true positives.

The **Irish PPSN** detector is deliberate: it is the most sensitive identifier in Irish payroll and
health data, and no US-built DLP tool ships it.

## Install

```bash
./build.sh        # compiles, runs tests, signs, installs to /Applications
open /Applications/PasteGuard.app
```

Requires macOS 13+. No dependencies, no package manager, no Xcode project — just `swiftc`.

### Permissions

PasteGuard needs two grants, and refuses to run half-armed:

- **Input Monitoring** — lets the event tap see ⌘V at all.
- **Accessibility** — lets it *suppress* the paste and re-post one, and read a browser window's
  title to tell which site is focused.

Without Accessibility the app could only warn *after* the paste landed, which is worse than
useless — so it stays inactive (menubar icon shows a slashed shield) until both are granted. Grant
them from the menubar menu.

## How it works

An **active** `CGEventTap` (`.defaultTap`, not listen-only) on `keyDown`. Returning `nil` from the
callback swallows the keystroke, so the decision happens before any data moves:

1. ⌘V pressed (plain — ⌘⇧V is left alone so ClipKeep's picker still works).
2. Is the frontmost app an AI surface? Native bundle ID allowlist, or for browsers, the focused
   window's **title** (never page content).
3. Scan the clipboard with the local detectors, capped at 200k characters so the tap can't overrun
   its deadline.
4. Findings? Swallow the event and show a non-modal panel.
5. On decision: write the chosen text to the pasteboard, reactivate the destination app, synthesize
   ⌘V stamped with a bypass marker in `eventSourceUserData` so it isn't re-intercepted, then
   **restore the original clipboard** — redaction applies to what the AI receives, not to what you
   keep.

The panel is deliberately not an `NSAlert`: `runModal` blocks the main run loop, the tap callback
runs on that run loop, and a blocked run loop makes macOS disable the tap.

## Audit log

`~/Library/Application Support/PasteGuard/audit.jsonl`, one JSON object per decision:

```json
{"timestamp":"2026-08-19T14:22:31Z","destinationApp":"Claude","findings":{"aws_access_key_id":1,"iban":1},"highestSeverity":"Critical","decision":"redacted","charactersScanned":842}
```

**The pasted text never enters this file** — not the match, not a hash of it, not a preview. Only
the kind of thing found, the count, the destination and the choice. That constraint is what would
make a future team dashboard shareable with a security team without handing them anyone's
clipboard.

## Testing

```bash
./test.sh    # 49 tests, no app bundle or permissions needed
```

The detection core is Foundation-only precisely so it can be tested this way. `build.sh` runs the
suite and refuses to install on failure.

To sanity-check detection against your own real data without staging a paste: copy something, then
**Scan Clipboard Now** from the menubar. It shows what would be caught and a redacted preview.

## Known gaps

Honest list of what a POC does not yet do:

- **Ad-hoc code signature.** Rebuilds can invalidate the TCC grants, meaning Accessibility and
  Input Monitoring need re-granting. A Developer ID identity fixes this permanently and is the
  first thing to do before anyone else installs it.
- **Browser detection is title-based.** If a tab's title doesn't contain a known marker, the paste
  isn't checked. Robust detection would need a browser extension, which breaks the "no extra
  surface" property — a deliberate trade for now.
- **Drag-and-drop and right-click → Paste bypass the tap entirely.** Only ⌘V is intercepted.
- **Text only.** A screenshot of a customer record pasted into Claude is not inspected. This is the
  biggest real-world hole, and the one where `mac-ocr`'s Vision pipeline would slot in directly.
- **No policy layer.** Detectors are compile-time constants. Per-org allowlists, custom patterns
  and a "never allow critical" enforcement mode are what a paid tier would be built from.
- **Detection tuning is unproven at scale.** 49 tests is enough to prove the approach, not enough
  to prove the false-positive rate on a real person's daily clipboard.
