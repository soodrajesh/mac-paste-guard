import Foundation

// Compiled against Sources/Detectors.swift + Sources/Redactor.swift only —
// no AppKit, no app bundle, no permissions. Run with ./test.sh
//
// Every credential-shaped string below is either syntactically valid but
// non-issued, or a published test vector. Nothing here is a live secret.

var passed = 0
var failed = 0

func check(_ name: String, _ condition: Bool) {
    if condition {
        passed += 1
    } else {
        failed += 1
        print("  FAIL  \(name)")
    }
}

func expectFinding(_ name: String, in text: String, kind: String, count: Int = 1) {
    let findings = DetectionEngine.standard.scan(text)
    let matching = findings.filter { $0.kind == kind }
    if matching.count == count {
        passed += 1
    } else {
        failed += 1
        print("  FAIL  \(name) — expected \(count)×\(kind), got \(matching.count) " +
              "(all: \(findings.map(\.kind).sorted().joined(separator: ",")))")
    }
}

func expectClean(_ name: String, _ text: String) {
    let findings = DetectionEngine.standard.scan(text)
    if findings.isEmpty {
        passed += 1
    } else {
        failed += 1
        print("  FAIL  \(name) — expected no findings, got \(findings.map(\.kind).joined(separator: ","))")
    }
}

func section(_ title: String) { print("\n\(title)") }

// MARK: - Checksums

section("Checksums")

// Luhn test vectors (well-known non-issued test card numbers).
check("luhn accepts Visa test number", Checksum.luhn("4111111111111111"))
check("luhn accepts Mastercard test number", Checksum.luhn("5555555555554444"))
check("luhn accepts Amex test number", Checksum.luhn("378282246310005"))
check("luhn rejects transposed digit", !Checksum.luhn("4111111111111121"))
check("luhn rejects short run", !Checksum.luhn("411111111"))

// IBAN vectors from the ISO 13616 registry examples.
check("iban accepts GB example", Checksum.iban("GB82WEST12345698765432"))
check("iban accepts spaced GB example", Checksum.iban("GB82 WEST 1234 5698 7654 32"))
check("iban accepts DE example", Checksum.iban("DE89370400440532013000"))
check("iban rejects bad check digits", !Checksum.iban("GB83WEST12345698765432"))
check("iban rejects wrong length for country", !Checksum.iban("IE29AIBK9311521234567"))

// PPSN check-character algorithm.
check("ppsn accepts valid 8-char", Checksum.ppsn("1234567T"))
check("ppsn accepts valid 9-char with A", Checksum.ppsn("1234567FA"))
check("ppsn rejects wrong check letter", !Checksum.ppsn("1234567A"))
check("ppsn rejects too short", !Checksum.ppsn("123456T"))

check("entropy separates random from prose",
      Checksum.entropy("wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY") > Checksum.entropy("aaaaaaaaaaaaaaaaaaaa"))

// MARK: - Credential detection

section("Credentials")

expectFinding("AWS access key ID",
              in: "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
              kind: "aws_access_key_id")

expectFinding("AWS secret needs its name nearby",
              in: "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY1",
              kind: "aws_secret_access_key")

expectClean("bare base64 blob is not a secret",
            "The build artifact hash is wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEYZ")

// A quantifier of exactly {40} would match a prefix and leave the tail behind,
// producing text that looks redacted but still carries part of the key.
let longSecret = "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY1234"
let longSecretRedacted = Redactor.redact(longSecret, findings: DetectionEngine.standard.scan(longSecret))
check("over-length secret is consumed whole, no residue",
      !longSecretRedacted.contains("1234") && !longSecretRedacted.contains("EXAMPLEKEY"))

expectFinding("Anthropic key",
              in: "ANTHROPIC_API_KEY=sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAA",
              kind: "anthropic_key")

expectFinding("GitHub PAT",
              in: "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
              kind: "github_token")

// Assembled at runtime rather than written as a literal. GitHub's push
// protection flags a well-formed Slack token even as a test fixture, and a
// repo whose test suite is *made of* credential-shaped strings should not
// require a scanning exception to push, clone or fork. The value the detector
// sees is identical either way.
let slackFixture = "xox" + "b-000000000000-000000000000-ABCDEFGHIJKLMNOP"
expectFinding("Slack bot token", in: slackFixture, kind: "slack_token")

expectFinding("JWT",
              in: "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
              kind: "jwt")

expectFinding("private key block",
              in: "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----",
              kind: "private_key")

expectFinding("assigned password",
              in: "db_password: Tr0ub4dor&3xyz",
              kind: "assigned_secret")

// MARK: - False positives (the failure mode that kills the product)

section("False positives")

expectClean("documentation placeholder", "password: <your-password-here>")
expectClean("env example placeholder", "API_KEY=your_api_key")
expectClean("repeated character filler", "password: xxxxxxxxxxxx")
expectClean("ordinary prose", "Can you review this function and explain what it does?")
expectClean("order reference that is not Luhn-valid", "Order number 1234567890123456 shipped today.")
expectClean("version numbers and dates", "Released 2024.11.03, build 8817263, up from 8817001.")
expectClean("stack trace", """
    Thread 0 crashed at 0x00007ff8106a2e1a in libsystem_kernel.dylib
    at RootViewController.swift:142
    """)

// MARK: - Personal data

section("Personal data")

expectFinding("IBAN in a sentence",
              in: "Please transfer to GB82 WEST 1234 5698 7654 32 by Friday.",
              kind: "iban")

expectFinding("card number",
              in: "Customer card 4111 1111 1111 1111 exp 04/28",
              kind: "card_number")

expectFinding("PPSN",
              in: "Employee PPSN 1234567T starts Monday.",
              kind: "ppsn")

expectFinding("email address",
              in: "Escalate to aoife.murphy@example.ie please.",
              kind: "email")

expectFinding("Irish mobile",
              in: "Call him on 086 123 4567 after five.",
              kind: "irish_mobile")

// MARK: - Redaction

section("Redaction")

let ticket = """
Customer Aoife Murphy (aoife.murphy@example.ie, 086 123 4567) disputes a charge
on card 4111 1111 1111 1111. Refund to GB82 WEST 1234 5698 7654 32.
Our deploy key is AKIAIOSFODNN7EXAMPLE — check CloudTrail.
"""

let ticketFindings = DetectionEngine.standard.scan(ticket)
let redacted = Redactor.redact(ticket, findings: ticketFindings)

check("redaction removes the card number", !redacted.contains("4111 1111 1111 1111"))
check("redaction keeps last four for identification", redacted.contains("1111"))
check("redaction removes the IBAN", !redacted.contains("GB82 WEST 1234 5698 7654 32"))
check("redaction removes the AWS key", !redacted.contains("AKIAIOSFODNN7EXAMPLE"))
check("redaction removes the email local part", !redacted.contains("aoife.murphy@"))
check("redaction keeps the email domain for context", redacted.contains("@example.ie"))
check("redaction preserves surrounding prose", redacted.contains("disputes a charge"))
check("redaction preserves the customer's question", redacted.contains("check CloudTrail"))

// A weaker finding that merely starts earlier must never claim a span ahead
// of a stronger finding that overlaps it — a location-first sort (an earlier
// version of resolveOverlaps used one) would silently drop the critical
// finding in favour of whichever one happened to start first.
let overlapCandidates = [
    Finding(kind: "weak", label: "Weak", severity: .medium,
            nsRange: NSRange(location: 0, length: 10), matched: "", replacement: "[WEAK]"),
    Finding(kind: "strong", label: "Strong", severity: .critical,
            nsRange: NSRange(location: 5, length: 10), matched: "", replacement: "[STRONG]"),
]
let overlapResolved = Finding.resolveOverlaps(overlapCandidates)
check("stronger overlapping finding wins over an earlier-starting weaker one",
      overlapResolved.count == 1 && overlapResolved[0].kind == "strong")

// Overlap safety: a card number is also a long digit run. Two detectors must
// never both replace the same characters.
let overlapping = DetectionEngine.standard.scan("card 4111 1111 1111 1111 here")
check("no overlapping ranges survive resolution", {
    let sorted = overlapping.sorted { $0.nsRange.location < $1.nsRange.location }
    for (a, b) in zip(sorted, sorted.dropFirst()) {
        if a.nsRange.location + a.nsRange.length > b.nsRange.location { return false }
    }
    return true
}())

// Emoji before a finding shifts UTF-16 offsets — the reason redaction uses
// NSMutableString rather than String.Index arithmetic.
let emojiText = "🔐🔐 secret is AKIAIOSFODNN7EXAMPLE ok"
let emojiRedacted = Redactor.redact(emojiText, findings: DetectionEngine.standard.scan(emojiText))
check("redaction survives emoji offsets", !emojiRedacted.contains("AKIAIOSFODNN7EXAMPLE"))
check("redaction keeps text after an emoji intact", emojiRedacted.hasSuffix(" ok"))

// MARK: - Performance guard

section("Performance")

let bulk = String(repeating: "Ordinary log line with no secrets in it at all.\n", count: 6000)
let started = Date()
_ = DetectionEngine.standard.scan(bulk)
let elapsed = Date().timeIntervalSince(started)
// The event tap is disabled by macOS if the callback overruns; the real
// budget is well under a second, so this is a generous ceiling that still
// catches catastrophic regex backtracking.
check("large paste scans within the tap budget (\(String(format: "%.3f", elapsed))s)", elapsed < 0.5)

// MARK: - Summary

print("\n\(passed) passed, \(failed) failed")
exit(failed == 0 ? 0 : 1)
