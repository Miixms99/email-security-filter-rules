# Security and Privacy

This repository is public. Do not submit private email content or account data. The only mail text allowed is the redacted corpus in `corpus/` (short excerpts of clear phishing/spam/ads, redacted with `scripts/redact.cjs` and checked by `tests/corpus-privacy.test.cjs`).

## Never include

- Full email bodies or raw message sources
- Personal email addresses or recipient aliases
- Message IDs, account identifiers, or recovery information
- Passwords, OAuth tokens, API keys, cookies, or session data
- Complete private URLs or query strings containing personal values
- Screenshots of private mailboxes

## Allowed evidence

Only generalized, non-personal indicators needed to explain a reusable detection rule, such as an abstract URL-path pattern, authentication mismatch category, or repeated social-engineering structure.

Report accidental disclosure privately to the repository owner. Do not open a public issue containing the exposed value.
