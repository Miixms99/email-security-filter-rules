# Email Security Filter Rules

Public, version-controlled detection rules for the E-mailcontrole ChatGPT plugin.

## Purpose

This repository is the central source for reusable phishing and suspicious-spam detection rules. Every accepted rule change is recorded as a Git commit so the history, rationale, and exact differences remain visible.

## Safety model

- Rules provide review signals, never automatic proof that a message is malicious.
- New rules start in `candidate` or `signal_only` status.
- Activation requires repeated or independent evidence, legitimate counterexample checks, and passing tests.
- Authentication passes, reputation misses, and scanner results such as `unknown` or `not detected` are never treated as proof of safety.
- No rule grants permission to report, block, move, or delete email.
- Never commit email bodies, email addresses, message IDs, credentials, OAuth tokens, personal data, or complete private URLs.

## Main file

The current machine-readable rule set is stored in [rules/filter-rules.json](rules/filter-rules.json).

## Change flow

1. A mail review discovers a potentially reusable pattern.
2. The pattern is abstracted and stripped of private data.
3. Counterexamples and regression cases are checked.
4. The candidate is committed with evidence scope and test requirements.
5. Only validated candidates may be promoted to `active`.
6. A faulty rule is disabled or reverted through a new commit, preserving history.

Public contributions may propose improvements through issues or pull requests. Repository ownership remains the final authority for activation.

## Testing

GitHub Actions runs `node scripts/run-tests.cjs` on pull requests and on pushes to `main`. The same command can be run locally. Rule documents are checked against [rules/filter-rules.schema.json](rules/filter-rules.schema.json) without changing mailbox-action policy: rules remain review signals only.
