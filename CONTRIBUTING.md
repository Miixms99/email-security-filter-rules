# Contributing

Anyone can report a problem, propose an idea, or ask a question in this repository. You do not need to be a developer. If you want to run the full package against your own Gmail or Outlook account(s), start with [GETTING-STARTED.md](GETTING-STARTED.md).

## How to open an issue

Use the issue forms: [Open an issue](https://github.com/miixms99/email-security-filter-rules/issues/new/choose)

Pick the form that fits:

- **Bug in the code** — something is broken, a test fails, or the analyzer behaves wrongly.
- **Idea or new signal** — a detection idea, a new rule, or a way to improve existing signals.
- **Question** — anything else you want to ask about the project.

### What to include

- A short title that says what the issue is about.
- For a bug: what you expected, what actually happened, and how to reproduce it.
- For a new signal: the general pattern (for example a lure phrase type, a sender pattern, or a lookalike domain style), not a real message.
- Use only redacted or made-up (synthetic) examples.

### Privacy rule

Never paste real email content, personal addresses, names, headers with personal data, or tracking links.

Replace names, addresses, IDs and query strings with placeholders such as `[NAME]`, `[EMAIL]`, or `[TOKEN]`. If you accidentally include personal data, tell the repository owner privately. Do not leave it in a public issue. See [SECURITY.md](SECURITY.md).

## How issues are reviewed

Grok Bot maintains this repository (including through daily spam checks) and reviews every issue. It may:

- accept the idea or fix and follow up with a pull request,
- ask for more information, or
- close the issue and explain why.

Rule changes go through pull requests. CI must pass before a pull request is merged. Nothing is pushed directly to `main`.

## For developers

1. Branch from `main`.
2. Keep rules signal-only: they give review signals, never a verdict and never permission to change a mailbox.
3. Run the tests:

   ```bash
   node scripts/run-tests.cjs
   ```

   After a mailbox check, record aggregate counts (no addresses or subjects) and refresh the public status block:

   ```bash
   node scripts/stats.cjs --record run.json
   node scripts/stats.cjs --render
   ```

   `run.json` is a JSON object with optional `gmail` and `outlook` objects whose fields are non-negative integers (`mailsChecked`, `phishing`, `spam`, `uncertain`, `legitimate`, `sendersBlocked`, `domainsBlocked`, `reportedToProvider`, `movedToTrash`). CI fails if the README block between `<!-- STATS:START -->` and `<!-- STATS:END -->` is out of sync with `stats/stats.json`.

4. Open a pull request. The title must say concretely what changed (for example "Add gambling-lure signal and two corpus samples", not "Update rules").
5. Wait for CI on Node 20 and 22. A pull request is merged only after the tests pass.

Do not commit real email, personal addresses, `config/private-identifiers.json`, `config/accounts.json`, or `stats/local-stats.json`. New rules start as `signal_only` (or `candidate`). See the [Corpus](README.md#corpus) and [Contributing and the rule gate](README.md#contributing-and-the-rule-gate) sections in the README, [GETTING-STARTED.md](GETTING-STARTED.md) if you are using the package with your own mailboxes, and [SECURITY.md](SECURITY.md).
