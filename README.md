# Email Security Filter Rules

Signal-only phishing and spam detection rules plus a local, observe-only analyzer for
a personal Gmail and Outlook setup. The repository is public: it holds abstracted
signals only, never email content.

*Maintained by Grok Bot (Email Security agent): the daily spam-check routine proposes new signals through pull requests, which are merged after CI passes.*

## How it fits together

| Part | Path | Role |
| --- | --- | --- |
| Central rules | `rules/filter-rules.json` | Machine-readable signal-only rules (source of truth). |
| Rule schema | `rules/filter-rules.schema.json` | Shape and policy checks used by CI. |
| Analyzer | `scripts/Controle-Email.cjs` | Offline analysis of structured message data: URL parsing with the Public Suffix List, OpenPhish exact match, link/identity comparison, campaign, sender and signal rules. Never visits URLs and never touches a mailbox. |
| Signal library | `scripts/signals.cjs` | Header parsing (Authentication-Results, ARC, Microsoft anti-spam), DMARC alignment, Unicode confusables, sender rules and the generic signal-rule evaluators. |
| Rule routing | `scripts/rule-learning.cjs` | `runtimeRuleSet()` routes enabled rules to the analyzer input that can evaluate them; `discover()` proposes campaign candidates from reviewed abstractions. |
| Enrichment | `scripts/enrich.cjs` | Optional network step: RDAP domain age, URLhaus and Spamhaus DBL (only with keys), and the hashed first-contact history. Its output is passed to the analyzer as `enrichment`. |
| Rule loader | `scripts/fetch-rules.cjs` | Fetches the rules from GitHub (or `--local`), validates them like CI and prints analyzer-ready rule sets. |
| Validator | `scripts/validate-rules.cjs` | Schema, policy flags, unique IDs, private-data scan, severity/weight consistency, and a runtime-load check of every enabled rule. |
| Publication gate | `scripts/prepare-publication.cjs`, `scripts/chat-review.cjs` | Reviewed candidate publication (see `PUBLICATION.md`). |
| Plugin | `plugin/` | Assistant instructions (`email-security-review` skill) for the review workflow. |
| Tests | `tests/`, `scripts/run-tests.cjs` | Offline, synthetic-only test suite run by CI. |

### Rule routing

`runtimeRuleSet(document)` uses only rules with status `signal_only` or `active`:

- **Campaign rules**: `markers` or `urlParameters` plus `exactPaths`. They match only when a marker or parameter and an exact path appear in the same message. `hosts` are supporting context only and are reported as `supportingHosts`.
- **Sender rules**: `senderDomains` (exact domain or subdomain) or `senderAddressRegex` (anchored, length-limited patterns without nested quantifiers or backreferences).
- **Signal rules**: everything else. A signal rule is evaluated automatically only when it names an `evaluator`. Otherwise the analyzer lists it under `centralRules.manualReviewOnly` and the assistant applies it during review.

Signal matches carry their severity weight (low 1, medium 2, high 4). A high-severity match, or a combined weight of at least 4, recommends review. No rule classifies a message or performs a mailbox action.

## Rules (revision 2026-11-14.7)

| Rule | Category | Severity | Evaluated by |
| --- | --- | --- | --- |
| `campaign.marker-and-path.v1` | campaign_correlation | high | campaign matcher |
| `campaign.rotating-marker-sender-pattern.v1` | campaign_correlation | high | sender matcher |
| `campaign.fake-cloud-storage-deletion.v1` | social_engineering | high | assistant review |
| `campaign.repeated-malicious-sender-domain.v1` | campaign_correlation | medium | sender matcher |
| `auth.spf-fail-or-softfail.v1` | authentication | low | `auth_result_tokens` |
| `auth.dkim-fail-or-none.v1` | authentication | low | `auth_result_tokens` |
| `auth.dmarc-fail.v1` | authentication | low | `auth_result_tokens` |
| `auth.dmarc-alignment-fail.v1` | authentication | medium | `dmarc_alignment` |
| `auth.ms-compauth-fail.v1` | authentication | medium | `ms_compauth` |
| `auth.missing-or-inconsistent-headers.v1` | authentication | low | `auth_missing_or_inconsistent` |
| `auth.return-path-from-mismatch.v1` | authentication | low | `return_path_mismatch` |
| `provider.ms-verdict.v1` | provider_verdict | medium | `ms_verdict` |
| `identity.unicode-confusable-mixed-script.v1` | identity | medium | `unicode_confusable` |
| `identity.lookalike-homoglyph-typosquat.v1` | identity | medium | assistant review |
| `identity.freemail-brand-display.v1` | identity | medium | assistant review |
| `identity.subdomain-confusion.v1` | identity | medium | assistant review |
| `identity.reply-to-mismatch.v1` | identity | low | `reply_to_mismatch` |
| `identity.hidden-char-brand-spoof.v1` | social_engineering | high | assistant review |
| `identity.brand-impersonation-unrelated-domain-hidden-chars.v1` | identity | high | assistant review |
| `social.credential-phishing-lures.v1` | social_engineering | medium | assistant review |
| `social.urgency-threat-language.v1` | social_engineering | low | assistant review |
| `social.payment-invoice-giftcard-lures.v1` | social_engineering | medium | assistant review |
| `attachment.unexpected-html-zip-iso.v1` | attachment | medium | `attachment_types` |
| `attachment.html-smuggling-or-qr.v1` | attachment | medium | `attachment_types` |
| `attachment.qr-image-bait.v1` | attachment | low | `attachment_qr_bait` |
| `attachment.ics-invite-lure.v1` | attachment | low | `calendar_invite_lure` |
| `domain.newly-registered.v1` | domain_reputation | medium | `domain_age` (needs enrichment) |
| `domain.spamhaus-dbl.v1` | domain_reputation | high | `spamhaus_dbl` (needs enrichment + `SPAMHAUS_DQS_KEY`) |
| `link.urlhaus-listed.v1` | domain_reputation | high | `urlhaus_host` (needs enrichment + `URLHAUS_AUTH_KEY`) |
| `identity.first-contact-brand-claim.v1` | identity | medium | `first_contact_brand` (needs enrichment + `EMAILCONTROL_DATA_DIR`) |
| `link.visible-href-domain-mismatch.v1` | link | medium | `link_visible_mismatch` |
| `link.shortener-or-open-redirect.v1` | link | low | assistant review |
| `link.storage-or-free-host-html.v1` | link | low | `host_html_path` |

A test (`tests/project.test.cjs`) fails if a rule exists in the JSON but is missing from this table.

### Header signals

- **Authentication-Results**: only the topmost header is trusted, because the receiving provider adds it; lower headers can be forged and are only counted. Both RFC 8601 (Gmail, with authserv-id) and Microsoft 365 (without) formats are parsed: `spf`, `dkim` (all signatures), `dmarc` (+ policy), `compauth`, `arc`.
- **DMARC alignment** (relaxed, RFC 7489): the From domain must share its organizational domain with a passing SPF or DKIM domain. This needs a current Public Suffix List; an unknown boundary never matches.
- **Microsoft anti-spam** (`X-Forefront-Antispam-Report`, `X-Microsoft-Antispam`): SCL, BCL, CAT, SFV and SFTY (9.19/9.20 impersonation, 9.25 first contact). See [Microsoft's anti-spam header reference](https://learn.microsoft.com/en-us/defender-office-365/message-headers-eop-mdo).
- **Unicode**: zero-width and bidi characters, mixed Latin/Cyrillic/Greek within one word, mathematical or fullwidth letters, punycode (`xn--`) domains, and a confusable skeleton that spells a listed brand. It uses a compact subset of [UTS #39 confusables](https://www.unicode.org/reports/tr39/).

Header parsing reports what the provider claims; it does not verify signatures.

### Attachment signals

These are judged from filename extension and MIME type only. Attachments are never opened and QR codes are not decoded.

- HTML, SVG or MHT attachments: HTML smuggling.
- Archives, disk images, scripts and macro documents.
- Image or PDF attachments with almost no text and no links: QR-code bait ("quishing").
- Calendar invites (`.ics`) with links to an unrelated domain.

### Enrichment (optional, network)

`scripts/enrich.cjs` reads the same `{messages:[...]}` input and sends **domain or host names only** (never addresses, paths or content):

| Source | Signal | Needs | When missing |
| --- | --- | --- | --- |
| [RDAP](https://about.rdap.org/) via `rdap.org` | Domain registered at most 30 days ago | nothing | n/a (some TLDs have no RDAP: result `unknown`) |
| [URLhaus](https://urlhaus.abuse.ch/api/) host lookup | Link host distributes malware | `URLHAUS_AUTH_KEY` (free abuse.ch Auth-Key) | inactive |
| [Spamhaus DBL](https://www.spamhaus.com/data-access/) via DQS | Sender or link domain listed (`127.0.1.x`) | `SPAMHAUS_DQS_KEY` | inactive |
| First-contact history | Unknown sender domain claiming a brand | `EMAILCONTROL_DATA_DIR` | inactive |

- **Spamhaus:** there is currently no DQS account (a free account requires your own mail server), so `domain.spamhaus-dbl.v1` stays inactive until `SPAMHAUS_DQS_KEY` is set. Answers in `127.255.255.x` (public resolver, typo, rate limit) are treated as errors and never as listings. The public `dbl.spamhaus.org` zone is not used, because it refuses public resolvers.
- **URLhaus:** abuse.ch now requires a free Auth-Key even for the community API, so `link.urlhaus-listed.v1` stays inactive without `URLHAUS_AUTH_KEY`.
- **First contact:** `contact-history.json` contains only HMAC-SHA256 hashes of organizational sender domains, salted with a random local salt. It is written only when the input sets `"recordContacts": true`. Seed it from known legitimate mail first; with an empty history every sender counts as a first contact.
- **Keys:** keys are read from environment variables only and are never written to files, caches or output. Lookups are cached in `enrichment-cache.json` in the cache directory (registration data 7 days, URLhaus 6 hours, DBL 1 hour, errors 30 minutes). `--offline` uses the cache only.

```bash
node scripts/enrich.cjs < messages.json > enrichment.json
# then add  "enrichment": <contents of enrichment.json>  to the analyzer input
```

## Commands

Requires Node.js 20 or newer and no dependencies. Run from the repository root.

| Task | Linux / macOS | Windows (PowerShell) |
| --- | --- | --- |
| Full offline test suite | `node scripts/run-tests.cjs` | `node scripts\run-tests.cjs` |
| Validate rules only | `node scripts/validate-rules.cjs` | `node scripts\validate-rules.cjs` |
| Central rules (GitHub) | `node scripts/fetch-rules.cjs` | `node scripts\fetch-rules.cjs` |
| Repository rules | `node scripts/fetch-rules.cjs --local` | `node scripts\fetch-rules.cjs --local` |
| Refresh public feeds | `node scripts/Controle-Email.cjs --refresh` | `node scripts\Controle-Email.cjs --refresh` |
| Feed status | `node scripts/Controle-Email.cjs --status` | `node scripts\Controle-Email.cjs --status` |
| Analyze JSON from stdin | `node scripts/Controle-Email.cjs --analyze < input.json` | `Get-Content input.json \| node scripts\Controle-Email.cjs --analyze` |
| Enrichment (network) | `node scripts/enrich.cjs < input.json` | `Get-Content input.json \| node scripts\enrich.cjs` |
| Extract a Gmail/Outlook message | `node scripts/Controle-Email.cjs --extract < message.json` | `Get-Content message.json \| node scripts\Controle-Email.cjs --extract` |
| Input formats | `node scripts/Controle-Email.cjs --help` | `node scripts\Controle-Email.cjs --help` |

Minimal analyzer input using the repository rules:

```json
{"useBundledRules": true, "messages": [{"mailbox": "Gmail", "messageId": "local-1",
  "fromAddress": "sender@example.com", "displayName": "Example", "text": "", "urls": [],
  "headers": [{"name": "Authentication-Results", "value": "mx.example; spf=pass smtp.mailfrom=example.com"}]}]}
```

To use the central rules instead, merge the `campaignRules`, `senderRules` and `signalRules` fields from `fetch-rules.cjs` into the input. Messages produced by `--extract` keep their headers and attachment metadata, so they can be passed through as they are.

### Directories

| Variable | Default | Content |
| --- | --- | --- |
| `ESF_CACHE_DIR` (legacy `EMAILCONTROL_CACHE_DIR`) | Linux/macOS: `$XDG_CACHE_HOME/email-security`, else `~/.cache/email-security`. Windows: the `scripts` folder, which must be on `D:` unless the variable is set. | Public feed cache (`publieke-bronnen.json`) and enrichment cache (`enrichment-cache.json`). |
| `EMAILCONTROL_DATA_DIR` | none (required for `--plan` and first contact) | Private local state (`email-register.json`, `email-bewijs.json`, `contact-history.json`). Never commit it. |
| `SPAMHAUS_DQS_KEY` | unset (inactive) | Spamhaus DQS key for `domain.spamhaus-dbl.v1`. |
| `URLHAUS_AUTH_KEY` | unset (inactive) | abuse.ch Auth-Key for `link.urlhaus-listed.v1`. |

Storage paths are confined to their directory: no `..` traversal, no symbolic links or junctions, and a realpath containment check.

## Privacy and safety policy

- Signal-only: rules give review signals, never proof, verdicts or permission for mailbox actions (`automaticMailboxActions: false`).
- Authentication failures alone never block; passes, feed misses and scanner "not detected" never prove safety.
- Never commit email bodies, email addresses, message IDs, credentials, tokens, screenshots or complete private URLs. The validator scans the rule document for addresses, message IDs and secrets.
- No external storage: rules live in this repository, and the cache and private state stay on the local machine.
- The analyzer never opens links, attachments or unsubscribe URLs. See `SECURITY.md`.

## Workflow

1. **Daily check.** The assistant reviews Gmail Spam, Outlook Junk and recent inbox mail through the providers' web interfaces using the plugin instructions. Mailbox actions (report, block the exact sender, move to Trash) are taken there and verified one by one.
2. **Signals.** New, abstracted signals (domains, markers, paths, patterns; no content) are added to `rules/filter-rules.json` with a `filterRevision` bump.
3. **Pull request.** The changes go on a branch with a pull request whose title states concretely what changed. Nothing is pushed directly to `main`. The only exception is the owner-triggered `publish-rule.yml` workflow, which commits one reviewed campaign candidate after the full test suite passes.
4. **CI.** `.github/workflows/validate.yml` runs `node scripts/run-tests.cjs` on Node 20 and 22.
5. **Merge.** The pull request is merged only after CI passes. Clients that fetch `main` see the new rules immediately.

## Contributing and the rule gate

- New rules start as `signal_only` (or `candidate`) and need repeated or independent evidence, a review of legitimate counterexamples, and passing tests (`activationPolicy` in the rule file).
- A machine-evaluated rule must name a built-in `evaluator` and come with synthetic positive and negative tests. The validator rejects rules the analyzer cannot load.
- Rule-only changes bump `filterRevision`. Code or instruction changes also bump `plugin/plugin.json` `version` and the matching line in the plugin skill (checked by tests).
- A faulty rule is disabled or reverted with a new commit, so history is preserved.
- Use descriptive commit and pull-request titles.

See `MAINTENANCE.md` for maintenance details and `PUBLICATION.md` for the reviewed-candidate publication gate.
