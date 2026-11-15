# Email Security Filter Rules

Signal-only phishing and spam detection rules plus a local, observe-only analyzer
that you can use with your own Gmail and Outlook accounts (one or several). The
repository is public: it holds abstracted signals and a small redacted corpus of
clear phishing/spam excerpts (see [Corpus](#corpus)), never full emails or personal data.

*Maintained by Grok Bot (Email Security agent): the daily spam-check routine proposes new signals through pull requests, which are merged after CI passes.*

## Use it for your own mailbox

You can run this whole package against your own Gmail and/or Outlook account, or
several accounts, without a mail server and without external storage. Nothing in
this repository logs into a mailbox or stores mail off your machine. You review
messages, run the analyzer on headers and signals, and apply filters or blocks
yourself.

The [Getting started / self-hosting guide](GETTING-STARTED.md) covers install,
multi-account config, analyzing a message, step-by-step Gmail and Outlook
filters, an optional filter-export file, keeping rules up to date from upstream,
keeping your own stats separate, and contributing signals without personal data.
A short Dutch summary is at the end of that guide.

<!-- STATS:START -->
## Project status

Updated automatically by Grok Bot after every daily spam check. Totals below are aggregate counts only (no addresses, subjects or personal data), since 14 November 2026. Mail-handling figures are lower bounds: only verified, classified mail is included.

![Mails checked](https://img.shields.io/badge/Mails%20checked-29-0a66c2) ![Phishing caught](https://img.shields.io/badge/Phishing%20caught-7-c41e3a) ![Spam removed](https://img.shields.io/badge/Spam%20removed-22-d97706) ![Senders blocked](https://img.shields.io/badge/Senders%20blocked-19-4b5563) ![Domains blocked](https://img.shields.io/badge/Domains%20blocked-4-4b5563) ![Detection rules](https://img.shields.io/badge/Detection%20rules-41-0f766e)

| | Count |
| --- | ---: |
| Mails checked | 29 |
| Phishing caught | 7 |
| Spam removed | 22 |
| Senders blocked | 19 |
| Domains blocked | 4 |
| Detection rules | 41 |
| Corpus samples | 19 |
| Rules revision | 2026-11-15.3 |
| Last check | 15 November 2026, 13:02 Europe/Amsterdam |

| Provider | Checked | Phishing | Spam | Senders blocked |
| --- | ---: | ---: | ---: | ---: |
| Gmail | 15 | 7 | 8 | 15 |
| Outlook | 14 | 0 | 14 | 4 |
<!-- STATS:END -->

## Questions, ideas and problems

Anyone can [open an issue](https://github.com/miixms99/email-security-filter-rules/issues/new/choose) to report a bug, propose an idea or a new detection signal, or ask a question. Please read [CONTRIBUTING.md](CONTRIBUTING.md) first: never paste real email content or personal data.

Grok Bot reviews every issue and decides what to do: accept it, ask for more information, or close it with a reason.

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
| Redaction | `scripts/redact.cjs` | Removes names, addresses, phone numbers, IBAN/card numbers, IDs, long digit runs, times, IPs, street addresses/postcodes, greetings with names, URL queries and tracking tokens, and invisible characters before text may enter the corpus. |
| Corpus | `corpus/`, `scripts/corpus.cjs` | Redacted phishing/spam/ad samples (`corpus/sample.schema.json`), privacy scan and offline detection evaluation. |
| Project status | `stats/stats.json`, `scripts/stats.cjs` | Public aggregate counts (mails checked, phishing, spam, blocks) and the README status block. No addresses or personal data. Self-hosters keep their own counts in the gitignored `stats/local-stats.json` (`--init-local`). |
| Self-hosting | `GETTING-STARTED.md`, `config/accounts.example.json`, `scripts/accounts.cjs` | Guide and optional local mailbox list (labels and providers only; the real `config/accounts.json` is gitignored). |
| Filter export | `scripts/export-filters.cjs` | Optional, reviewable Gmail `mailFilters.xml` and Outlook blocked-senders list from current domain and marker signals. Nothing is applied automatically. |
| Tests | `tests/`, `scripts/run-tests.cjs` | Offline, synthetic-only test suite run by CI. |

### Rule routing

`runtimeRuleSet(document)` uses only rules with status `signal_only` or `active`:

- **Campaign rules**: `markers` or `urlParameters` plus `exactPaths`. They match only when a marker or parameter and an exact path appear in the same message. `hosts` are supporting context only and are reported as `supportingHosts`.
- **Sender rules**: `senderDomains` (exact domain or subdomain) or `senderAddressRegex` (anchored, length-limited patterns without nested quantifiers or backreferences).
- **Signal rules**: everything else. A signal rule is evaluated automatically only when it names an `evaluator`. Otherwise the analyzer lists it under `centralRules.manualReviewOnly` and the assistant applies it during review.

Signal matches carry their severity weight (low 1, medium 2, high 4). A high-severity match, or a combined weight of at least 4, recommends review. No rule classifies a message or performs a mailbox action.

## Rules (revision 2026-11-15.3)

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
| `social.gambling-casino-lures.v1` | social_engineering | medium | `text_phrases` |
| `obfuscation.letter-for-digit-amount.v1` | obfuscation | medium | `letter_for_digit_amount` |
| `campaign.lucky-boom-outlet-sender.v1` | campaign_correlation | high | `display_name_and_local_part` |
| `obfuscation.hyphen-leading-domain-label.v1` | obfuscation | high | sender matcher |
| `obfuscation.random-alnum-sender-shape.v1` | obfuscation | medium | sender matcher |
| `identity.retailer-brand-local-part.v1` | identity | high | `impersonation_local_part_unrelated_domain` |
| `social.spinkong-vip-sender.v1` | social_engineering | high | sender matcher |
| `identity.cjib-impersonation-unrelated-domain.v1` | identity | high | `impersonation_local_part_unrelated_domain` |

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

### Content and campaign signals

- **Gambling or casino lures**: promotional phrases such as "free spins", "first deposit bonus", "rakeback" or "welcome pack of". Ordinary invoices and retail cashback without these phrases are counterexamples.
- **Letter-for-digit amounts**: a lookalike letter used as a digit in a money amount or number token, often only in the subject (`€1,25O`, `2OO`). Highway names such as I-95 are not flagged; I or l count only next to a currency marker.
- **Lucky Boom / `outlet@` or `appliancebillow@`**: the display name "Lucky Boom" with local-part `outlet` or `appliancebillow` on rotating domains (observed examples include `ravenstone.pro`, `buyharbor.me`, `campaignharbor.info`, `northforge.rent` and other listed single-purpose domains). Those domains are also listed on `campaign.repeated-malicious-sender-domain.v1`.
- **Rotating campaign marker `111.957097` / `111-957097`**: seven-letter local-part plus the marker, at an eight-letter label plus a word label under `.biz`, `.biz.id`, `.my.id`, `.web.id` or `.us`.
- **Hyphen-leading domain labels**: a sender domain label that starts with one or more hyphens (invalid as an ordinary DNS label), including hyphen-padded mail labels and long random labels.
- **Random alphanumeric sender shape**: an eight-character alphanumeric local-part at a 28-to-32-character alphanumeric `.com` domain.
- **Retailer brand as local-part**: local-parts such as `walmart`, `bestbuy`, `samsclub` or `costco` on a domain that is not the brand's genuine domain. A genuine newsletter at the brand domain is a counterexample.
- **SpinKong VIP sender**: local-part in the `spinkong-vip-` shape at a hyphen-leading bonuses or vip domain.
- **CJIB impersonation**: a `cjib-nietantwoorden-referentie-` local-part on a domain that is not `cjib.nl`. Mail from `cjib.nl` itself is a counterexample.

### Enrichment (optional, network)

`scripts/enrich.cjs` reads the same `{messages:[...]}` input and sends **domain or host names only** (never addresses, paths or content):

| Source | Signal | Needs | When missing |
| --- | --- | --- | --- |
| [RDAP](https://about.rdap.org/) via `rdap.org` | Domain registered at most 30 days ago | nothing | n/a (some TLDs have no RDAP: result `unknown`) |
| [URLhaus](https://urlhaus.abuse.ch/api/) host lookup | Link host distributes malware | `URLHAUS_AUTH_KEY` (free abuse.ch Auth-Key) | inactive |
| [Spamhaus DBL](https://www.spamhaus.com/data-access/) via DQS | Sender or link domain listed (`127.0.1.x`) | `SPAMHAUS_DQS_KEY` | inactive |
| First-contact history | Unknown sender domain claiming a brand | `EMAILCONTROL_DATA_DIR` | inactive |

- **Spamhaus:** a free DQS account requires your own mail server, so `domain.spamhaus-dbl.v1` stays inactive until you set `SPAMHAUS_DQS_KEY`. Answers in `127.255.255.x` (public resolver, typo, rate limit) are treated as errors and never as listings. The public `dbl.spamhaus.org` zone is not used, because it refuses public resolvers.
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
| Add corpus samples | `node scripts/corpus.cjs --add < raw.json` | `Get-Content raw.json \| node scripts\corpus.cjs --add` |
| Corpus privacy check | `node scripts/corpus.cjs --check` | `node scripts\corpus.cjs --check` |
| Corpus detection report | `node scripts/corpus.cjs --evaluate` | `node scripts\corpus.cjs --evaluate` |
| Record a spam-check run | `node scripts/stats.cjs --record run.json` | `node scripts\stats.cjs --record run.json` |
| Refresh README status | `node scripts/stats.cjs --render` | `node scripts\stats.cjs --render` |
| Check README status sync | `node scripts/stats.cjs --render --check` | `node scripts\stats.cjs --render --check` |
| Init local (private) stats | `node scripts/stats.cjs --init-local` | `node scripts\stats.cjs --init-local` |
| Record to a local stats file | `node scripts/stats.cjs --file stats/local-stats.json --record run.json --no-render` | `node scripts\stats.cjs --file stats\local-stats.json --record run.json --no-render` |
| Validate / list local accounts | `node scripts/accounts.cjs --check` / `--list` | `node scripts\accounts.cjs --check` / `--list` |
| Export optional Gmail/Outlook filters | `node scripts/export-filters.cjs --out-dir export` | `node scripts\export-filters.cjs --out-dir export` |

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

Local, gitignored configuration (never commit these, and never put secrets in them):

| File | Purpose |
| --- | --- |
| `config/accounts.json` | Optional list of Gmail and Outlook mailboxes you manage (labels and providers only). Copy `config/accounts.example.json`. |
| `config/private-identifiers.json` | Optional names and addresses used only for local redaction and privacy tests. Copy `config/private-identifiers.example.json`. |
| `stats/local-stats.json` | Optional personal aggregate counts. Create with `node scripts/stats.cjs --init-local`. |

## Privacy and safety policy

- Signal-only: rules give review signals, never proof, verdicts or permission for mailbox actions (`automaticMailboxActions: false`).
- Authentication failures alone never block; passes, feed misses and scanner "not detected" never prove safety.
- Never commit full email bodies, recipient addresses, message IDs, credentials, tokens, screenshots or complete private URLs. The validator scans the rule document for addresses, message IDs and secrets.
- The only mail text in the repository is the redacted corpus: short excerpts of clear phishing, spam or ads, with no personal data (see [Corpus](#corpus)).
- No external storage: rules live in this repository, and the cache and private state stay on the local machine.
- The analyzer never opens links, attachments or unsubscribe URLs. See `SECURITY.md`.

## Corpus

**Purpose.** `corpus/` holds short, redacted excerpts of clear phishing, spam and unwanted ads seen in reviewed mailboxes. It shows how lures are phrased and built (brand spoofing, urgency, fake account details, hash-buster filler, invisible preheader padding, campaign link paths), and it is a regression set: `tests/corpus-detection.test.cjs` re-runs the analyzer on every sample and fails if a recorded rule match disappears. `node scripts/corpus.cjs --evaluate` prints the detection rate per category.

**Sample format** (`corpus/sample.schema.json`, one JSON file per sample): random `id`, `category` (`phishing` / `spam` / `ad`), `provider` (`gmail` / `outlook`), `receivedDate` (date only), the spammer's or advertiser's own `senderAddress`, redacted `senderDisplayName` and `subject`, `lureSnippets` (redacted, about 600 characters in total), `linkHostsAndPaths` (scheme, host and path only), `attachmentTypes`, `matchedRuleIds` (offline analyzer result when added), `notes` and the names of the `redactionApplied` categories. Full bodies, headers with recipient data, message IDs and exact times are never stored.

**Redaction** (`scripts/redact.cjs`) replaces, in this order: invisible/zero-width characters (removed and counted), URL queries, fragments and opaque tracking path segments (`[TOKEN]`), every email address except the sender's own (`[EMAIL]`, also percent-encoded forms), names and handles from `config/private-identifiers.json` (`[NAME]`), greetings with a name (`Hi [NAME],`), exact times (`[TIME]`), IP addresses (`[IP]`), IBANs (`[IBAN]`), Luhn-valid card numbers (`[CARD]`), phone numbers (`[PHONE]`), street addresses and postcodes (`[ADDRESS]`, `[POSTCODE]`), labelled account/order/reference IDs, mixed alphanumeric IDs and digit runs of six or more (`[ID]`), and long random tokens (`[TOKEN]`). Campaign markers such as `111.957097` are public indicators and are kept.

**Private identifiers** live only in the local, gitignored `config/private-identifiers.json` (format: `config/private-identifiers.example.json`). Adding samples requires that file; it is never committed or included in exports. Each person who adds samples uses their own copy.

**How to add samples.** Read the message through the mailbox connector, select a few lure sentences in memory, and pipe a raw object (`category, provider, receivedDate, senderAddress, senderDisplayName, subject, lureSnippets[], links[], attachmentTypes[], notes`) into `node scripts/corpus.cjs --add`. The script redacts every field, evaluates the sample, runs the privacy scan and refuses to write a sample with findings. Then review each new file by hand, run `node scripts/run-tests.cjs`, and open a pull request. Only clearly malicious or unwanted mail is eligible; never personal or business correspondence. Links and attachments are never opened.

**Privacy guarantees.** `tests/corpus-privacy.test.cjs` validates every sample against the schema and fails on any email address other than `senderAddress`, phone numbers, digit runs of six or more (other than the campaign marker), query strings or fragments, IP addresses, IBAN-like strings or message IDs. This generic check runs everywhere, including CI. When `config/private-identifiers.json` is present locally, the test also fails if any of those names or addresses appears anywhere in the corpus.

## Workflow

To use the package on your own mailboxes, follow [GETTING-STARTED.md](GETTING-STARTED.md). The steps below are how this public repository itself is maintained.

1. **Daily check.** The maintaining assistant reviews configured Gmail Spam, Outlook Junk and recent inbox mail through the providers' web interfaces using the plugin instructions. Mailbox actions (report, block the exact sender, move to Trash) are taken there and verified one by one, and only when the mailbox owner has authorized them.
2. **Signals.** New, abstracted signals (domains, markers, paths, patterns; no content) are added to `rules/filter-rules.json` with a `filterRevision` bump. Clear phishing/spam may also be added to `corpus/` as redacted samples. After the check, `node scripts/stats.cjs --record <json>` adds the run's aggregate counts and `--render` refreshes the public [Project status](#project-status) block. Personal clones should record into `stats/local-stats.json` instead, so they do not overwrite this public block.
3. **Pull request.** The changes go on a branch with a pull request whose title states concretely what changed. Nothing is pushed directly to `main`. The only exception is the repository-owner-triggered `publish-rule.yml` workflow, which commits one reviewed campaign candidate after the full test suite passes.
4. **CI.** `.github/workflows/validate.yml` runs `node scripts/run-tests.cjs` on Node 20 and 22.
5. **Merge.** The pull request is merged only after CI passes. Clients that fetch `main` see the new rules immediately.

## Contributing and the rule gate

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to open an issue or a pull request. In short:

- New rules start as `signal_only` (or `candidate`) and need repeated or independent evidence, a review of legitimate counterexamples, and passing tests (`activationPolicy` in the rule file).
- A machine-evaluated rule must name a built-in `evaluator` and come with synthetic positive and negative tests. The validator rejects rules the analyzer cannot load.
- Rule-only changes bump `filterRevision`. Code or instruction changes also bump `plugin/plugin.json` `version` and the matching line in the plugin skill (checked by tests).
- A faulty rule is disabled or reverted with a new commit, so history is preserved.
- Use descriptive commit and pull-request titles.

See `MAINTENANCE.md` for maintenance details and `PUBLICATION.md` for the reviewed-candidate publication gate.
