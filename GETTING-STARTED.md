# Getting started: use this package with your own mailbox

This repository is a **self-hosted, privacy-first** toolkit. You can use the full package with your own Gmail and/or Outlook account — one mailbox or several — without running a mail server and without sending mail to any external storage.

The package never signs in to a mailbox, never opens links or attachments, and never applies a filter or block for you. You review messages, run the local analyzer on headers and other signals, and then apply filters or blocked-sender entries yourself in Gmail or Outlook.

Public files in this repository hold only abstracted detection signals and a small redacted corpus. Your names, addresses, and mailbox list stay in gitignored local config on your machine.

## 1. Get the package

You need [Node.js 20 or newer](https://nodejs.org/). There are no other dependencies.

**Option A — fork or clone** (best if you want updates and may contribute signals back):

```bash
git clone https://github.com/miixms99/mailshield.git
cd mailshield
```

If you work from a fork, add the upstream remote so you can pull rule updates later:

```bash
git remote add upstream https://github.com/miixms99/mailshield.git
```

**Option B — download** a ZIP from the repository's Code button and extract it. You can re-download later to pick up new rules, or switch to a clone when you want `git pull`.

On Windows, the same commands work in PowerShell. Where this guide shows `scripts/…`, you can write `scripts\…`.

Run the offline tests once, from the repository root, to confirm the checkout is healthy:

```bash
node scripts/run-tests.cjs
```

## 2. Configure your accounts and private identifiers

Both files below are optional, copied from examples, and **must not be committed**. They must never contain passwords, OAuth tokens, API keys, or session cookies. This package does not need those secrets.

### Mailboxes you manage

```bash
cp config/accounts.example.json config/accounts.json
```

Edit the labels and providers. You may list several Gmail accounts and several Outlook accounts. Use a short label such as `Personal Gmail`, never an email address.

```bash
node scripts/accounts.cjs --check
node scripts/accounts.cjs --list
```

`config/accounts.json` is gitignored. It is only a local checklist of which mailboxes you review; the analyzer does not log in with it.

### Names used for redaction

If you add redacted corpus samples, or want local privacy checks to look for your own identifiers, copy the identifiers example and put **your** names and addresses there:

```bash
cp config/private-identifiers.example.json config/private-identifiers.json
```

This file is gitignored and is never included in exports or pull requests. If it is missing, the analyzer and tests still run; only adding corpus samples requires it.

## 3. Analyze a message locally

The analyzer is observe-only. It reads a JSON object you give it (headers, addresses, visible text, link hosts, attachment types). It never visits URLs and never touches a mailbox.

1. Open the message in Gmail or Outlook. Copy the headers (Gmail: Show original; Outlook: View message source / internet headers) and the visible From, subject, and link destinations. Do not open suspicious links or attachments.
2. Build a small JSON file, or use `node scripts/Controle-Email.cjs --extract` if you already have a provider message object from a mailbox tool you control.
3. Run the analyzer with the rules from this checkout:

```bash
node scripts/Controle-Email.cjs --analyze < message.json
```

Minimal input (repository rules):

```json
{
  "useBundledRules": true,
  "messages": [
    {
      "mailbox": "Gmail",
      "messageId": "local-1",
      "fromAddress": "sender@example.com",
      "displayName": "Example",
      "subject": "",
      "text": "",
      "urls": [],
      "headers": [
        {
          "name": "Authentication-Results",
          "value": "mx.example; spf=pass smtp.mailfrom=example.com"
        }
      ]
    }
  ]
}
```

On Windows PowerShell:

```powershell
Get-Content message.json | node scripts\Controle-Email.cjs --analyze
```

To use the latest published rules instead of the checkout, merge the `campaignRules`, `senderRules` and `signalRules` fields from `node scripts/fetch-rules.cjs` into the input. If the fetch fails, use `node scripts/fetch-rules.cjs --local`.

The result is a set of **review signals**, not a verdict and not permission to change the mailbox. A high-severity match, or a combined weight of at least 4, recommends review. You decide what to do.

Optional enrichment (`node scripts/enrich.cjs`) looks up **domain or host names only** (RDAP age always; URLhaus and Spamhaus DBL only if you set your own keys in the environment). Keys never go in files. See the Enrichment section in [README.md](README.md).

## 4. Apply rules in Gmail (manual)

Do this in the Gmail web interface for each Gmail account you listed. The package cannot create the filters for you.

### Block one sender

1. Open the message.
2. Open the more-actions menu (three dots) and choose **Block** for that exact sender address.
3. Or go to **Settings > See all settings > Filters and Blocked Addresses** and add the address under Blocked addresses.

Block the exact address unless you have carefully reviewed a domain block. Do not block shared providers (for example Google or Microsoft infrastructure).

### Create one filter

1. In the Gmail search box, open the search-options panel.
2. Enter a precise criterion. For the rotating campaign marker, use **Has the words**: `"111.957097"` or `"111-957097"` (include the quotes).
3. Click **Create filter**.
4. Choose **Delete it** (this moves the message to Trash, it does not delete permanently) and create the filter.
5. Gmail may ask you to verify your identity before it saves a new filter. That confirmation has to be done in your browser.

### Optional: import a generated filter file

```bash
node scripts/export-filters.cjs --out-dir export
```

This writes `export/mailFilters.xml` plus a review sheet. The file is optional and may be stale the moment new rules land, so regenerate it after you update the repository.

1. Open **Settings > See all settings > Filters and Blocked Addresses > Import filters**.
2. Choose `mailFilters.xml`.
3. **Review every filter** in the confirmation list. The export only includes campaign markers and repeatedly observed malicious sender domains. It never includes shared infrastructure hosts.
4. Confirm the import. "Delete it" means Trash. You do not have to apply the filters to existing conversations unless you intend to.

See `export/EXPORT-REVIEW.txt` for the full list and the reasons an entry was included or omitted.

## 5. Apply rules in Outlook (manual)

Do this in Outlook on the web, or in classic Outlook desktop, for each Outlook account you listed.

### Block a sender or domain

- **Outlook on the web:** **Settings > Mail > Junk email > Blocked senders and domains**. Add the exact address, or a domain without an `@`.
- **Classic Outlook desktop:** **Home > Junk > Junk Email Options > Blocked Senders**. Some desktop versions can import a plain text list (one domain per line).

### Create a rule

- **Outlook on the web:** **Settings > Mail > Rules > Add new rule**.
- Example: if the subject or body contains `111.957097` or `111-957097`, move the message to **Deleted Items**.

### Optional: use the generated list

`node scripts/export-filters.cjs` also writes `export/outlook-blocked-senders.txt`. It is a reviewable text list of blocked domains and suggested rule wording, not a silent import of Inbox rules. Copy entries only after you have read them.

### Outlook quirk

In the Junk folder, **Delete** can permanently delete a message. Prefer **Block** or **Move to > Deleted Items**. Reporting a message as phishing can also make it disappear from the folder; verify each step.

## 6. Optional: use an AI assistant or the plugin

`plugin/` contains instructions (`email-security-review`) that an assistant can follow to review mail **you** give it access to, using this repository's rules. The assistant must still treat mailbox actions as unauthorized until **you** grant them in that session. Standing cleanup of someone else's mailbox is not a default of this package.

You can also keep using the scripts alone, without an assistant.

## 7. Optional: your own scheduled check

There is no built-in unattended mailbox reader and no mail server. A schedule can only remind you, or run local scripts on data you already exported.

Examples:

- A calendar reminder or Task Scheduler / cron job to review Gmail Spam and Outlook Junk, then record aggregate counts (see below).
- A scheduled `node scripts/fetch-rules.cjs` or `git fetch` so you notice upstream rule updates.
- If you already export messages to JSON with a tool you control, schedule `node scripts/Controle-Email.cjs --analyze` on that file.

Never put mailbox passwords or tokens in a scheduled command line, a committed script, or this repository.

After a check, record **totals only** (no addresses or subjects):

```bash
node scripts/stats.cjs --file stats/local-stats.json --record run.json --no-render
```

`run.json` looks like `{"gmail":{"mailsChecked":3,"spam":2,"phishing":1,"sendersBlocked":3,"movedToTrash":3}}`. Fields are listed in [CONTRIBUTING.md](CONTRIBUTING.md).

## 8. Keep the rules up to date

The detection rules live in `rules/filter-rules.json` on the `main` branch of this project.

If you cloned or forked the repository:

```bash
git fetch upstream
git merge upstream/main
# or: git rebase upstream/main
node scripts/run-tests.cjs
```

If you only have a fork remote named `origin` and no local changes, `git pull` from your fork after you have synced it with upstream (GitHub: **Sync fork**). If you downloaded a ZIP, download a fresh copy, or convert the folder into a git clone.

Then regenerate any imported filter files and review the diff before changing Gmail or Outlook. Do not force-push, and do not push directly to `main` on the public repository.

If you keep local rule experiments, put them on a branch and merge upstream carefully so your changes are not overwritten.

## 9. Keep your own stats separate

The public [Project status](README.md#project-status) block in this repository is the **project's** aggregate history. It is not your mailbox.

For personal counts, create a gitignored local file (this does not touch the public `stats/stats.json` or the README):

```bash
node scripts/stats.cjs --init-local
# writes stats/local-stats.json
node scripts/stats.cjs --file stats/local-stats.json --record run.json --no-render
```

To start that local file over:

```bash
node scripts/stats.cjs --file stats/local-stats.json --reset --yes
```

`--reset --yes` without `--file` zeros the public `stats/stats.json`. Use that only in a private clone that you will not send back as a pull request. Do not open a pull request that resets or replaces the public project status with your own numbers.

You can also point `ESF_STATS_FILE` at your local stats path. Recording to a local file skips README rendering unless you explicitly pass `--force-render` on a clone that you keep only for yourself.

## 10. Contribute signals back (no personal data)

Anyone may [open an issue](https://github.com/miixms99/mailshield/issues/new/choose) or a pull request. Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

Share only abstracted signals: a lure-phrase type, a sender-address *shape*, a lookalike domain style, a campaign marker, a path pattern. Never paste real mail, names, your addresses, raw headers with recipient data, message IDs, or tracking links. Redact with placeholders such as `[NAME]`, `[EMAIL]`, and `[TOKEN]`.

If you add a redacted corpus sample, use `node scripts/corpus.cjs --add` with your local `config/private-identifiers.json`, review the file, run the tests, and keep identifiers out of the commit.

## What this package will not do

- It will not connect to Gmail, Outlook, or any mail server by itself.
- It will not store mail, credentials, or identifiers outside your machine (and the gitignored local files you choose to create).
- It will not classify a message as a final verdict or take a mailbox action automatically (`automaticMailboxActions` is false).
- It will not tell you to block shared infrastructure.

---

## Kort in het Nederlands

Je kunt dit hele pakket zelf gebruiken voor je eigen Gmail- en/of Outlook-account(s). Er is geen mailserver en geen externe opslag. Het pakket logt niet in op je mailbox; jij bekijkt berichten, draait de analyzer lokaal op headers en signalen, en zet filters of geblokkeerde afzenders zelf in Gmail of Outlook.

1. Fork, clone of download de repository en installeer Node.js 20 of nieuwer. Draai `node scripts/run-tests.cjs`.
2. Kopieer `config/accounts.example.json` naar het gitignored bestand `config/accounts.json` en zet daar alleen labels en providers in, geen e-mailadressen, wachtwoorden of tokens. Voor redactie kopieer je ook `config/private-identifiers.example.json`.
3. Analyseer een bericht met `node scripts/Controle-Email.cjs --analyze < message.json`. De output zijn reviewsignalen, geen automatisch oordeel.
4. Zet regels handmatig in Gmail (filters, afzender blokkeren) en Outlook (regels, geblokkeerde afzenders). Optioneel genereer je een importbestand met `node scripts/export-filters.cjs` en beoordeel je elke regel vóór import. In Outlook Junk kan Verwijderen definitief wissen; gebruik liever Blokkeren of Verplaatsen naar Verwijderde items.
5. Werk regels bij met `git fetch upstream` en `git merge upstream/main` (of Sync fork), of download een nieuwe ZIP.
6. Houd je eigen tellingen apart: `node scripts/stats.cjs --init-local` schrijft `stats/local-stats.json`. Stuur die cijfers niet terug in een pull request naar het publieke project.
7. Meld nieuwe signalen via een issue of pull request, zonder persoonsgegevens of echte mailinhoud. Zie [CONTRIBUTING.md](CONTRIBUTING.md).
