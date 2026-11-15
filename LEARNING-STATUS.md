# Learning implementation status

## Implemented and tested

- Fetch central public GitHub rules with a timeout and status validation.
- Route every enabled rule by indicator shape (`runtimeRuleSet`): campaign rules to the marker/path matcher, sender rules to the sender matcher, others to signal evaluators or the manual-review list.
- Evaluate header signals (Authentication-Results, ARC, DMARC alignment, Microsoft anti-spam) and Unicode confusables.
- Exclude candidate and disabled rules from runtime detection.
- Discover candidate marker/path combinations from at least three reviewed abstractions.
- Reject a combination when a supplied legitimate counterexample matches it.
- Preserve Gmail and Outlook provider coverage in candidate summaries.
- Test rule injection, counterexamples and removal in fresh analyzer processes.
- Optional network enrichment: RDAP domain age; URLhaus host lookups when `URLHAUS_AUTH_KEY` is set (enabled for the maintained daily check with a key stored outside the repo); Spamhaus DBL only when `SPAMHAUS_DQS_KEY` is set (unused by the maintained project).

## Boundaries

The discovery input is an already reviewed public-safe abstraction, not a raw email.
Alphabetic strings can still contain private information: syntax guards do not prove
anonymization. The caller must review privacy before uploading any candidate.
Repeated observations are not independent evidence. Candidates cannot self-certify
publication eligibility. No automatic candidate activation is implemented.

## Not yet implemented or verified

- An unattended mailbox reader that supplies reviewed observations.
- A robust independent-evidence and rule-specific counterexample gate.
- Automatic GitHub candidate submission and publication after that gate.
- An independent ChatGPT/Work chat reading a newly published rule.
- Automatic publication to the ChatGPT plugin Library.

These components must not be described as active. Installing instructions alone
does not implement them. Existing chats may lack the tools required for writes or
tests; such chats must report incomplete synchronization.

