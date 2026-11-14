# Learning implementation status

## Implemented and tested

- Fetch central public GitHub rules with a timeout and status validation.
- Convert supported campaign rules into the existing analyzer input format.
- Exclude candidate and disabled rules from runtime detection.
- Discover candidate marker/path combinations from at least three reviewed abstractions.
- Reject a combination when a supplied legitimate counterexample matches it.
- Preserve Gmail and Outlook provider coverage in candidate summaries.
- Test rule injection, counterexamples and removal in fresh analyzer processes.

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

