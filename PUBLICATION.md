# Publication procedure

The current installed plugin has not been changed by this pull request.

1. Review the pull request diff, including privacy checks and all test results.
2. Require successful GitHub Actions on the exact commit to publish.
3. Review Gmail and Outlook coverage separately. A missing provider is incomplete coverage.
4. Merge only the reviewed commit. Package plugin/plugin.json and plugin/skills.
5. Upload to the existing ChatGPT plugin ID; do not create a duplicate plugin.
6. Verify the displayed version and test reading the central rules from a fresh chat.
7. Record the actual published package version and source commit after verification.

A repository commit does not deploy a ChatGPT plugin. There is currently no implemented automated package publication service.

## Learning and synchronization

The plugin is a set of instructions. The script performs deterministic analysis.
Neither trains a model or runs in every chat automatically.

During an email review using this plugin, an assistant can read current GitHub rules,
identify a reusable pattern from Gmail or Outlook, check counterexamples, run tests,
and propose a privacy-safe rule commit. GitHub stores changes and runs tests; it does
not inspect mail or invent rules. A passing test cannot prove a new rule correct.

New candidates stay signal-only. Activation needs evidence and review.
Chats need the plugin and the required tools to use this process.
Without GitHub write access or executable tests, updates remain pending.

## Public source scope

scripts/Controle-Email.cjs contains the local analysis implementation and synthetic tests.
Historical message IDs, source hashes, evidence files, screenshots, register data,
local backup configuration, and the public feed cache are intentionally excluded.
The historical regression command requires a private local harness and is unavailable
in this public build. EMAILCONTROL_DATA_DIR points to private local state when planning.
EMAILCONTROL_CACHE_DIR may select a disposable public-source cache.

## Version policy

Rule-only changes increment filterRevision. Code or interface changes increment the
plugin version. Never claim a package version is deployed solely because it exists
in GitHub. A rollback republishes a verified previous package and reverts rules by commit.


