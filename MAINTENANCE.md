# Repository Maintenance

## Source of truth

- Plugin source: `plugin/`
- Runtime filter rules: `rules/filter-rules.json`
- Published ChatGPT package version: tracked in `plugin/plugin.json` and repeated in the skill's `Code version` line
- Analyzer: `scripts/Controle-Email.cjs` with `scripts/signals.cjs`; rule routing in `scripts/rule-learning.cjs`

## Versioning

- Change the plugin code version only when executable behavior, the plugin interface, or plugin instructions materially change.
- For rule-only changes, keep the code version and increment `filterRevision`; also update the skill's `Bundled filter revision` line and the README rule table (tests enforce both).
- Every accepted rule update must be a separate commit whose title states concretely what changed (no generic "Rules <revision>" titles). The same applies to pull-request titles.
- Keep all repository content in English. The one exception is the short Dutch summary at the end of `GETTING-STARTED.md`.

## Publication

A GitHub commit updates the central rules immediately for chats that fetch the repository. A plugin source commit does not by itself publish a new ChatGPT package. Publish the package separately, then commit any publication metadata only after the published version is verified.

## Testing and validation

Run the full offline suite from the repository root:

```bash
node scripts/run-tests.cjs
```

This syntax-checks every `scripts/*.cjs` and `tests/*.cjs` file (including `scripts/accounts.cjs` and `scripts/export-filters.cjs`), validates `rules/filter-rules.json` against `rules/filter-rules.schema.json` (policy flags, unique rule IDs, a conservative private-data scan, severity/weight consistency, and a runtime-load check that routes every enabled rule through `runtimeRuleSet()` and the analyzer normalizers), then runs the synthetic analyzer self-test (which loads the real campaign rules), evaluation, and all test files, and checks that the README project status block matches `stats/stats.json`. Shared synthetic fixtures live in `tests/helpers/` and are not run as tests.

Public handling totals live in `stats/stats.json` (schema `stats/stats.schema.json`). After each mailbox check, record the run and refresh the README section:

```bash
node scripts/stats.cjs --record run.json
node scripts/stats.cjs --render
```

Counts are aggregates only: never put addresses, subjects or personal data in `stats/stats.json` or the README block. People running a private clone should record into `stats/local-stats.json` (`node scripts/stats.cjs --init-local`) and must not send a pull request that resets or replaces the public project status with their own numbers.

## Adding a machine-evaluated rule

1. Give the rule an indicator shape the router understands (campaign, sender) or an `evaluator` from `EVALUATORS` in `scripts/signals.cjs`.
2. Add synthetic positive and negative cases to `tests/runtime-rules.test.cjs` or `tests/signals.test.cjs` (example domains only).
3. Add the rule to the README table and bump `filterRevision`.

`node scripts/validate-rules.cjs` can be used on its own. Do not add a `$schema` property to `rules/filter-rules.json` unless that document is being intentionally revised; the validator loads the schema file directly.
