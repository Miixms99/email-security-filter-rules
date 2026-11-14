# Repository Maintenance

## Source of truth

- Plugin source: `plugin/`
- Runtime filter rules: `rules/filter-rules.json`
- Published ChatGPT package version: tracked in `plugin/plugin.json`

## Versioning

- Change the plugin code version only when executable behavior, the plugin interface, or plugin instructions materially change.
- For rule-only changes, keep the code version and increment `filterRevision`.
- Every accepted rule update must be a separate, descriptive commit.
- Keep all repository content in English.

## Publication

A GitHub commit updates the central rules immediately for chats that fetch the repository. A plugin source commit does not by itself publish a new ChatGPT package. Publish the package separately, then commit any publication metadata only after the published version is verified.

## Testing and validation

Run the full offline suite from the repository root:

```bash
node scripts/run-tests.cjs
```

This syntax-checks every `scripts/*.cjs` and `tests/*.cjs` file, validates `rules/filter-rules.json` against `rules/filter-rules.schema.json` (policy flags, unique rule IDs, and a conservative private-data scan; indicator shapes stay open for new rule types), then runs the synthetic analyzer self-test, evaluation, and all test files.

`node scripts/validate-rules.cjs` can be used on its own. Do not add a `$schema` property to `rules/filter-rules.json` unless that document is being intentionally revised; the validator loads the schema file directly.
