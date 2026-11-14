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
