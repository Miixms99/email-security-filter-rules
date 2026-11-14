# E-mailcontrole plugin source synchronization

The file `plugin/emailcontrole/SKILL.md` is a snapshot of the installed E-mailcontrole plugin's available skill instructions, captured on 2026-11-14. It is **not** proof that the plugin's executable helper, build files, package, or deployment credentials are present in this repository.

## Safe workflow

1. Keep detection rules in `rules/filter-rules.json`; do not commit personal email data.
2. Make proposed plugin changes on branches, and run CI plus regression tests.
3. Promote only reviewed, tested changes to the default branch.
4. Publishing an updated ChatGPT plugin requires a supported plugin deployment mechanism, authentication, and post-deployment verification. None is configured by this snapshot.
5. Never claim an installed plugin has been updated solely because GitHub changed.
6. Keep automatic mailbox actions disabled unless separately verified.

## Missing integration

- The executable plugin helper source and deployment manifest, if any.
- A documented supported publisher/upload API or other deployment path.
- Credentials configured as private secrets, never in this public repository.
- Version verification and rollback after deployment.
