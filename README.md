# ubes-media-cleaner

WordPress media audit / cleanup plugin for https://www.ubes.co.uk/.

## Repository layout

- `plugin/` — installable WordPress plugin source.
- `dist/` — packaged WordPress release ZIPs.
- `docs/` — safety, testing and release notes.
- `CHANGELOG.md` — version history.

## Current baseline

The latest source I can verify is **UBES Media Audit v1.0.0**. It performs a conservative scan of the Media Library, normal uploads folders, the WordPress database, active theme and active plugins; files are reviewed and quarantined before permanent deletion.

## Safety rules

- No automatic permanent deletion.
- Candidate means no strong reference was found; it is not proof a file is unused.
- Quarantine first, inspect the live site, then restore or permanently delete.
- Keep external WordPress backups independent of this repository.

## Release workflow

1. Keep the complete installable source in `plugin/`.
2. Make changes and bump the plugin version.
3. Test scan, filtering, bulk actions, quarantine and restore on WordPress.
4. Package as `dist/ubes-media-audit-vX.Y.Z.zip`.

Do not commit WordPress credentials, database dumps, quarantine contents or other secrets.