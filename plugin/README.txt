UBES Media Audit
Version 1.3.0

A conservative WordPress admin tool for auditing and cleaning the UBES uploads library.

Main features
- Inventories Media Library items and normal wp-content/uploads media files.
- Finds filesystem-only/orphan files.
- Searches sensible WordPress database locations and active UBES/theme code for references.
- Groups WordPress generated image sizes into the original media family.
- Protects items with strong references from quarantine.
- Reversible quarantine and restore workflow before permanent deletion.
- Filters for Safe candidates, Candidate filesystem orphans, all Candidates, all Filesystem orphans, Used, Keep, Quarantined and Missing.
- Bulk select across ALL pages matching the current filters (not just the visible 50 rows).
- CSV audit export.

Recommended cleanup workflow
1. Run a full scan.
2. Start with "Safe candidates (orphan + zero refs)".
3. Tick the header checkbox. A banner will offer to select every item matching the current filters across all pages.
4. Quarantine the selected batch.
5. Inspect the live website.
6. Restore anything needed, or permanently delete the quarantined batch later.

Important
Candidate status is intentionally conservative but is not an absolute guarantee that a file is unused. Keep a complete external backup before cleanup.


v1.3.0: Added rendered public-site crawl to catch theme/widget/shortcode references, and rescans can now run while files remain quarantined.

== 1.3.1 ==
- Adds native WordPress update support from GitHub Releases.
- WordPress updates only from published release versions, not ordinary source commits.
- The existing conservative quarantine-first Media Audit behaviour is unchanged.
