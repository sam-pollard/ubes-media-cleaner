# Media cleanup safety

The Media Audit is intentionally conservative.

- A Candidate is a review state, not proof that a file is unused.
- Strong references protect files from quarantine.
- Weak references should be inspected rather than treated as definitive usage.
- Use quarantine before permanent deletion.
- Check the live site after quarantining a batch and restore anything unexpectedly missing.
- Permanent deletion should only happen after the quarantine test and with an external WordPress backup available.
- Never place quarantine contents or database exports in GitHub.
