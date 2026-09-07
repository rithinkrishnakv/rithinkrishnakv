# Cyber Daily archive

One line of JSON per day, appended automatically by
`.github/workflows/update-cyberdaily.yml` (see `scripts/generate_cyberdaily.py`).

Each line has the shape:

```json
{"date": "YYYY-MM-DD", "cves": [{"id": "...", "label": "...", "url": "..."}], "threat": {"label": "...", "url": "..."}, "research": {"label": "...", "url": "..."}, "tool": {"label": "...", "url": "..."}}
```

A category is `null` for a given day if that source couldn't be reached or had
nothing new — items are never invented to fill a gap.

The file is capped at the most recent 365 entries (`ARCHIVE_MAX_LINES` in the
script); older lines roll off automatically so this stays lightweight
indefinitely.
