---
name: trap-defects-py-update-w-replaces-the-evidence-field-it-does-not-append
description: TRAP (0.90.39): tools/defects.py update -w REPLACES a record's evidence; only -a appends (to next). Pass the old evidence plus the new, joined by ' =…
metadata:
  type: feedback
---

`tools/defects.py update <id> -w "<text>"` overwrites the whole evidence field. It looks like an append because the next-step flag has an append form (`-a`), but evidence has none.

Seen 0.90.39: adding the 20 GiB board measurements to D-TAUTH-RECOVERY-SCANS-SCALE-WITH-LUN-SIZE-NOT-LEDGER-USE erased its 1 TB takeover measurement, the sizing pointers and the consult reference. It was restored only because the text was still in this session's context from an earlier `show`.

Do: `tools/defects.py show <id>` first, then pass `-w "<old evidence> ===== <new evidence>"`. Check with `show` afterwards.
