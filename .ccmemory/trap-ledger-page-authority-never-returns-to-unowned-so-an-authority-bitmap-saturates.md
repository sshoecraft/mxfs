---
name: trap-ledger-page-authority-never-returns-to-unowned-so-an-authority-bitmap-saturates
description: TRAP (0.90.39): no code sets a tauth page back to PG_UNOWNED; owned pages only grow, so a "page in use" summary for the orphan/takeover scans saturat…
metadata:
  type: feedback
---

The 2026-10-01 consult (ruling-tauth-ledger-recovery-scan-cost-sparse-summary-first) recommended a sparse occupancy summary so recovery scans read only pages in use. It was told pages hold records; it was NOT told how page AUTHORITY works.

Fact (code read 0.90.39): MXFS_TAUTH_PG_UNOWNED is set only by mkfs. Nothing in dlm/ assigns it again. A page becomes ACTIVE under some node at first touch and stays owned forever, moving between nodes on handoff/takeover. The orphan sweep (dlm.c dlm_orphan_scan_cb) and the node-death takeover select pages by authority, not by records.

Consequence: a summary keyed on records does not shrink those scans; one keyed on "authority present" fills up as the filesystem ages. The 1 TB measurement (live_pages=1) was a FRESH format and understates an aged one.

Before designing the summary: measure owned pages after real workloads (P-TAUTH-ORPHAN-SWEEP live_pages / cand, P-TAUTH-TAKEOVER pages_prepared on the boards), and weigh: returning an empty page's authority to UNOWNED (an activation write per first touch, the D-0349 park cost), a per-node owned-page index, or a population-sized npages. Bring this fact to any consult on the ledger.
