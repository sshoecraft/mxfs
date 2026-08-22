---
name: scst-overflow-contaminates-32node-evidence-and-flood-swallowed-warnings
description: The SCST PR overflow was damaging clyde for 2+ days before the wedge, and the trace flood swallowed its own warnings — so 32-node MXFS defect evidenc…
metadata:
  type: project
tags: [scst, clyde, rule6, evidence-integrity, open-defects, 32-node, contamination]
---

Follow-on to `scst-pr-overflow-caused-BOTH-clyde-wedges-jbd2-and-pagetable`.

## 1. The damage started days before the wedge

The jbd2 `bh->b_state` corruption oops in the wedge-A pstore record carries
monotonic timestamp **[512208]**, while the SCST trace lines at the end of the
same record are **[595040]** — ~83,000 s ≈ **23 hours apart**. That boot had
~6.9 days of uptime. So the buffer_head corruption happened around
**2026-08-19 20:23** (matching the record's file mtime) and the host then ran
for another day, reaching **Oops #9** by the 08-20 19:24 wedge. It was already
`Tainted: G D W` at oops #3.

**This host was silently corrupting kernel memory for at least two days.**

## 2. The flood swallowed the overflow's own warnings

The preserved wedge-A journal has **zero** `Too big response data len` lines,
yet the corruption demonstrably happened in that boot. In the count==1 SG case
`buffer_size == cmd->bufflen`, so every overflow SHOULD print. Most likely the
182 lines/s trace flood overwrote them in the kmsg ring before journald read
them — the same flood also filled the 40 MB corrupted journal tail and the
716 KB ERST buffer with nothing but `scst_check_scsi_atomicity`.

**Consequence: absence of that printk is NOT evidence the overflow did not
occur.** Only the wedge-B boot (quiet log) shows all three.

## 3. Therefore 32-node MXFS evidence from that window is SUSPECT

The overflow writes 400-928 bytes of TransportID text into whatever page
follows an SCSI command's data page. Observed victims: a `struct buffer_head`
(08-19) and a live QEMU page-table page (08-21). **Nothing prevents the
neighbour from being another SCSI command's data buffer** — i.e. data in
flight to or from the shared LUN. It could fabricate exactly the class of
FS-level corruption the campaign has been chasing.

Precedent for how to treat this: the sess137 GPT ruling on the SCST fileio
bvec UAF — *"timing/perf and error-rate evidence from before the fix is
SUSPECT and a clean run does not establish absence."*

**Action for the ledger:** any 32-node (>=27 dual-path node) result gathered
while `+caw-abort-reclaim.3` or earlier was loaded needs re-verification on
`.4` before it is trusted — specifically the sess385/386 conclusions (split
publications, the #361 chain, node deaths, the 474 legs). Do NOT close or
re-open entries on that basis alone; re-measure.

The overflow only arms above ~53 iSCSI registrants, so single-digit and
16-node evidence is unaffected.

## 4. Rig note found at the same time

**25 PR registrants were still on the LUN with 0 iSCSI sessions** after the
host reset — persistent reservations survive the initiators. When 32 nodes
rejoin that becomes 25 stale + 64 live = 89 registrants, which on the OLD code
is a much larger overflow, and which MXFS's fencing sees as phantom peers.
Check/clear stale registrants as part of rig bring-up.
