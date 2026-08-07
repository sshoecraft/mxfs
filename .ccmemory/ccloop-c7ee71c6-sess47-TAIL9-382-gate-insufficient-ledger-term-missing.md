---
name: ccloop-c7ee71c6-sess47-TAIL9-382-gate-insufficient-ledger-term-missing
description: sess47 last finding: fatal P53 recurred on 382 with ZERO gate refusals — clobber path carries no buffer-local state; my gate omitted GPT's ledger ter…
metadata:
  type: project
---

# 382 recurrence (test2 t=1384, ring /root/c2_382_t2_*.dmesg) — gate condition proven insufficient

p53=3, refused=0, shutdown at __xfs_trans_commit again. The non-destructive gate (DELWRI||pinned||bli-dirty||uncheckpointed) NEVER matched: when the snapshot install (or fresh cold read) happened, the buffer had NO local unhomed markers. Implications, in GPT's own warned order:
1. **Buffer-scoped defenses cannot close this** — the producer path crosses a full buffer teardown (fresh xfs_buf instance has no flags/bli/uncp history) and/or a target-level lost write (CLAUDE.md precedent: LIO stack drops FUA/O_SYNC durability — mkfs pwrite lesson). Only MOUNT-level state survives.
2. **My step-1 gate omitted GPT's ledger term**: the ruling's refusal condition included "or ledger pend>flush present [for the buffer's inos]". Not wired (needs per-slot ino walk + P220 epoch-ledger query API). Interim hardening for the relay: add that term to the gate AND to the plain cold-read fill path (read_map) for cluster buffers — refuse/park is impossible on a cold fill (nothing valid to keep), so the cold-fill variant must instead OVERLAY the ledger's authoritative next_unlinked values (mini-A-prime) or force targeted destage-then-reread.
3. **A-prime is THE fix** (typed iunlink records: ino+gen+ownership-epoch+committed value, retained until HOME completion, overlay+CRC-recompute+verify). Implementation target: the P220 epoch ledger machinery already keys per-ino pend/dur/flush — extend records with the value+epoch fields per the ruling digest (TAIL8 memory).
4. Verify from the new ring: what read/fill of the victim chunk preceded the P53s (P34D src=plain? cold read_map fill? coherent reread with clean buffer?) — names the exact install site for the mini-A-prime overlay.

Producer rate: 2 fatals + 1 idempotent wave across ~9 cycles on 380-382. Rig: test2 withdrawn (ring saved, safe to re-prep); 31 green on 382 ship config. Everything else: TAIL8 (ruling digest + queue), TAIL7 (root shape), END memory (session arc).
