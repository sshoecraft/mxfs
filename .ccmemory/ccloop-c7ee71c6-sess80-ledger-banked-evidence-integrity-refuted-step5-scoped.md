---
name: ccloop-c7ee71c6-sess80-ledger-banked-evidence-integrity-refuted-step5-scoped
description: sess80: sess78/79 fixes BANKED in the ledger (3 entries). The sess79 missed-grep thread CLOSED — 3 mechanisms refuted, cross-boot stamps is the answe…
metadata:
  type: reference
tags: [rule6, open-defects-ledger, evidence-integrity, foreign-replay, authority-token, step5, sess80]
---

# sess80 — ledger banked, evidence-integrity thread closed, step 5 scoped

Tree 0.11.418, srcversion `412957C596B75E582F3F676`. Rig re-prepped and
converged: 32/32 nodes mounted, active_count=32 stable, 231s.

## 1. RULE 6 banking done (the blocker sess79 flagged)

`tests/criteria/OPEN_DEFECTS.json` was 46 entries with **no entry at all** for
the HB defect sess78 fixed — so it could not be closed. Now 49 entries,
**18 OPEN / 19 FIXED AND VERIFIED**. Added:

- **D-HB-BLIND-WRITE-CLOBBERS-RECOVERY-GUARD** (critical) — FIXED AND VERIFIED.
  Carries the sess78 rig measurement (guard destroyed at t+0.8s, victim silent)
  and the sess79 four-line PASS on both 0.11.417 and 0.11.418. Residuals recorded
  as residuals, not gaps: call site 2 (`release_slot`) is code- but not
  rig-verified, and the ~1.8s detection latency belongs to
  D-VICTIM-REPLAY-WITHOUT-PROVEN-EXCLUSION, still OPEN.
- **D-SELF-FENCE-REPORTS-FALSE-CAUSE** (major) — FIXED AND VERIFIED.
- **D-P49-STALEBASE-FORMAT-VAARG-GARBAGE** (major) — FIXED AND VERIFIED, with
  the method trap: `-Wformat` only surfaces on a FULL rebuild, and
  `grep -iE 'error|warning'` hides the filename (it is on the
  `note: in expansion of macro` line).

## 2. The sess79 missed-grep thread — CLOSED, three mechanisms REFUTED

sess79 left this open and it mattered: a grep that false-negatives turns a real
failure into a PASS (sess27 found three board cells lying that way). All three
mechanical candidates are now measured and dead:

| hypothesis | instrument | result |
|---|---|---|
| kmsg visibility lags its stamp | `tests/kmsg_visibility_latency.sh` (sess79) | REFUTED — worst 15.4ms, 0/10 invisible |
| fresh-ssh-per-poll fetch failure | `tests/kmsg_fresh_ssh_miss_probe.sh` (new) | REFUTED — 30/30 HIT |
| `dmesg` skips records under log flood | `/dev/kmsg` sequence numbers, single pass | REFUTED — **0 seq gaps in 179535 records, quiet AND flooding** |

**The answer is cross-boot printk stamps.** sess79 ran the guard probe TWICE
(0.11.417 then 0.11.418) and the probe fences its victim, which reboots it.
printk stamps are boot-relative, so `92.168009` is only "earlier than" a grep at
uptime 120s if both are the same boot. Not provable retroactively — so it is
made impossible instead.

Two traps found the hard way while doing this:

- **`dmesg -S` is NOT the safer backend — it is CAPPED.** It returned a constant
  164483 lines while the live log grew past 176000. Do not "harden" a log read
  by switching to `-S`.
- **A flood probe DESTROYS kernel-log evidence.** Mine wrapped test2's ring
  buffer; afterwards a grep for `mxfs` across 176950 lines matched NOTHING — the
  node's entire MXFS history was gone. Warning is now in the probe header. Never
  run it on a node holding unread evidence.

### New in-tree tooling (RULE 3)

- **`tests/rig_dmesg_grep.sh <host> <pattern>`** — the reusable outcome. Exit
  **0=HIT / 1=MISS (proven absent) / 2=ERROR (nothing proven)**. Absence is
  PROVEN, never inferred: the remote side snapshots dmesg then emits a sentinel
  carrying dmesg's rc, the line count, **the boot_id and the uptime**. No
  sentinel, rc!=0, or 0 lines ⇒ ERROR. Use this instead of
  `ssh h "dmesg | grep PAT"`, which throws the exit code away twice (the
  pipeline takes `grep -v`'s status) and cannot tell a failed look from a
  no-match. Every printk stamp it reports comes with the boot it belongs to.
- `tests/kmsg_fresh_ssh_miss_probe.sh`, `tests/kmsg_flood_skip_probe.sh` — the
  two refutations, kept with their verdicts written into the headers.

## 3. D-FOREIGN-REPLAY-UNGATED-IMAGES — step 5 is the remaining work

The ledger's `next` field is STALE: it asks for "ATOMIC foreign replay", and
that landed (`P227-FR-ATOMIC-SKIP`, `xfs/xfs_log_recover.c:2181-2207`). Step 3b
also landed in sess49. Verified present in the tree this session:

- parser `mxfs_blf_parse_authority` — `xfs_log_recover.c:2034`
- report-only decode `P227-TOKEN` / `P227-TOKENSUM` — `:2080-2145`
- ATOMIC-SKIP taint scan — `:2181`
- token fill at CIL format time — `pal/linux/xfs_buf_item.c:341-404`
- `IMAGE_REPLAY_DONE` exists as descriptor stage
  `MXFS_RECOV_STAGE_IMAGES_REPLAYED=3` (`dlm/disklock.h:322`), and the step-4
  ordering at `dlm/v5_mount.c:2086-2219` is CORRECT: descriptor{FENCED} →
  IMAGES_REPLAYED → CAW purge → flush → GRANTS_RELEASED → broadcast.

**Step 5 = swap the taint predicate.** Today it taints on *any*
BUF/DQUOT/QUOTAOFF/ICREATE item — **tokened or not** — so a fully authorized
transaction is still skipped. That IS the residual false-SKIP durability gap
keeping the defect OPEN. Target: a BUF item taints only when its token is
absent, classless, or fails an exact `{class, resource, epoch}` match against
the fenced node's manifest.

Facts gathered for that design:
- **Manifest source**: the dead node's CAW lock-slot table — slots it holds
  EX/PW, keyed `(class=AG, resource=agno, epoch=ex_grant_epoch)`. It is readable
  at replay time because replay precedes the CAW purge in the step-4 ordering
  above.
- **Released-grant records correctly fail to match.** A slot carries only its
  latest `ex_grant_epoch`; a record logged under an earlier G1 whose grant was
  released won't match. That is right, not a gap — step 2b's audit proved the
  release barrier (`log_force(SYNC)` → drain → `blkdev_flush`) already destaged
  it, so replay is unnecessary.
- **SB class must fail closed.** `xfs_buf_item.c:378` sets
  `MXFS_AUTH_CLASS_SB` but assigns **no epoch and no resource**, so there is
  nothing to match against. Per the GPT ruling SB must never inherit authority
  from co-transaction AG items ⇒ SB-class items keep tainting until SB gets its
  own epoch source.
- DQUOT/QUOTAOFF/ICREATE are untokenized ⇒ keep tainting.

**Next session:** RULE 5 consult on the step-5 gate before writing it (manifest
construction, SB fail-closed, and whether epoch-mismatch should be a hard fail
or a taint), then implement, then A/B with `tests/foreign_replay_ab.sh` and the
`tests/openunlink_deaths.sh unlinker_death` reproducer.

**Not done this session:** the full board on 0.11.418. The rig is prepped and
converged, so `./run.sh 32 caw` + `./showstat.sh` is ready to go.
