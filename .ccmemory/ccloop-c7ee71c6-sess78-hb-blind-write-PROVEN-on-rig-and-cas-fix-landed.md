---
name: ccloop-c7ee71c6-sess78-hb-blind-write-PROVEN-on-rig-and-cas-fix-landed
description: sess78: the HB blind-write clobber is MEASURED on the 32-node rig (guard destroyed at t+0.8s, victim logged nothing) + the own-slot CAS fix landed 0.…
metadata:
  type: reference
tags: [disklock, heartbeat, fencing, recovery-descriptor, critical, rule4-proven, sess78]
---

# sess78 — D-HB-BLIND-WRITE-CLOBBERS-RECOVERY-GUARD: PROVEN, then fixed

Took the sess77 GPT ruling's #1 item. RULE 4 loop ran to 2b (proven) and the
patch landed. **0.11.417, srcversion `3CC53C56D9A8899B9164861`, builds clean,
NOT DEPLOYED and NOT re-measured.**

## The measurement — direct, on the live 32-node caw rig

New harness `tests/hb_guard_clobber_probe.sh` (RULE 3, in-tree).
`./tests/hb_guard_clobber_probe.sh test2 test1`, victim slot 30,
node_id 3090681846, against 0.11.416:

```
t0     flags=ACTIVE ts=22672128
t+2.6  flags=ACTIVE ts=22674172   LIVE: ts advanced +2044 ms — victim IS heartbeating
WROTE: flags ACTIVE -> RECOVERY_GUARD (all other bytes unchanged)
 t+0.4 flags=GUARD  ts=22674172
 t+0.8 flags=ACTIVE ts=22676223   <-- CLOBBERED
VERDICT: CLOBBERED at t+0.8s.  DEFECT PRESENT.
--- test2 kmsg since probe mark ---   (EMPTY — the victim never noticed)
```

The guard survived **0.8 s**. The victim logged **nothing**: it kept
heartbeating and kept writing to the FS with its slot under a recovery.

### Two traps the probe had to dodge (both would have faked a PASS)
1. **O_DIRECT is mandatory.** Buffered reads of `/dev/mapper/mpatha` come from
   the READER's page cache, which no peer's write invalidates — a buffered
   probe reads back its own write and reports a false HELD. Probe uses
   `os.preadv`/`os.pwritev` on an `mmap(-1,4096)` (page-aligned; LUN is
   `--getss 512` so 512-byte O_DIRECT at 512-aligned offsets is legal).
   **NOTE: `tests/hb_slots.sh` is buffered — it may be showing stale data.**
2. **`timestamp_ms` is ktime_get_boottime (per-node UPTIME).** Only ever
   comparable to ITSELF. The probe proves liveness by *advance* across one HB
   interval, never by a reader-clock delta. (`hb_slots.sh`'s `age_s` column is
   nonsense for exactly this reason — it printed 1.7e9 s.)

## The fix (0.11.417) — every own-slot write is a compare-and-write

`dlm/disklock.h`: new `ctx->hb_img` + `hb_img_valid` — the exact image we last
wrote to our own slot, the compare source for every later write.

`dlm/disklock.c`:
- `hb_own_record()` — is the sector still ours? magic + flags==ACTIVE +
  node_id + epoch + fs_gen. **The old `magic && node_id` test was NOT this
  test**: `recovery_begin()` rule 2 preserves magic/node_id/fs_gen/epoch byte
  for byte and only moves `flags`, so the old predicate passes on a guard.
- `hb_foreign_kind()` — names the foreign image for the fence log.
- `hb_cas_own_slot()` — CAW from `hb_img`; `-EOPNOTSUPP` → read-verify-write
  fallback. Returns **-EPERM** (sector is NOT ours → self-fence),
  **-EAGAIN** (still our live record → cached image drifted, resync +
  `P236-HB-CAS-RESYNC`, retry next cycle), or an I/O error, which is
  INDETERMINATE → `hb_img_valid=false` so the next call re-reads.

Three call sites converted (**all three were blind, all three clobber**):
1. `disklock_hb_fn` — every 2 s. On -EPERM: `P236-HB-FOREIGN-WRITE` +
   `P236-SELF-FENCE`, `fence_cb()`, break. (P131 self-fence fires only on an
   fs_uuid change, so nothing covered this before.)
2. `mxfs_disklock_release_slot` — read+`magic&&node_id` then blind flags=0.
   Now `hb_own_record()` + CAS from the exact image read (heap, not the 512B
   stack buf). `P236-RELEASE-REFUSED` / `-RACE`.
3. `mxfs_disklock_withdraw` — blind WITHDRAWN stamp. The voluntary-death stamp
   destroyed the very recovery it was trying to trigger. Now reads first,
   `P236-WITHDRAW-REFUSED` if foreign, CAS otherwise. **Read-failure keeps the
   blind stamp** deliberately: never declaring death is worse.

`claim_slot` (both CAW and non-CAW) seeds `hb_img`; non-CAW seeds from the
read-back `rec`, not `hb`.

## NEXT SESSION — do these in order

1. **Deploy + re-run the probe.** `MXFS_FORCE_PREP=1 ./run.sh 32 caw
   prep_cluster` (72-137 s), then `./tests/hb_guard_clobber_probe.sh test2
   test1`. PASS requires BOTH: `VERDICT: HELD` **and** the victim's kmsg
   showing `P236-HB-FOREIGN-WRITE` + `P236-SELF-FENCE` + an XFS shutdown.
   HELD without the self-fence is a FAIL — a silently-guarded node that keeps
   writing is defect (b), untouched.
   *The probe force-shuts-down the victim by design; re-prep after.*
2. **Watch `P-HB-SLOW`.** CAW is one command like the old write, but sess38
   measured real HB stalls — confirm the cadence did not regress.
3. Full board `./run.sh 32 caw` + `./showstat.sh` (RULE 0 budgets first).
4. Only then resume the sess77 ledger: yield-by-evidence, `GUARD{FENCING,
   owner=UNOWNED}` in place, kill every ordinal `stage >= FENCED` test
   (audit slot reuse / join scans / recovery enumeration / admin cleanup, not
   just replay dispatch), certify-until-success-or-self-fence.

## Do NOT close the ledger entry on this
Fix is written and compiles. Under RULE 6 it is FIXED AND VERIFIED only after
step 1 passes on the rig. Right now it is **unverified**.
