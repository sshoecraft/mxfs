---
name: ccloop-c7ee71c6-sess91-recov-auth-zero-victim-epoch-wedge
description: sess91: incarnation predicate PROVEN discriminating on the rig (first ever P237-RECOV-INC-MISMATCH) + a NEW critical wedge found: inc_eq(0,0)=false m…
metadata:
  type: reference
tags: [sess91, disklock, incarnation, recov_auth_holds, inc_eq, wedge, measured, GPT-ruling, P237, P234-RECOV-NOTOURS]
---

# sess91 — the incarnation guards are live, and one of them wedges recovery forever

Build 0.11.420, srcversion `33018595D555FBE463F017B`, 32/32 mounted on caw.
No code changed yet. New instrument + one new critical ledger entry
(`D-RECOV-AUTH-ZERO-VICTIM-EPOCH-WEDGE`).

## New instrument (RULE 3) — `tests/incarnation_mismatch_probe.sh`

`incarnation_mismatch_probe.sh [arm=zero|nonzero] [victim] [writer] [detect_s] [heal_s]`

sess88/89 both recorded that the incarnation REFUSAL arms had never executed on
the rig, and sess89 proved the route the code comments assume (claim pass-1
own-stamp reclaim) is unreachable by construction. This probe reaches them by a
**different, reachable route**: the monitor's EPOCH-CHANGE arm
(`disklock.c:1147`). When a tracked slot's on-disk epoch changes, the monitor
declares the PREVIOUS incarnation dead with `victim_epoch = nt->last_epoch`
(the *cached* value, not a re-read) and jumps straight to `fire_dead`, skipping
the 62s dead threshold and the FUA confirm. `recovery_begin` then RE-READS the
sector and compares cached-vs-on-disk — exactly the discrimination under test.

Injection: `virsh destroy` the victim (its sector is then written by nobody, so
the write cannot race its heartbeat or trip the sess78/79 own-slot CAS
self-fence), wait for the sector to be provably frozen, then rewrite **only the
8-byte epoch field**, 512B O_DIRECT from a survivor, recomputing `feat.crc32c`
so the feature block stays VALID (it binds {magic,proto_gen,feat_flags,fs_gen,
node_id,epoch} — leaving it stale routes the test through the VERSION gate
instead of the incarnation gate, which is a different experiment).

**The CRC self-check is load-bearing and must stay**: before writing anything,
the probe recomputes the crc of the LIVE record and aborts unless it reproduces
what the kernel wrote. crc32c here is the kernel's reflected CRC-32C
(poly 0x82F63B78, init 0xFFFFFFFF, **no final xor**) over a 24-byte packed LE
struct. Verified on the rig: kernel=111580837 == computed=111580837.

Record layout used: magic 0, flags 4, node_id 8, fs_gen 12, timestamp_ms 16,
epoch 24, lock_count 32, union{evict,recov} 40..456, mepoch 456..500,
feat 500..512 (magic 500, proto_gen 504, feat_flags 506, crc32c 508).

## RESULT 1 — the incarnation predicate DISCRIMINATES (first execution, ever)

    disklock: P237-RECOV-INC-MISMATCH slot=4 victim=4085327405
      victim_inc=1634619062121349274 slot_inc=0 flags=0x1 featstate=0
      — refusing to publish
    mxfs: P234-COMPLETE-FENCEFAIL slot=4 node=4085327405 rc=-116   (-ESTALE)

Zero was **not** treated as a wildcard; no `P234-RECOV-FENCED` was published in
that round. This is positive evidence that the 0.11.420 incarnation is not
merely a nonzero number on disk — the comparison is live and fails closed. It
covers mechanism items (2), (5) and (7) of `D-MOUNT-INCARNATION-CONSTANT-ZERO`.

## RESULT 2 — a NEW critical defect: `inc_eq(0,0)` wedges recovery forever

On the next death round the monitor had rebased its cached incarnation to the
on-disk 0, so `recovery_begin` took its documented UNOBSERVED arm and created a
descriptor with `victim_epoch = 0`:

    P237-RECOV-INC-UNOBSERVED slot=4 victim=4085327405 on-disk=0
    P234-RECOV-FENCED slot=4 victim=4085327405 epoch=0 slice=0/4
      owner=4195151743 gen=1 term=1

The slice replayed fine (`foreign replay of slot 4 complete` ×10,
`P163-RECOVERED slot=4` ×31). Every advance then failed:

    P234-RECOV-NOTOURS slot=4 victim=4085327405 stage->3 — the descriptor is
      owned by node=4195151743 epoch=14541807080602951442 gen=1 term=1; we
      hold  node=4195151743 epoch=14541807080602951442 gen=1 term=1.
    P234-COMPLETE-REPLAYEDFAIL slot=4 node=4085327405 rc=-16    (-EBUSY)

**The two tuples printed are identical.** Root: `recov_auth_holds`
(disklock.c:2722) tests `inc_eq(d->victim_epoch, auth->victim_epoch)` — but
`inc_eq(a,b)` is `a && b && a==b` ("zero is never a wildcard", right for
CROSS-SOURCE matching) and `auth` was issued verbatim FROM that descriptor
(`recov_auth_issue` copies the 0). `inc_eq(0,0)` is false, so the owner fails
its own authentication. Same shape at disklock.c:3291 (fencing lease).

12 min later: sector still `flags=GUARD stage=2 victim_epoch=0`, owner at 11
NOTOURS retries, `P163-RECOVERY-COMPLETE=0`, `P97-SWEEP-DONE=0`. The freeze gate
refuses to zero below GRANTS_RELEASED, so the slot and the dead node's CAW
grants are frozen permanently. **The rig needs a re-prep after this arm.**

## RULE-5 ruling (verbatim points worth keeping)

- The one-line equality change is correct. The design rule: *"unknown may equal
  unknown only as part of a strongly bound descriptor identity; it may never
  establish equality of two independently sourced incarnations."*
- **`recov_auth_holds` never compares `victim_slot`** even though
  `recov_auth_issue` copies it — a stale auth can pass against another slot's
  descriptor. Not zero-specific; applies to nonzero epochs too. Fix with the
  equality change, and prefer a durable unique `recovery_id` nonce over the
  composite tuple.
- Classify each `inc_eq(d->victim_epoch, …)` site by **provenance, not syntax**:
  takeover + advance-guard = descriptor identity (plain equality);
  fence_intent + fence_certify = independent evidence (zero must fail — a zero
  epoch cannot certify an INCARNATION fence; that needs a separately typed
  SLOT/lease fence kind); purge freeze gate must key off descriptor id + slot
  guard, never a naked epoch argument.
- A zero-victim_epoch descriptor is safe only if its authority is
  SLOT/slice-level quarantine, not incarnation identity (seven invariants
  listed in the ledger `next`). Otherwise `recovery_begin` must refuse to
  publish one and take an explicit transition (durable QUARANTINED/NEEDS_FENCE
  + re-election, or withdraw) — never endless refusal.
- **Separate defect to file:** the monitor downgrading a KNOWN nonzero cached
  incarnation to 0 (disklock.c:1156 `rebase_epoch`, :1358) is information loss,
  not an observation. `known E1 + observed UNKNOWN` must RETAIN E1 and mark the
  disk state inconsistent. That downgrade is what launders a mismatch into the
  UNOBSERVED arm.
- Unbounded advance retry is itself an obligation violation: reread, classify,
  relinquish or escalate. If the descriptor is unchanged and still ours yet
  auth fails, that is an invariant violation — fatal diagnostic, stop the loop,
  do NOT force the milestone or clear the guard.

## Harness fix applied to two probes

`incarnation_death_probe.sh` and the new probe learn the victim's slot/node_id
from its claim line, and on a node that has run a board that line has long
since rolled out of the dmesg ring. Both now ask **dmesg AND
`journalctl -k`** and take whichever still holds it (ccmemory
`kernel-log-retention-varies-per-node-pick-best-source`); the on-disk
node_id cross-check catches a stale answer.

## Rig state left behind

test32 was destroyed and restarted (`virsh -c qemu:///system start test32`);
slot 4 is wedged in RECOVERY_GUARD. Next session must run
`MXFS_FORCE_PREP=1 ./run.sh 32 caw prep_cluster` before any measurement.
