---
name: ccloop-c7ee71c6-sess175-GPT-ruling-enforcement-gate-design-and-sample3
description: sess175 RULE-5 ruling (#1 gate swap): txn-atomic admission ratified w/ corrections; lineage=option-b v3 token; release invariant unproven; 108-captur…
metadata:
  type: project
---

# sess175 — GPT ruling: foreign-replay enforcement gate design (full text in sess175 transcript)

## P273 sample #3 (this session, elected arm, victim test5/slot3, 0.11.462)
capable=1 desc_rc=0 stage=2; buf=39 csum=39 (conservation exact); WOULD_APPLY=39/39; txn=10
all_apply=10; untagged/v1/resmis/winc/notheld/staleep/uncap_match/uncached/missed_txns ALL 0;
visibility 40/40/40. Third sample; all three show blanket-skip suppressed fully-authorized txns.
Victim restarted NOT re-prepped — MXFS_FORCE_PREP=1 ./run.sh 32 caw prep_cluster before next board.

## Ruling (gpt-5.6-sol): gate direction ACCEPTED; default-on NOT ratified. Hard blockers:

**Q1 capable=1 (RATIFIED with corrections):** txn-atomic AUTHORITY admission — preflight the ENTIRE
committed txn before ANY replay side effect (buffer+inode+dquot/icreate+intent reconstruction);
any rejecting terminal/malformed/untagged/v1 record rejects the WHOLE txn; verdict cached once per
txn; streaming apply-before-inspect forbidden. CORRECTIONS: (a) token does NOT supersede
di_changecount — authority gate AND di_changecount both-must-pass for inode items; a di_changecount
"already newer" no-op is idempotence, NOT an authority rejection (must not discard the txn's needed
buffer replay). (b) COVERAGE GAP: producer guarantee covers buffer records only — dquot/icreate and
every replay-affecting type need authority evidence or a separately ratified node-independent test;
"not tokenized yet" must NOT be treated as authorized (txn containing such a type cannot be admitted).

**Q2 capable=0 (SPLIT required):** legitimately adopted (predecessor durably DONE/CONSUMED) =>
retain containment (blanket skip + P226) unchanged; uncapable_match>0 alone must NOT fail the mount
(DONE-before-purge crash window legitimately leaves a matching manifest — high-severity probe +
stage verify only). REFUTED: treating descriptor READ FAILURE (I/O error/checksum/malformed/
unproven stage) during ELECTED live recovery as ordinary capable=0 — that must ABORT/RETRY recovery,
never silently skip-all (silent discard of acked victim changes = control-plane corruption accepted).

**Q3 tenure-release invariant (UNPROVEN — open hazard):** stale_epoch rejection is safe ONLY under
"no new tenure effective until old tenure's dirty state has completed HOME-LOCATION writeback +
device flush, then unlock peer-visible". begin_release conservation proves path classification, NOT:
drain completion before peer-effective unlock; no redirty after drain snapshot; coverage of all
state types; ordering through flush completion; no local release/reacquire shortcut minting N+1
before N drained. Same-node reacquire must not mint N+1 until the N drain barrier completes (else
it is the SAME tenure continuation, no new epoch). Preferred closure: harden+instrument the
per-tenure drain barrier, publish unlock only after completion. Slice-force insufficient (log
durability != home destage). Manifest high-water mark acceptable only if it means home-write/AIL
retirement completed. Required fault test: stop after each drain/flush/unlock-publication/regrant/
epoch-mint boundary; prove no undestaged epoch-N item coexists with effective N+1 tenure.

**Q4 lineage (option b RATIFIED):** independent lineage discriminator — durable stable per-resource
lineage across slot moves OR fresh globally-monotonic lineage minted at rebind; carried in durable
resource record + token + frozen manifest; exact equality in gate; never inherited from prior slot
occupant; wide non-reusing value with defined wrap; likely NEW TOKEN FORMAT (v3), not overloaded v2
fields. Option (c) refuted as complete bound: same victim incarnation + tombstone/rebind through
another lineage + numeric epoch collision + refrozen manifest can pass all existing checks. Option
(a) drain-before-rebind = acceptable backstop, not primary (couples rebind to historical-log
reclamation). Until lineage-bearing records exist, records subject to slot-lineage restart are NOT
authoritative and must reject their transactions.

**Q5 evidence bar:** staged knob foreign_replay_token_enforce (default 0) RATIFIED; setting fixed
per-recovery; shadow and enforce MUST share the same evaluator + cached verdict; fault injection
must verify ZERO side effects before preflight completes; positive+negative tests for every
terminal + tuple component (incl. lineage, manifest errors, malformed lengths, duplicate tokens,
multi-resource txns). Minimum campaign: **108 qualified victim-kill captures** (4 per cell of the
27-cell board): 54 elected capable=1, 27 adopted/DONE, 27 recoverer-crash-and-resume spanning every
descriptor stage. Workloads: mid-CIL-format/mid-log-write/post-ack kills; create/unlink/link/
cross-dir rename (sess41 shape); dquot+icreate; alloc/free, truncate; multi-AG txns; release/regrant
churn; tombstone/slot-reuse/cross-slot rebind with lineage; log wrap; kill during fence/freeze/
replay/DONE/purge; flush delay/failure; descriptor read failures. Default-on checklist: exact
shadow/enforce agreement, no partial effects, no unauthorized apply, remount durability agreement,
proven release ordering, proven recoverer-crash resumability, lineage active for all admissible
records.

**Q6:** sess133 lifecycle-shape re-consult DISCHARGED by the sess150/160 census (does NOT discharge Q3).

## Implementation order (derived)
1. Lineage discriminator (v3 token + durable resource lineage + manifest carry) — prerequisite for admission.
2. Tenure-release drain-barrier instrumentation + epoch-mint ordering proof + boundary fault tests.
3. Preflight/verdict-cache enforcement machinery behind knob; dquot/icreate evidence; descriptor-failure abort/retry split.
4. Capture campaign toward 108.
