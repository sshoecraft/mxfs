---
name: sess38-DECISIVE-clobber-is-inail-clean-nonstale-subset-genblind
description: sess38 DECISIVE (valid dataclobber=1, build F6DB00D5): dir_reuse loss = in_ail CLEAN bgen==dirgen(NOT stale) data buffer 1-entry behind disk, xfsaild…
metadata:
  type: project
---

## sess38 — the 8/tcp dir_reuse readdir=799 clobber, finally measured cleanly (build F6DB00D5, dataclobber=1 VALID this time).

### ENV CORRECTION (cost a cycle): `MXFS_EXTRA_MODARGS` is passed to `insmod` (prep_node.sh:77), which takes the BARE param name. Pass `dataclobber=1`, NOT `mxfs.dataclobber=1` (the mxfs. prefix is silently ignored → param stays 0 → probe inert). Always verify `cat /sys/module/mxfs/parameters/<p>` after prep.

### TEST REALITY (clean reboot of all 8 VMs first — they wedge rmmod after each shutdown):
- 8/tcp dir_reuse: **round 1 PASSES (800/800); the loss is a RACE** — fires ~1-2× per 24 rounds at a random round (saw round 2, 13, 16, 21 across runs). 2-3 round runs PASS (not enough). Must run full 24 rounds to repro. Loss = ONE entry, coherent across all 8 nodes, lookup_fail=0 (pure DATA-block dirent loss). CRC-shutdown (block 0x1ff0f0 = a DATA block where the reader's map expects a LEAF) is DOWNSTREAM accumulation in later rounds, not the primary bug.

### THE CLOBBER (P-DATACLOBBER-SKIP, kind=data, the one that drops the readdir entry):
`daddr=120 buf_cnt=167 disk_cnt=168 bufgen=8 dirgen=8 mode=5 real_mode=5 master_self=0 in_txn=0 in_ail=1 bdirty=0 pin=0 stale=0 comm=xfsaild`
- daddr=120 = dir block 0. Buffer holds 167 dirents; durable DISK holds 168 (a peer's add). Writing the buffer drops 1.
- **stale=0 (bufgen==dirgen)** → the gen-coherency mechanism is BLIND to it. i_dlm_dir_gen did NOT advance even though disk grew past the buffer.
- in_ail=1, bdirty=0, in_txn=0, comm=xfsaild → a CLEAN, committed-but-not-retired buffer being BACKGROUND-flushed by xfsaild. Stack = xfs_buf_submit/xfs_buf_submit_bio (confirmed background, not an active modify/commit).
- It is a STRICT SUBSET of disk (disk has all 167 + the 1 extra).
- This is a **ZOMBIE in_ail buffer surviving a tenure handoff**: node committed 167 (in_ail), released+drained (167 durable), but the BLI was NOT retired; a peer added the 168th (disk=168); node re-acquired; the stale 167 buffer is still in_ail and xfsaild reflushes it over disk's 168.

### REFUTED THIS SESSION:
- **Write-side subset-suppress (`dir_subset_guard=1`, P26-SUBSET-SKIP)**: fired 10× but made it WORSE — failed at round 2 and cascaded to shutdown (readdir=0) by round 10. Confirms the standing "write-side DROP/suppress of dir DATA = corruptor" negative. Do NOT enable dir_subset_guard.
- The whole multi-session "stale-base RMW caught by the gen/stale check" framing is INCOMPLETE: the killer clobber is **stale=0** (gen says fresh). Gen-based read-invalidation cannot see it.

### THE READ-GUARD TRAP (xfs_da_btree.c ~3280): the read-time invalidation PRESERVES any in_ail buffer ("always THIS node's committed work") — but a ZOMBIE in_ail buffer (this node's OLDER work, a strict SUBSET of what a peer durably superseded) is wrongly preserved → never refreshed → reflushed stale.

### FIX DIRECTION (next, RULE 4): retire/refresh the zombie. Discriminator: an in_ail dir DATA buffer that is a STRICT SUBSET of durable disk = zombie → must retire BLI + invalidate (re-read disk). One that has entries disk LACKS = current work → preserve. Two candidate sites: (1) EX-RELEASE drain: retire BLIs so NO in_ail dir buffer survives the handoff (sess37 DECISIVE; their attempt double-freed because bwrite already retires — implement only for buffers the drain did NOT bwrite); (2) EX-REACQUIRE read hook: when cached in_ail buffer is a strict subset of disk, invalidate+retire instead of preserve. Must NOT suppress the physical write (refuted) — fix the BASE before the modify. See [[sess37-DECISIVE-clobber-on-nonmaster-stale-local-dlm-EX]] [[sess11run-SMOKINGGUN-datalog-entry-bytes-logged-then-vanish-no-evict-no-reload]].

### P34-TRYLOCK-STALE fired 16× (read-invalidation skipped because buffer trylock-locked → serves stale cached). Secondary contributor.
### Probe build F6DB00D5 adds: P38-LEAFCRC-FAIL (leaf read CRC dump), P38-DIRMAP (logical→daddr for bno!=0 dir reads), dump_stack on data-clobber (≤6).
</body>
