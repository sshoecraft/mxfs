---
name: sess38-HEAD-handoff
description: sess38 HEAD: ROOT FOUND — 8/tcp dir_reuse loss is a DLM stale-EX/split-brain grant (buf reads current by gen+epoch yet content-stale). Fix = DLM mast…
metadata:
  type: project
---

## sess38 HEAD — handoff. CRITERIA NOT MET (8/tcp dir_reuse intermittently loses 1 dirent; 1/2/4 tcp PASS). Keeper build = clean default (all new dir levers off).

### ★ ROOT CAUSE FOUND THIS SESSION (decisive, instrumented) — moved from "dir-block cache staleness" (37 sessions) to **DLM STALE-EX / SPLIT-BRAIN GRANT**:
The genuine loss clobber (dir block 0, daddr=120, comm=xfsaild background reflush, buf_cnt=N disk_cnt=N+1) reads **bufgen==dirgen AND buf_epoch==master_ep** (e.g. 329==329) — i.e. the buffer is FULLY CURRENT by BOTH the gen token AND the node's own held grant dir-epoch, yet its content is one dirent behind durable disk. The node retained a STALE EX grant (epoch never advanced) across a peer's EX-modify, so xfsaild reflushes its stale buffer over the peer's add. **This is why all gen/epoch read-side heuristics fail: the freshness tokens LIE** — the node believes it still holds the tenure under which the buffer was stamped. Corroboration: **P-STALEMASTER-GRANT fired** (split-brain mastership: transient membership divergence → two masters grant EX from independent dg_shadow tables → concurrent EX the per-master P-DOUBLEGRANT (=0×) can't see). active_nodes IS sorted/deduped (dlm/dlm.c:2144) so masters are consistent for the SAME set; the divergence is a transient membership window under the 8-node storm. Full evidence: [[sess38-DECISIVE-loss-is-stale-EX-grant-bufepoch-eq-masterep]].

### THE FIX (GPT-5.5 consult #2, full design): [[sess38-GPT2-DLM-fix-design-split-brain-mastership-write-authority]]. DLM must guarantee one-master-per-resource-generation + no-EX-grant-until-old-holder-drained-or-fenced; FS must enforce no-metadata-writeback-without-current-EX-write-authority-token. SMALLEST piece that kills the measured loss: (a) reject stale-master EX grants, and/or (b) a per-resource write-authority token (mode+seq+cookie+io_refs) that xfsaild MUST hold before submitting a dir-metadata write — so even under a split-brain grant the stale holder cannot background-write; on -ESTALE a CLEAN stale buffer is DROPPED (never written — the refuted "skip write" was keeping/writing it). Full fix = membership recovery-barrier (freeze grants during membership change) + blocking BAST + write-authority token + optional on-LUN owner record (PR-fenced).

### REFUTED this session (all default-off): dir_subset_guard=1 (write-suppress→shutdown); my dir_release_retire_done=1 (retire-without-write→round-1 shutdown); dir_tenure_evict=1 (BEST read-side: 0%→~67%, but INSUFFICIENT — the epoch the buffer carries EQUALS the held grant epoch); dir_tenure_evict+dir_evict_prior_tenure (fail); dir_tenure_stale_bypass=1 (round-21 loss + 11 shutdowns — keep-guard must be honored). The release flush already retires all in_ail buffers (P38-POSTREL-ZOMBIE=0×) — NOT a zombie-survives-release bug.

### TEST FACTS: only 8/tcp dir_reuse fails; it's a RACE (round1 PASSES, ~1 dirent lost in ~1-2 of 24 rounds; need full 24 rounds to repro; 2-3 rounds pass). `dirwr=1`/`instr=1` MASK the race (logging slows the storm → false PASS); `dataclobber=1` does NOT mask — use it. `MXFS_EXTRA_MODARGS` → insmod needs BARE param (`dataclobber=1`, not `mxfs.dataclobber=1`). Reboot ALL 8 VMs (`virsh -c qemu:///system destroy/start test1..test8`) before each run (they wedge rmmod after CRC-shutdown). Run: `MXFS_TEST_ENV='DRC_ROUNDS=24' ./run.sh 8 tcp dir_reuse_coherency`.

### PROBES IN BUILD (keeper-equiv at default, low/zero overhead): P38-LEAFCRC-FAIL, P38-DIRMAP (failure-path), P38-POSTREL-ZOMBIE (dirwr-gated), buf_epoch + master_ep added to P-DATACLOBBER-SKIP, dump_stack on data-clobber. P-STALEMASTER-GRANT / P-DOUBLEGRANT / P64-MASTER-HANDOFF are pre-existing always-on DLM probes (dlm/dlm.c) — grep them on a failing run to confirm split-brain timing.

### NEXT (RULE 4): implement the write-authority token gating xfsaild dir-metadata writeback (cheapest correctness guard) FIRST — measure; then the membership recovery-barrier / stale-grant rejection. Decisive confirm-probe: at the loss clobber, dump the MASTER node's live EX-owner for ino 131 vs this node's real_mode to prove the EX is stale. Guard 1/2/4 tcp against regression.
</body>
