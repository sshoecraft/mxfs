---
name: AAA-ccloopa864-sess8-ROOT-PROVEN-bmbt-leaf-RMW-restamp-laundering
description: sess8 ROOT PROVEN: dir_reuse@32/caw = re-acquiring node RMWs a STALE prior-tenure bmbt leaf buffer + re-stamps it current (sess66 gate laundered), xf…
metadata:
  type: project
---

## sess8 (ccloop a864) — dir_reuse@32/caw ROOT CAUSE **PROVEN** (RULE 4, live repro build 6C932BD7)

### THE BUG (one sentence): A node that RE-ACQUIRES the shared dir EX after peers grew it RMWs its own STALE prior-tenure bmbt-leaf buffer (never re-read from the coherent medium), the sess66 tenure gate re-stamps that stale image as current-epoch (laundering), and xfsaild writes it onto the SHARED leaf block concurrently with the current real holder's write → the on-disk bmbt leaf TEARS (bad CRC) → the next reader (xfs_create) EFSBADCRC → xfs_trans_cancel → shutdown → 0/32.

### DECISIVE EVIDENCE (stream_rank*.log, t≈546-552, failing leaf daddr=46051048=0x2beaee8, dir ino=131):
- **Raw LUN block** (dd /dev/mapper/mpatha @ daddr+xfs_data_offset[=196688 sectors]): magic=BMA3, level=0, **numrecs=39**, self-daddr ok, owner=131 ok — a structurally-valid leaf but **CRC FAILS (err=-74)** = torn (content≠its own CRC). 39 matches NO single writer.
- **Concurrent writers to the SAME block 46051048 in a 200ms window**: rank20 numrecs=19 tenure=1032 (comm=bash ×13); rank13 numrecs=16 tenure=1131 (comm=bash AND **comm=xfsaild/dm-1**); rank18 numrecs=16 tenure=713 (comm=dd). All show `buf_tenure==cur_seq mode=5 ex=1` (each node LOCALLY believes it holds current-tenure EX).
- **Handoff history**: rank13 acquired dir at gen 234 (t546.72); rank20 at gen 246 (t550.55) = 12 handoffs / ~4s apart. rank13's xfsaild writes leaf at t550.69 — ~4s + 12 handoffs AFTER its gen-234 tenure — because rank13 re-acquired (epoch→1131), RMW'd its stale cached leaf, re-stamped it 1131.
- **rank1 (victim)**: P63-HANDOFF fmt=2→P-RELOAD-IDENTICAL fmt=3 nx=19 (adopts coherent dinode broot→leaf46051048); P59-BMBT-ROOT-KEEP daddr=46051048 DONE=0 (its buffer cold, re-reads medium); reads the TORN medium block → P15I-CRCFAIL secrc=[83b4d6aa f70fac59 00×5] (sectors0-1 content) → Internal error xfs_trans_cancel line 1068 caller xfs_create → Shutting down. rank1 side is CORRECT — it's a victim of the torn medium.

### WHY EXISTING MACHINERY FAILS (all confirmed in code):
- **sess66 tenure gate** `mxfs_buf_xfsaild_skip_bmbt_write` (xfs_mxfs_dlm.c:28797): skips xfsaild bmbt write if dir mode==NL OR b_tenure_id != i_mxfs_ex_grant_seq. It's a LOCAL per-node check → cannot see that ANOTHER node is the real holder.
- **The laundering** `mxfs_dir_bmbt_track` (xfs_mxfs_dlm.c:28878, called at modify from xfs_trans_log_buf): unconditionally sets `bp->b_tenure_id = ip->i_mxfs_ex_grant_seq`. The sess4 P67-STALE-BASE-RMW detector (28920) DETECTS the exact laundering moment (old tenure stamp + dirty/in_ail buffer being re-stamped) but is **LOG-ONLY** — line 28941 re-stamps anyway. Comment 28908-28918 literally says "the sess66 gate is defeated by design from that instant."
- So: a first-modify-of-a-reacquired-tenure on a NOT-re-read leaf buffer RMWs stale content and re-stamps current → gate passes → xfsaild clobbers the shared block.

### THE FIX TARGET (writer/re-acquire side): the STALE cached bmbt leaf must be re-read from the coherent medium at cross-node EX re-acquire BEFORE the first modify. `mxfs_dir_evict_bmbt_blocks` (xfs_mxfs_dlm.c:1804) is supposed to clear XBF_DONE on cached leaves at reload so the next read cold-fetches — but at the failure it emitted **P59-BMBT-ROOT-KEEP daddr=46051048 DONE=0** = it KEPT (did not evict) that leaf. NEXT: read the P59-ROOT-KEEP branch (xfs_mxfs_dlm.c ~1900-2010) — find why 46051048 is kept (treated as root? dirty/pinned skip?) and force the stale prior-tenure leaf to be discarded/re-read. CAUTION: do NOT drain (bwrite) a stale leaf at re-acquire (would clobber the peer's newer medium image); DISCARD (invalidate) it — at cross-node re-acquire the peer's medium image is authoritative and our cached image is superseded (our prior-tenure work is already durable per INVARIANT #1). Handle pinned specially (sess64: clearing XBF_DONE on pinned corrupts — drive unpin first, like the sess66 pin-only drain at 1868).

### repro: `env MXFS_DEV=/dev/mapper/mpatha MXFS_TEST_ENV='DRC_STREAM=1' timeout 1800 ./run.sh 32 caw dir_reuse_coherency`. Fails deterministically r5 (~t550, ~9min in incl 107s prep). Streams persistent at tests/tcp/drc_cap/stream_rank${R}.log. secrc/daddr vary per run but mechanism identical.
