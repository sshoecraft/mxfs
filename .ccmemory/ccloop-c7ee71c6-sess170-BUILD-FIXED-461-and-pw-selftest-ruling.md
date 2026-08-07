---
name: ccloop-c7ee71c6-sess170-BUILD-FIXED-461-and-pw-selftest-ruling
description: sess170: tree BUILDS again at 0.11.461 (edge-mint fully landed, NOT deployed). GPT APPROVED kernel-hook PW selftest vehicle; full verified design ins…
metadata:
  type: project
---

# sess170 — build fixed at 0.11.461; PW-selftest vehicle ruled; design fully specified

## 1. TREE BUILDS AGAIN — 0.11.461, NOT YET DEPLOYED
All three sess169 pending edits landed in dlm/dlm_caw.c:
- Knob decl at ~424 (after wait_expire block, inside the file-top `#ifdef __KERNEL__` at line 38 / #else 459 / #endif 470): `mxfs_caw_inject_gep_wrap` (module_param caw_inject_gep_wrap, 0644, consumable).
- `cur_slot` inserted as 2nd arg at ALL 5 live call sites of `caw_grant_epoch_update` (wait-grant ~6246, claim ~6998, compat-add ~7859, direct handoff ~8641 `(uint8_t)w_slotno`, convert-upgrade ~9910).
- Dead `mxfs_dlm_caw_flush_held_to_disk_orig` REMOVED (was ~12956-13125); tombstone comment left before `int mxfs_dlm_caw_flush_held_to_disk`.
VERSION 0.11.461. `make modules` rc=0, srcversion **AC77A91359602432ABDB805**; `make -C tools` rc=0. Helper body verified correct per ruling (mint/CONT-ZERO/preserve arms, prev from `s` not `cur`, zero-skip in caw_next_grant_epoch at 1102). Rig still on 0.11.460 — deploy needed before any board.

## 2. RULE-5 ruling (this session, gpt-5.6-sol): kernel-hook PW selftest APPROVED
Q5's user-mode vehicle premise REFUTED by inspection: tools/caw_verify.c = raw SCSI CAW/FUA sector checker; NO user-mode DLM build exists (pal/linux only, no pal/user, no mxfsd in tree; dlm_caw.c only in Kbuild). GPT: in-kernel modparam/debugfs-armed selftest driving mxfs_dlm_caw_lock/convert/unlock on a reserved resource "satisfies Q5's verification intent, arguably stronger"; user-mode re-host NOT justified. Approved ledger wording captured in transcript. CONDITIONS:
- (A1) Do NOT claim WHICH grant site minted the re-mint token unless attributed; inequality only proves new tenure.
- (A2) acquire-upgrade arm only if a supported shape — VERIFIED SUPPORTED: v5_mount.c:4347 comment names "normal held-mode upgrade path"; compat-add handles same-node upgrade in one CAS (P109-CLR-UPGRADE).
- (B) Reserved unallocatable key, node-derived; NOT "some ino no file uses". Audit that lock-only activity publishes nothing into XFS transaction state (holds by construction: no log records ever written for the test ino → no trailers; manifest entries are opaque per-resource, purge is resource-agnostic). Destructive qualification case required: kill/fence node while it holds test PW/EX, confirm normal purge/recovery + reacquisition.
- (C) Per-context trigger preferred (debugfs under the mount) over global modparam; atomic IDLE→RUNNING with -EBUSY; ctx pinned for handler lifetime; refuse during unmount/unformed; never queue onto CAW progress/reconcile worker; best-effort unlock on every failure path; ONE run-ID-qualified verdict line; probe grep must be instance-qualified (match by reserved ino in rk=/id= fields of P274-GEP-PRESERVE / P109-CLR-UPGRADE).

## 3. Fully-verified design (all code anchors checked this session)
- **Entry point**: new `mxfs_v5_dlm_caw_pw_selftest(struct mxfs_v5_dlm *ctx, uint64_t ino)` in dlm/v5_mount.c (has ctx->dlm_caw, make_inode_resource(&res, ctx->volume_id, ino), portable logging). Decl in dlm/v5_mount.h. Uses `mxfs_dlm_caw_lock(caw, &res, mode, 0, &granted, &gres)` (dlm_caw.h:1341), `mxfs_dlm_caw_convert(caw, &res, new_mode, &gres)` (1453, accepts any non-NL mode, old_mode derived from slot → downgrade EX→PW flows through same body), `mxfs_dlm_caw_unlock(caw, &res)` (1357). Assert per-step with `mxfs_grant_result_proving(&gres)` (status==MXFS_GAUTH_WRITE_EPOCH && epoch!=0) on write-capable grants; on downgrade assert only if gres proving (defensive), real check = round-trip.
- **Sequence** (each step logs P274-PWTEST step line w/ run id+ino+rc+epoch): arm1: lock PW→T1!=0 proving; convert EX→==T1 (+P274-GEP-PRESERVE fires, rk=ino); convert PW; convert EX→==T1 (proves downgrade preserved); unlock; lock EX→T3!=T1,!=0; unlock. arm2: lock PW→T4!=0 (also !=T3); lock EX (ACQUIRE-upgrade → compat-add: P109-CLR-UPGRADE id=ino old=4 new=5 + P274-GEP-PRESERVE)→==T4; unlock. Any failure → best-effort unlock + FAIL verdict. Single verdict line: `mxfs: P274-PWTEST <PASS|FAIL> run=%u ino=%llu t1=%llu t3=%llu t4=%llu step=%s rc=%d`.
- **Test key**: computed in the DEBUGFS HANDLER (xfs side owns geometry): ino = (u64)(sb_agcount + 1 + node_slot) << (sb_agblklog + sb_inopblog) | 1 — agno>=agcount ⇒ unallocatable by geometry (format-guaranteed), node_slot (mxfs_v5_dlm_get_node_slot, used at xfs_super.c:997) ⇒ per-node unique. Key stable across runs is GOOD (tombstone recycle = the re-mint edge).
- **Trigger**: write-only debugfs file "caw_pw_selftest" under mp->m_debugfs (mkdir at xfs_super.c:2656, exists before DLM init at 3075). New dentry field in xfs_mount (pattern: m_mxfs_* fields exist). Create after m_mxfs_dlm set (~3075 success path); **remove EARLY in teardown right before `mp->m_mxfs_dlm = NULL` at xfs_super.c:1553** — debugfs_remove blocks on in-flight handlers (proxy fops), closing the use-after-free race (m_debugfs itself is only removed in xfs_mount_free, LAST — too late). Handler: snapshot mp->m_mxfs_dlm (NULL→-ENODEV), static atomic busy gate (-EBUSY), parse u64 (0=auto key), run SYNCHRONOUSLY in write(2) context (blocking allowed; ~seconds; caw_op_enter inside each CAW call gates shutdown), return count on PASS / -EREMOTEIO on FAIL so `echo 1 > file` rc IS the verdict.
- **Harness**: tests/ script — arm on one rig node via ssh, check write rc, grep journal for verdict + the two attribution probes filtered by the reserved ino. Then wrap test: arm caw_inject_gep_wrap=1, re-run selftest (or any EX mint), assert P274-GEPWRAP-INJECT + minted epoch==1 (zero skipped).

## 4. Next session queue (in order)
1. Implement selftest fn (v5_mount.c/.h) + debugfs file (xfs_super.c + xfs_mount.h dentry field). Rev 0.11.462, build.
2. Deploy to rig, run selftest harness on 1 node + wrap-inject case; then kill-while-held qualification case (GPT B); then full board 32/caw.
3. Ledger: #15 rewrite per sess169 ruling queue item 7 (mark sess108 steps DONE, record vehicle ruling + selftest evidence); #1 add historical-record-lifetime gate blocker + Q6 cross-ref.
4. Wrap-policy documentation duty (Q4): document 2^64 CAS-rate math or fail-closed exhaustion — goes with #15 closure.
Rig: all 32 on 0.11.460 (460F52B), board-ready, untouched this session. COMPACTION DUE (182 unfolded) — run compile-memories synchronously early next session.
