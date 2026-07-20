---
name: net2-plan-rescan-errata-0.10.120
description: NET2 plan verified vs 0.10.120 tree (5-agent scan): all core claims hold; 15 errata incl. lease-port split 7602/7603, no gen-advance in lease_expire,…
metadata:
  type: project
tags: [net2, dlm-plan, verification, errata, tcp-transport]
---

# DLM_PLAN.md re-scan vs 0.10.120 (2026-07-17, five parallel verification agents)

User directive: re-scan the tree, then GPT-verify the plan, before any NET2 implementation. Every file:line anchor and behavioral claim in DLM_PLAN.md (written 2026-07-11) was checked against current source. Full agent tables are in this session's transcript; GPT consult prompt embeds the condensed errata.

## Core claims that HOLD
Inner `mxfs_dlm_msg_hdr.seq` inert (no ack/retransmit anywhere); peer.c keeps sockets on transient send timeout (retry {200,500,1000}ms ×3 → -EAGAIN); dlm.c wholesale lock-table purge + epoch bump on membership change; master = nodes[hash%count]; grant_gen monotonic never 0 (dlm.c:915); stale-gen RELEASE dropped (dlm.c:4001); XFS release contract intact — p_rel_gen capture @12120, mid-drain abort (p_rel_gen vs p_entry_gen) @12383-12508, unlock_gen(p_rel_gen) + -ESTALE→re-arm @14025-14063; drains now named mxfs_dlm_ag_drain_{meta_buffers,alloc_buflist,inode_buffers} + blkdev flush in mxfs_dlm_ag_bast_work_fn Phase 2/2b @29479-29507; BAST entry = mxfs_dlm_bast_notify @15146 via mxfs_v5_dlm_set_bast_notify @31654 (+AG twin @29106); make_*_resource memset padding (whole-struct hashable); scsipr anchors exact (key=(u64)node_id @31, preempt @138, unregister @169, read_keys @200); find_slot never returns tombstone as found; v5 seam: all 8 entries keep the `if(ctx->dlm)…else if(ctx->dlm_caw)` shape; transport enum CAW=0 TCP=1 AUTO=2 (3 free for NET2).

## Errata / drift (the 15 items GPT was given as ground truth)
1. Inner hdr = 32B {magic u32, version u16, type u16, length u32 (total; frames on hdr.length — NO payload_len field), seq u32 inert, sender u32, target u32, epoch u64}. Wire already carries TWO epoch systems: hdr.epoch (lease/membership) + lock_resp.{grant_gen, dir_epoch, handoff-byte} per-resource.
2. mxfs_resource_id {volume, ino, offset, ag_number, type, pad[3]} — NO generation/incarnation field.
3. MXFS_PEER_MAX_MSG_SIZE 8192 lives in peer.c:17 (not peer.h).
4. CAW slot reserved[] now [364] not [376] — dir_block0_fsb(u64)+dir_block0_gen(u32) consumed 12B. New post-plan slot fields: yield_to(u64)+yield_set_ms(u64 wall-clock) fair-handoff ticket, ex_grant_streak (yield to PR class at 3, modparam caw_fair_handoff), waiters_ex. Envelope mode must replicate these semantics, not just holders/gen/dir_epoch/last_ex_slot.
5. mxfs_dlm_caw_unlock_gen(ctx,res,expected_gen32,bool is_free) — is_free zeroes dir_epoch/last_ex_slot inside the SAME tombstone CAS (the dlm_scaling@32 fix; separate post-hoc CAS regressed to 0/32 = TRAP-1 per-free sync FUA). Modparam caw_epoch_free_reset registered but never consulted (vestigial).
6. CAW ctx: grant_meta[32768]+grant_seq_counter; CAW grant_gen token = mxfs_dlm_caw_grant_seq32; mxfs_dlm_caw_granted_mode() exists @3656; orphan_clock[4096]+own PAL spinlock.
7. v5 CAW branches now SERVE grant_gen/dir_epoch/handoff/granted_mode (plan written when they returned 0/false); unlock honors expected_gen (is_free=false generic; mxfs_v5_dlm_inode_unlock_free passes true, impl @1498).
8. v5_mount.c does NOT do CAW-probe/fallback — transport = opts->transport + force_transport==1 override; AUTO resolved by caller.
9. v5_lease_expire_cb @766: CAW purge + disklock purge + TCP purge + lowest_live_slot replay election + dead_node_notify — NO "advance resource generation" step exists (plan's recovery ordering cites one; NET2 must ADD it).
10. PORTS: 7600 @881/1171, 7601 @882/1173; LEASE SPLIT — lease.h MXFS_LEASE_PORT=7602 is a LIVE fallback (lease.c:323, legacy mount passes 0→7602) while v5 paths pass literal 7603 → effective lease port differs by mount path, and 7602 collides with CAW_BAST. 7604/7605 unused. Mcast group 239.66.83.1.
11. memb_settle: mxfs_memb_settle_ms=20000 (was 6000) defined v5_mount.c:92, consumed dlm.c:1128 ("dlm_lock_impl" = dlm.c); trigger stamp last_memb_change_ms is a field INSIDE the TCP engine struct (ctx->dlm), stamped v5:507/522/570 — TCP-struct-local; NET2 freeze must own its own state. Plan's claim that the CAW grant path checks memb_settle is UNVERIFIED (consumption found only in dlm.c TCP path).
12. PAL: mxfs_pal_spinlock_* family (pal.h:280-309, added 07-13) and mxfs_pal_time_real_ms (pal.h:520) exist post-plan. Plan's "zero PAL additions for core" holds; only watchdog_arm/pet + fence_agent genuinely new.
13. transport_caw() 12 call sites; != (CAW, restartable epochs) vs > (network, monotone) exactly as planned; ALSO grant_gen==0 treated as CAW discriminator at several sites → NET2 MUST always deliver nonzero grant_gen.
14. Deferred-death machinery (tcp_death_grace_ms=40000, suspect arrays, worker declares dead on timeout alone @590-622) TCP-only — matches plan's fence-insertion point.
15. Unmentioned infra the membership plane must state a relationship to: disklock self-fence cb on generation change/re-mkfs (fs_gen in HB record), evict-ring (28 entries in HB record: inode-freed/dir-modified hints), runtime-settable disk dead-timeout (62s=31×2000ms default), MDS=slot-0 concept (is_mds/mds_node_slot), ever_multi single-node-regression latch.

## Also noteworthy
- E4: i_mxfs_ex_grant_seq decl xfs_inode.h:171, EX-upgrade stamp @22007 (plan's 20873 now unrelated code).
- discovery.c:463 is the setter; peer_cb invocation @205-206.
- B2: popcount>1 check is slot_appears_corrupt() bool detector (not an assert).
- C14 wording: purge fns are mxfs_dlm_caw_purge_node/mxfs_disklock_purge_node/mxfs_dlm_purge_node.

## Status
GPT consult (verify plan + right-size + amendments + holes + sequencing + fault matrix) launched 2026-07-17 from this session; verdict to be folded into DLM_PLAN.md. No net2_* files exist yet; no mxfs_ports.h. Prior Jul-12 GPT verdict ("don't build NET2 to fix CAW") noted as superseded-in-scope: CAW is green 1-32 on 0.10.120; this effort targets the legacy TCP transport replacement.
