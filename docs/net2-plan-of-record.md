# NET2 — the plan of record

NET2 is the replacement for the legacy TCP DLM transport: a reliable,
incarnation-qualified, effect-idempotent message layer with its own membership
authority and shard consensus. This document is the plan as decided on
2026-07-17, together with the verification that was run against the tree before
it was written. The external review that shaped it is in
`docs/rulings/net2-plan-review-verdict.md`; its verdict was explicitly overruled
on staging, and the section below says so.

## The v2 decision (2026-07-17)

USER DECISION (explicit, overrides GPT's staged-releases framing): implement the WHOLE NET2 system in ONE effort — "later stages means never" on this project. v2 keeps the full architecture (mesh + overlay, 1024 shards, membership/fencing, delegations, envelope) with the review's corrections folded in and the two under-designed pieces now fully designed. §11 = dependency order with in-effort gates (checkpoints inside the same push, not exit ramps). Envelope ships in the pass, feature-gated default-OFF until its matrix passes (that gate was in v1 too).

### Design 1 — MEPOCH membership authority (§7.C, replaces the CAW-write ledger)
Single committed record {epoch, member_mask, fenced_mask, slot→incarnation} = THE authority; lease mcast / unicast probe / disklock HB = observer votes only. No CAW dependency: commit = single-decree protocol over direct NET2 links among the 3 lowest-slot voters OF THE COMMITTED PREVIOUS EPOCH (deterministic; E+1 needs majority of E's voters = the reconfiguration rule), with PREPARED-then-COMMIT flags so a proposer crash can't fork the epoch. EXCLUSIONS require attached incarnation-qualified fence_done proof as a commit PRECONDITION (quorum-without-fencing structurally cannot exclude). Persistence: 44-byte LE record (incl. crc32c + self_incarnation) in each node's OWN disklock heartbeat record reserved bytes — single-writer 512B sector (Invariant 3), atomic, durable across whole-cluster restart, and DISK-VISIBLE to partitioned nodes (excluded node reads survivors' records → self-fence with zero network). Incarnation = persisted per-slot monotonic u32 in own HB record (+64-bit boot nonce, equality-matched in sessions) — never boot-time derived. Bootstrap: slot claim → read all HB records → adopt max committed epoch; fresh cluster = founding node commits epoch 1 solo. Membership always rides DIRECT links (kills routing↔membership circularity).

### Design 2 — epoch-fenced shard consensus (§7.B, replaces "Raft-style" hand-wave)
Shard configs are DERIVED from committed MEPOCH epochs (HRW top-3 over member_mask), so configurations are totally ordered/exclusive — the old-and-new-groups-both-quorate hole is closed by epoch fencing, no joint quorum needed. Within epoch: terms, 2-of-3 commit on a bounded log + snapshot (volatile, epoch-fenced state — lock state is exclusion state, reconstructible; GFS2/OCFS2 philosophy), leader completeness = max(term, commit_seq) candidate rule, restarted replicas may NOT vote/ack until state transfer (SH_XFER→CAUGHT_UP). Waiter queue + completed-op dedup cache are REPLICATED via the log → fairness (FIFO + CAW-equivalent 3-EX streak-yield) and duplicate-op results survive failover. Total shard-state loss → closed-set recovery barrier: N2_RECOVERY_REPORT from ALL E+1 members (gen-stamped client reports; claimant set closed + every non-member fenced+replayed ⇒ reconstruction-from-claims is safe here), gen_next = max(reported)+1024 slack. Whole-cluster restart = fresh epoch + formation journal replay; gens restart safely (epoch-qualified on wire, in-core compares never span remount). Record GC via shard-global gen floor (solves resource-lifecycle ABA without touching resource_id).

### Other v2 commitments
64-byte LE outer header (u32 incarnations; nonces in SYN TLV with full UUID + fs_gen binding + rate-limit); inner MXFS_DLM_VERSION NOT bumped (NET2 negotiated in its own handshake); NET2-allocated request_id op identity (inert inner seq untouched); 5 priority classes with RELEASE > BAST + reserved deficit quanta; control-queue overflow ⇒ scoped freeze (never drop, never bare error); full flow-control spec (win 64, SACK 32, delayed-ack 5ms/8, RTO 200ms→2s cap, 10s COMM_AMBIGUOUS escalation, ~1MB/session cap); reconnect-preserving-session (drops legacy keep-socket-up policy); both topology providers behind net2_topology={auto,mesh,overlay}, auto=mesh until overlay gate green; recovery ordering with EXPLICIT gen-advance step (fence < exclusion < replay < gen-advance < unfreeze); budgeted reason-coded freezes surfaced via stats/chk_mxfs (frozen must be testable-visible); fence ladder with per-multipath-path PR confirmation + incarnation-qualified fence_done; envelope state mirrors FULL current slot semantics (yield_to/yield_set_ms/ex_grant_streak/waiters_ex/dir_block0) with is_free reset riding the unlock CAS; ports registry with LEASE_LEGACY(7602)/LEASE_V5(7603) split (v1's "7602 dead" claim was wrong); Makefile edits still need explicit user go-ahead (§11 step 12).

### State
DLM_PLAN.md v2 written; DLM_PLAN_REVIEW.md + rescan errata memories on disk; no net2 code yet. Next: §11 step 1 (net2_wire.h + mxfs_ports.h + identity + counters + golden vectors) on user go.

## Verification of the plan against the 0.10.120 tree

Run before the plan was written, on user directive: re-scan the tree, then take
the review, then implement. Every `file:line` anchor and behavioural claim in
the v1 plan was checked against the source by five parallel verification agents.

User directive: re-scan the tree, then GPT-verify the plan, before any NET2 implementation. Every file:line anchor and behavioral claim in DLM_PLAN.md (written 2026-07-11) was checked against current source. Full agent tables are in this session's transcript; GPT consult prompt embeds the condensed errata.

### Core claims that HOLD
Inner `mxfs_dlm_msg_hdr.seq` inert (no ack/retransmit anywhere); peer.c keeps sockets on transient send timeout (retry {200,500,1000}ms ×3 → -EAGAIN); dlm.c wholesale lock-table purge + epoch bump on membership change; master = nodes[hash%count]; grant_gen monotonic never 0 (dlm.c:915); stale-gen RELEASE dropped (dlm.c:4001); XFS release contract intact — p_rel_gen capture @12120, mid-drain abort (p_rel_gen vs p_entry_gen) @12383-12508, unlock_gen(p_rel_gen) + -ESTALE→re-arm @14025-14063; drains now named mxfs_dlm_ag_drain_{meta_buffers,alloc_buflist,inode_buffers} + blkdev flush in mxfs_dlm_ag_bast_work_fn Phase 2/2b @29479-29507; BAST entry = mxfs_dlm_bast_notify @15146 via mxfs_v5_dlm_set_bast_notify @31654 (+AG twin @29106); make_*_resource memset padding (whole-struct hashable); scsipr anchors exact (key=(u64)node_id @31, preempt @138, unregister @169, read_keys @200); find_slot never returns tombstone as found; v5 seam: all 8 entries keep the `if(ctx->dlm)…else if(ctx->dlm_caw)` shape; transport enum CAW=0 TCP=1 AUTO=2 (3 free for NET2).

### Errata / drift (the 15 items GPT was given as ground truth)
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

### Also noteworthy
- E4: i_mxfs_ex_grant_seq decl xfs_inode.h:171, EX-upgrade stamp @22007 (plan's 20873 now unrelated code).
- discovery.c:463 is the setter; peer_cb invocation @205-206.
- B2: popcount>1 check is slot_appears_corrupt() bool detector (not an assert).
- C14 wording: purge fns are mxfs_dlm_caw_purge_node/mxfs_disklock_purge_node/mxfs_dlm_purge_node.

### Status
GPT consult (verify plan + right-size + amendments + holes + sequencing + fault matrix) launched 2026-07-17 from this session; verdict to be folded into DLM_PLAN.md. No net2_* files exist yet; no mxfs_ports.h. Prior Jul-12 GPT verdict ("don't build NET2 to fix CAW") noted as superseded-in-scope: CAW is green 1-32 on 0.10.120; this effort targets the legacy TCP transport replacement.
