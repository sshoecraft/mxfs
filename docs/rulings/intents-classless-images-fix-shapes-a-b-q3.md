<!-- sess467 RULE-5 ruling on the classless images that POLICY-REFUSE a dying node's rm txns: B (iunlink DINODE_BUF -> AG class, guarded) first, A (inacti… -->
# sess467 GPT ruling — D-FOREIGN-SLICE-INTENTS-ABANDONED classless images (chain 93: buf_items=37 classless=34 st=4 MISLABELLED = 39 bmbt one-block images + 2 DINODE_BUF iunlink images)

## Q1 — inactivation images: shape A ACCEPTED, narrowly
A certificate on an I_FREEING inode is sound (it attests a real DLM EX tenure, not VFS reachability). Requirements:
1. install ONLY from the completed grant result (resource/epoch/lineage/owner slot+incarnation); never infer from i_dlm_mode==EX; never before the grant is durably represented in the state the death manifest freezes from.
2. ordinary gen discipline: snapshot gen/routing identity before the blocking acquire; under i_dlm_lock recheck gen, ino, routing/resource identity and that THIS acquire owns the grant; abort rather than install on a recycled/rerouted inode.
3. install BEFORE any first dirty (every truncate/ifree txn incl. rolls).
4. revoke at INACT-EXREL by EXACT grant identity {resource,epoch,lineage}; a delayed release must not erase a newer certificate.
5. no dirtying after revocation: finish dirtying -> revoke under i_dlm_lock -> release the DLM grant.
6. routed (ICLUS) inodes: name the actual cluster resource granted, never a synthetic per-inode resource the manifest cannot match.
MUST NOT: clear/weaken I_FREEING; iget/igrab/reload/hash-insert; imply ilock ownership; publish for other users; synthesize an epoch from cached mode; enable any fast path because auth_state==DURABLE_EX. If consumers read DURABLE_EX as more than a replay certificate, add INACT_DURABLE_EX substate (classifies identically, confers nothing). A' (inactivation-tenure marker) REJECTED as a duplicate certificate mechanism.

## Q2 — DINODE_BUF iunlink images: AG class CORRECT, only for the iunlink image
The inode whose di_next_unlinked changes, its cluster buffer, and the AGI all live in AG X by construction. Producer checks: exact AG EX grant held with nonzero durable epoch; AG(ino)==AG(buffer)==AGI txn AG; restrict to the xfs_trans_inode_buf/iunlink format whose recovery applies only di_next_unlinked (xfs_inode_buf_ops + AG grant alone is NOT sufficient; no AG authority over inode cores). Replay hazard: applying an old di_next_unlinked into a reallocated cluster corrupts — the cross-slice buffer-LSN veto is a PREREQUISITE: run before the specialized inode-buffer replay, consider later records from ALL slices, veto if any later cluster image supersedes, keep LSN wrap semantics. Whole-buffer veto then field-only apply is safe.

## Q3 — UNPUBLISHED_EX bmbt images (3886/4931 in a create lap): heuristic REJECTED (false-APPLY hazard)
AG grant authorizes allocation metadata, not inode-private bmbt contents; ICREATE/inobt co-presence proves no delegation, no init image, no absence of handoff/free/reuse; AG and inode authority can be on different nodes. Minimal sound rule: (1) publish the inode's durable EX certificate before the first bmbt dirty, or (2) mint a durable unpublished-child delegation binding parent AG tuple + owner ino/gen + child blkno/len/type + delegation id/version + alloc txn identity + not-revoked/published/transferred/freed/superseded state, proven by the frozen manifest. Never infer from nearby log items.

## Q4 — order + pre-code census
Order: B, then A, then Q3 (never the AG/ICREATE inference as interim).
- A census: for every classless inactivation bmbt image: a real raw EX grant at first dirty with exact {resource,epoch,lineage}; gen/routing matched; certificate absent/stale/unpub/releasing. Decisive: real matching tenure existed and certificate absence was the SOLE failure. (0.64.2: P-INACT-EX ino/rc/resource/epoch/lineage/kind/gmode/dlm_mode/auth_state + P239-OWNAUTH-NONDUR by ino.)
- B census: AG(ino)==AG(buffer)==AGI txn AG; exact durable AG EX held at first dirty; replay routes via field-only recovery. Decisive: one unambiguous contemporaneous AG authority, no cross-AG case. (0.64.2: P227-TOKENSUM dino_none/dino_agsib.)
- Q3 census: bmbt block + owner gen + alloc txn + first-dirty txn + AG tuple + publication/delegation state; the fraction with a provable exact block-to-inode delegation.
Verification arm (victim destroyed inside the EFD hold): policy_refused_txns==0, classless_images==0, authority_mismatch_images==0, atomic_skipped_txns==0, undischarged_EFD_census>0, quarantine reason == 8 ONLY (INTENTS-UNDISCHARGED standing alone).
