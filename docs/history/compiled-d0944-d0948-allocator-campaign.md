<!-- sess570-572: D-0944 unpublished-metadata fix + symlink case + TCP release-gate hole; D-0945 choke-point gate; D-0946 (=D-0351 recurrence) fix+repro h… -->
# D-0944 → D-0945 → D-0946 → D-0947 → D-0948: the inode-allocator/publish campaign, sess570-572

One continuous investigation on 2-node TCP (test1/test2, QNAP LUN), 0.75.109 → 0.75.119.
Started as one defect (unreplayable images after a dirty death) and forked into five as each
fix exposed the next layer: publish timing, a release-gate hole, a stale-reuse defect that
turned out to be D-0351 recurring, and two more allocator/platter-coherency defects underneath
that.

## D-0944 — deferred publish never covered non-directory owned metadata (sess570)

Root cause, correcting sess567's wrong attribution ("free-space btree grow/collapse"):
`P239-OWNAUTH-NONDUR` lines in the same evidence directory showed all 6662 unreplayable images
belonged to ONE `fallocate`d file's **bmap btree** — inode-owned metadata, not AG metadata.
`XFS_BLFT_BTREE_BUF` conflates AG btrees with per-inode bmbt in a `t4=` summary; read the
NONDUR lines, not the blft histogram. See `docs/history/docs/history/docs/history/compiled-d0944-d0948-allocator-campaign.md`.

Mechanism: `mxfs_dlm_grant_local_new` gives a newly created inode a LOCAL-ONLY EX grant with no
on-disk slot (publish-on-create was removed for cost — ~25s of a 32s rsync of 8714 files).
Live coherency holds because every peer path to the inode transits a lock this node holds, which
publishes before release. That argument only covers *live access*. A metadata block outside the
inode core (bmbt, non-shortform attr fork, remote symlink target) is authorized only by the EX
grant, and while that grant is local-only, an image of it ships `AUTH_NOT_HELD`. A peer replaying
the slice refuses the whole transaction, atomically skips it, and quarantines every AG it touches
— AG 0 holds the root inode, so this is catastrophic. Directories were already diverted to a real
acquire (`mxfs_dlm_ilock_begin`); regular files were not.

Fix, 0.75.110, `unpub_publish_owned_meta` (default 1): divert any unpublished non-directory that
owns — or is one extent from owning — metadata outside the core
(`mxfs_inode_owns_logged_metadata`, two-extent margin because one op adds at most one extent).
A/B on identical workload: pre-fix 6662/6662 images unpublished, 0 durable; fix 0/6662
unpublished, 6662 durable, 4 extra publishes, no measurable pace cost.

**Symlinks are a distinct sub-case**, `docs/history/docs/history/docs/history/compiled-d0944-d0948-allocator-campaign.md`:
`xfs_symlink()` allocates the inode and logs the target block in the SAME transaction, so there
is no later "first exclusive modify" to divert — the ilock-time hook can't reach it. Fixed
separately in `pal/linux/xfs_symlink.c`: call `mxfs_dlm_publish_inode(du.ip)` when `fs_blocks >
0`, between dquot attach and `xfs_symlink_write_target`. Inline symlinks (target in inode core)
never reach the call and stay on the cheap path. General rule: any create form that externalizes
metadata *inside the create transaction itself* (remote symlink, large initial xattr/ACL,
reflink/prealloc needing an immediate bmap tree, directory going straight to block form) needs
the grant taken in that transaction or a durable creator-exclusive token — no third option.
Two probe traps found en route: a first probe reported symlink CLEAN because its 3000-byte
targets all failed `ENAMETOOLONG` against `XFS_SYMLINK_MAXLEN=1024` (zero real symlinks tested);
and `filefrag`'s summary line undercounts extents — count `-v` rows, never the summary.

**Publishing does not fully close the death path.** `docs/history/docs/history/docs/history/compiled-d0944-d0948-allocator-campaign.md`
also documents that `P273-SHADOW-EVAL` on the survivor splits refusals into at least two distinct
causes: `classless/untagged/badst` (producer shipped nothing enforceable — what the publish fix
removes) vs `notheld` (token is VALID but the fence-time manifest says the victim didn't hold
that resource at death — a *release*, not a *capture*, problem). One `notheld` case was observed
even under the fix. That thread leads directly to the TCP release-gate hole below. Rig trap noted
here: a lap whose victim fails to rejoin leaves it unmounted, and every subsequent lap then fails
its precondition silently — a driver must re-prep before any lap whose nodes aren't both mounted
and report which laps were prepped.

## The TCP release-gate hole (sess570)

D-0357 (closed) established: an incarnation may release an on-disk grant only while no
replay-eligible image of it can still require that grant; when `MXFS_V5_DEPART_POISONED`, no
release can prove this, so every release must be refused. Two gates implement it in
`dlm/v5_mount.c` (`v5_tcp_release_gate`, `v5_caw_release_gate`). `mxfs_v5_dlm_inode_unlock_free()`
— the inode FREE path — called the CAW gate on its CAW arm and **nothing** on its TCP arm: one
release primitive out of eight, asymmetric, invisible on CAW by construction (exactly why a
transport-scoped campaign matters). Effect: a dirty-death inode free dropped manifest evidence;
the survivor's replay then hit `notheld=1` on an otherwise-VALID token, `ATOMIC-SKIP`,
`P227-FR-TORN-UNPUBLISHED`, AG 0 quarantined, `mount_rc=32`. Tell: an evidence log where the AG
release is correctly refused (`P-TCP-RELEASE-POISONED ag=0`) but the inode release beside it has
no such line. Fixed: all eight release primitives now gated;
`mxfs_dlm_caw_purge_node` is deliberately left ungated (it purges a *dead peer's* slots from a
survivor — the opposite operation). See `docs/history/docs/history/docs/history/compiled-d0944-d0948-allocator-campaign.md`.

General technique extracted from finding this by re-reading the file after the damage was already
chased back three layers: an invariant enforced at N call sites has N chances to be missed; find
the 1-2 primitives every caller funnels through (`mxfs_dlm_unlock_gen`,
`mxfs_dlm_send_unconditional_release` in `dlm/dlm.c`) and ask the question there via a plumbed
oracle callback (`local_poisoned_cb`, alongside the existing `recovery_blocked_cb` /
`node_live_cb` / `refused_owner_cb` pattern). Critically, the choke point only **logs**, it never
enforces — whether releasing-while-poisoned is a defect depends on which call site it is, so
disposition stays per-site with evidence (`__builtin_return_address(0)` + `%pS`).
See [[technique-ask-the-invariant-at-the-choke-point-not-at-each-caller]].

## D-0945 and the A/B that found a new defect (sess571)

A/B of the D-0944 fix, build 0.75.114 (verified to carry `P945-INO-FREE-RELEASE`, not the later
0.75.115 edits — confirms the measurement wasn't contaminated). Two corrections to an earlier
in-session reading, both worth keeping as method: (1) "fix arm still atomic-skips" was an
artifact of grepping ring-buffer-tail dmesg captures instead of the driver's own windowed per-lap
summary — an evidence file named after a lap is not necessarily windowed to that lap; (2)
"fix-arm-only EFSCORRUPTED" was confounded, not established — the control kept failing to rejoin
so every control lap got a fresh mkfs, while the fix ran laps 2-6 on an aged filesystem;
"fix-arm-only" and "aged-filesystem-only" were the same observation. Trust the driver's windowed
summary, never raw dmesg greps. D-0945's gate (`P945-INO-FREE-RELEASE` / release-refused-while-
poisoned) was observed firing on 2 of 6 fix laps, 0 of 6 control — the two `NO-DEATH` laps, route
reached ~1 lap in 3.

**New defect found incidentally, on an aged filesystem with no death injection at all**: plain
`fallocate -l 8M` at lap setup produced `P-RECYCLE-GATE` with `incore_gen == disk_gen + 1` — the
allocator's in-core free bumped the generation but the free never reached the platter, so dialloc
reissued a number the disk still called allocated. The `-EFSCORRUPTED` fail-safe fired correctly
but cancelled a **dirty** transaction, which shuts the filesystem down. This became D-0946.
See `docs/history/docs/history/docs/history/compiled-d0944-d0948-allocator-campaign.md`.
Harness bugs this exposed: an `&&`-chained setup that short-circuits on create failure leaves
downstream timing vars unset (`wall_ms` prints an epoch), so a lap whose SETUP died must abort
rather than run workers against a dead filesystem; and a scorer that greps only for one specific
log-error text reads "shutdown by an unexpected route" as "no shutdown" — must distinguish the two.

## D-0946 identified as D-0351 recurring, ruling obtained (sess571)

Matched line-for-line against D-0351 (`FIXED AND VERIFIED`, same probe sequence, same
`incore_gen == disk_gen + 1`, always a peer-freed dead shell): D-0351's stated root — no guarantee
the free dinode is durable before the inobt free becomes visible to a peer under a new AG grant —
still holds. Ledger handling: D-0946 carries current evidence, D-0351 stays annotated (not
reopened) so it isn't double-counted, but D-0351's disposition must not be read as covering the
create path. Critically: **half of the original sess427 ruling — "validate the platter dinode
BEFORE dialloc dirties the transaction" — was never built.** Verified absent in `xfs_create`
between `mxfs_quar_gate_locked` (~2882) and `xfs_dialloc` (~2890); the only platter-mode check is
the post-error `P-CR62` probe at 3184, already after the transaction is dirty. The fail-safe is
correct to refuse (handing out a live inode would be worse) but fires too late to fail cleanly —
`mxfs_quar_gate_locked`'s own comment already names that spot as the last point a refused acquire
can become a clean failure instead of a shutdown. Landing containment there is independent of
finding the durability root and testable alone. Never relax the P-CR62 check itself — that turns
a caught divergence into a silent double-allocation. See `docs/rulings/docs/rulings/d0946-is-a-recurrence-of-d0351-and-its-ruling-containment-half-never-landed.md`.

design-consult ruling obtained on the underlying two-gate disagreement (gate 1 =
`mxfs_dialloc_validate_candidate`, allows reuse on the theory of a locally-held publication
obligation; gate 2 = the recycle gate in `xfs_icache.c`, which doesn't know about that obligation
and calls the live image corrupt). Full ruling: `docs/rulings/d0946-two-gates-reuse-authorization.md`.
Key points: naive "shape A" (teach gate 2 the exemption via a second inference from mutable state
— pubob lookup + generation matching) is UNSAFE to ship — false acceptance silently overwrites a
live inode, strictly worse than the shutdown. Worst unlisted hazard: a stale free-publication
action surviving reuse and later writing the freed image over the new incarnation; on reuse the
obligation must atomically transition and the old action must be cancelled/retargeted, never left
runnable keyed only on `ino`. "Shape B" (gate 1 stops granting the exemption, refuses instead) is
the right immediate containment, but needs (a) a transient state distinct from the corruption
quarantine — these inodes aren't corrupt, permanent quarantine leaks inode space and produces
false ENOSPC — and (b) an explicit progress rule (bounded skips → drive publication → release
locks the publisher needs → wait/force log → retry → quarantine only if still live with no valid
reason) or it starves. Do not hold the cluster AG grant across a synchronous flush — cluster-wide
head-of-line blocking. Long-term direction: gate 1 returns a refcounted, transaction-bound token
that gate 2 consumes instead of rediscovering the obligation by inode number. Also owed
regardless: enforce obligation drain at AG-grant handoff — this failure needs no handoff at all,
so that's a second, independent necessary rule.

## D-0946 fix landed and the reproducer hunt (sess572)

Fix ("shape B"): `mxfs_dialloc_validate_candidate()` now REFUSES on a positive whitelist
(`FREE`/`FREE_PENDING`/`CHAIN_LIVE`, never a negative `okind != UNLINK` test), returning `-EBUSY`
with `P946-VALIDATE-PUBPEND` — transient by construction, routed through the ordinary reservation
cooldown, never the corruption quarantine (`pag_disklive_q`). Progress path:
`mxfs_pubob_drive_publication()` after 4 refusals in one allocation; storm case →
`P946-DIALLOC-PUBPEND-STORM` → `-EAGAIN` into the existing sweep backoff, never ENOSPC. A/B knob
`mxfs.dialloc_pubpend_refuse` (default 1). Evidence it works and is mechanistic, not
absence-of-failure: `P-FREEOB-CHAIN-LIVE` (local re-allocation of a number whose free is still
unpublished — exactly the defect's population) is 0 in every fix round vs 205-209 in the
interleaved control. the derived-budget rule cost owed: fix arm ran 3900-4700ms vs control's 3100-3300ms for the
same 600 free+create pairs, ~20-25% regression, plausibly from refusing the just-freed number —
must be measured on the full board, not this micro-loop.

**Why it isn't FIXED AND VERIFIED yet**: the control arm has never produced the actual shutdown,
so there's no failing control to measure the fix against. Four harness modes (`local`/`peer`,
`tight`-zero-length, `tight`-1M-fallocate, `dirchurn`) all read `DEADSHELL=0` across 10+ rounds
each — see `docs/history/docs/history/docs/history/compiled-d0944-d0948-allocator-campaign.md`. The
`P-CR63-SHELL` gate that must fire before `DEADSHELL` can be nonzero printed **0** in all 10
rounds of both arms — the classifier was never even reached, so none of that churn was testing
the path at all. The captured failure's shell was `mode=00 nblk=11`: mode already zeroed by the
free, eleven blocks still attached — not a state ordinary churn produces at any rate, but an
**interrupted inactivation** (free zeroed the mode; the truncate's extent removal never finished
in core before a log shutdown+rejoin). Next step identified: the death-lap harness
(`tests/d0944_death_rejoin_ab.sh`), which produced it 3 times in 16 laps; both
`MXFS_PRECHURN_KNOBS` and `MXFS_EXTRA_INSMOD_PARAMS` must be set because the lap rmmods/insmods
between where a sysfs knob is set and the free under test — a sysfs-only knob is gone by then.

Companion technique for *why* it took three harness modes to even get this far:
[[technique-read-the-shell-dump-fields-to-identify-what-object-the-defect-needs]] — the captured
`nblk=11` didn't match the workload file (`fallocate -l 8M` = 2048 blocks at 4K); 11 blocks meant
a directory that had outgrown shortform, i.e. the object racing the allocator was the churn
**directory** removed by `rm -rf`, not any file in it. Converts an expensive death-injection
reproducer into a plain mkdir/fill/`rm -rf`/mkdir loop, no sync, no fault injection, no rejoin.
When a reproducer won't fire, re-read the one captured instance's own dump fields instead of
building a bigger workload — a field like `nblk` is an identity, and a mismatch against the
workload means you're churning the wrong object.

Measurement-integrity technique from the same rounds:
[[technique-a-vacuous-clean-run-is-detected-by-counting-the-gate-not-the-outcome]] — 16 rounds
scoring `DISKLIVE=0 DEFERLIVE=0` read as "did not reproduce" but also scored zero
`P-FREEOB-CHAIN-LIVE` and zero `P946-VALIDATE-ALLOW`, meaning the code path never ran. Two
harness properties were closing the window: a `sync -f` between create/delete passes published
every owed free before reuse could race it (removing all syncs made the gate fire 40× in 6
rounds), and zero-length test files leave `i_mode==0 && i_nblocks==0`, both terms of the entry
condition false, so even without sync the create can't reach the recycle gate. Resulting rule:
every defect-harness round reports its own gate-fire count, and a zero-outcome round with a
zero-gate-fire count is reported as VACUOUS, never as "not reproduced". Second trap in the same
instrument: both A/B arms sharing one `static atomic_t` rate limiter meant the fix arm burned all
32 print slots in round 1 and silenced the control arm's prints for the rest of the run, making
"the control never fired" a misread of the log — its `CHAINLIVE` counter (201 in one round) said
otherwise. One rate-limit counter per arm, or the louder arm silences the other and the A/B
reports backwards.

## D-0947 — filed, first fix retracted on rig evidence (sess572)

`mxfs_dbg_disk_di_mode_coherent()` returned the same `0xFFFF` for "the read failed" and "the read
succeeded, no inode magic present" — the D-0946 validator mapped both to `-EIO`, and on a
filesystem 7% full with 1% of inodes used, ALL 600 creates failed, permanently, mount healthy, no
corruption logged. First fix separated the outcomes
(`mxfs_dbg_disk_di_read_coherent(mp, ino, &mode, &gen, &magic)`) but then allowed the no-magic
case on the argument that a dinode keeps its magic even after being freed, so no magic proves
nothing was ever written there — every clause individually true, conclusion false. 13 rounds
(~11,700 creates, further than a prior build that died at round 10) passed before round 14
allocated a home block still holding `XDD3` — a live directory data block. 0.75.119: flush owed
publications first (`mxfs_pubob_flush_owed()` = log force + AIL push), re-read, then
`P947-VALIDATE-DESTAGED` (allocate, it's ours) or `P947-VALIDATE-NOMAGIC` (transient refusal).
Neither blanket policy survives: the old build failed every create; the naive fix could still
shut the filesystem down. See `docs/history/docs/history/docs/history/compiled-d0944-d0948-allocator-campaign.md`.

## D-0948 — new, critical, open (sess572)

A block that was a live dir3 data block owned by a specific inode (ten `P-BLKWR` platter writes)
had an inode chunk carved over it 51s later (AGI grew 3968→4000). 15ms after the carve, the
platter still held the old `XDD3` image with its own blkno in the header. A create that landed on
it failed `xfs_inode_buf_verify` 8 times and shut the filesystem down on a dirty transaction.
Offline `tools/chk_mxfs -v` confirms every AG's BNO btree verifies against its AGF — no
cross-allocation bug, the block legitimately belongs to the new chunk and the stale content is
simply the previous owner's. Two candidate causes, opposite fixes, not yet separated: the
SYNCINIT FUA write that should have overwritten the block never landed, or it landed and
something wrote the old image back afterward. `P948-SYNCINIT-READBACK` is in tree to
discriminate — a write returning success is not evidence the bytes are actually there. (Same run
also showed gross SB counter divergence, `icount 64` vs inobt 4000 — that's the separate D-0133
family, not this.)

## Rig fixes worth keeping (sess572)

`scripts/module_swap_deploy.sh` rewrote `.cluster_marker.json` without the `dev` field it had
just read from it, so the **second** consecutive swap fell through to a nonexistent
`/dev/mapper/mpatha` after every node was already torn down.
`tests/d0946_disklive_knob_vs_aging.sh` gained a `tight` mode (no sync anywhere, free and
re-allocate interleaved, files carrying blocks), per-round gate-fire counters, and an explicit
VACUOUS verdict — its earlier 16 "clean" rounds were retroactively identified as vacuous, not
clean.

## Standing status at end of sess572

D-0944: fixed (publish-before-dirty + symlink case), F&V pending full board pace measurement.
D-0945: gate landed and observed firing; release-path audit closed (all 8 primitives gated).
D-0946: shape-B fix landed and mechanistically verified (0 vs 205-209 on the targeted counter);
not F&V — no reproducer yet drives the actual shutdown through the fix; death-lap harness with
both env vars set is the next attempt. D-0947: fix iterated once already, current form
(0.75.119) unverified beyond 13+1 rounds. D-0948: open, root not yet separated between "FUA
never landed" and "stale image written back after landing". Open defect count 87→89 over the
session.
