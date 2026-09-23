---
name: trap-a-membership-exemption-justified-for-live-coherency-is-not-justified-for-crash-replay
description: TRAP (0.87.16, D-LONE-MOUNT-...AUTH-NOT-HELD): "no successor writer can exist for what a never-multi mount logs" ignored the replayer; every inode-ow…
metadata:
  type: feedback
tags: [D-LONE-MOUNT, never_multi, authority, foreign-replay, harness]
---

# A membership exemption argued from live coherency is unsound the moment a crash makes a successor

**What happened.** 0.83.3 (D-0955) kept one membership state exempt from the inode ownership
protocol: a mount single-node NOW that had NEVER had a peer (`mxfs_v5_dlm_never_multi()`).
The argument: its caches hold nothing but its own images, so a whole-buffer write publishes only
its own bytes, and "no successor writer can exist for anything it logs". A lone TCP mount then
did mkdir + 40 creates + fsync and was destroyed within a second (s53f, run by a harness for a
different record). The returning incarnation replayed the slice as a foreign slice: the
directory-block image carried authority class NONE / status AUTH_NOT_HELD, the whole
transaction was atomically skipped, AG 0 was quarantined cluster-wide, and every root lookup
answered EIO. 40 fsynced files lost from view.

**Why.** The replayer of a dead node's slice — a survivor, or the same node's next incarnation
— IS the successor writer for everything the victim logged, and it authorizes each inode-owned
image (dir block, bmbt block, remote symlink/attr block) only against the durable grant the
owner held at capture (frozen manifest, per-image token). The exemption meant no inode on a
lone mount ever had a DLM mode, an authority state or a grant. The AG path had no exemption
since 0.41.0, which is why the same transaction's six AG images were VALID. Instrumented
(tests/lone_dir_block_authority.sh s54a/s54b): 45 non-durable captures of the directory's block
at authority NONE / mode NL on the lone mount, zero with a peer mounted; after the fix (s54c)
zero on both.

**The corrected invariant (design consult 2026-09-18, shape A over a narrow divert and over a
replay-side "never had a peer" certificate):** being alone permits omitting coordination with
live peers (is_single_node shortcuts that signal nobody); it never permits omitting the durable
authority a future incarnation or foreign replayer needs. Before the first dirty capture of an
inode-owned, replay-protected image the inode must hold durable authority and the token must
name it at capture; later promotion cannot repair a token already captured NONE.

**Lessons.**
- When a design argument says "no X can exist", enumerate the post-crash actors too: the
  replayer, the returning incarnation, the survivor taking over ledger pages.
- A lone mount is not a corner case in a 2-node release: every formation's first node runs
  alone until the second mounts, and a crash in that window hit this.
- The cheapest proof of a capture-time hypothesis is the same workload without a crash, read
  through the producer's own probe (P239-OWNAUTH-NONDUR carries outcome/mode/unpub), on two
  arms that differ only in membership.
- Harness traps met on the way: never reformat the LUN under a peer still mounted on the old
  filesystem (it is fenced, withdraws, and its module cannot be unloaded — VM reboot);
  `xfs_bmap`/`xfs_io` cannot read an MXFS extent map (the XFS ioctl file is not compiled) — use
  `filefrag`; a verdict grep for `refus` matches the fence protocol's own "refusing the claim"
  stage lines and `mismatch` matches `inc_mismatch=0` — assert the image-refusal probes
  (P227-FR-ATOMIC-SKIP, P241-RECOV-TERMINAL, P240-QUAR) and the per-transaction
  `P227-TOKENSUM wskip=0` instead.
