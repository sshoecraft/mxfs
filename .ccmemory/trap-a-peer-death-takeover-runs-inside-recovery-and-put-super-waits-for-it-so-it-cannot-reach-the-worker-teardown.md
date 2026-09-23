---
name: trap-a-peer-death-takeover-runs-inside-recovery-and-put-super-waits-for-it-so-it-cannot-reach-the-worker-teardown
description: TRAP (sess588, D-0953): a virsh-destroy repro put the ledger takeover inside the peer's recovery, which put_super waits out — the worker-vs-teardown…
metadata:
  type: feedback
tags: [trap, dlm, departure-worker, harness-shape, D-0953]
---

# A takeover that runs inside recovery is not the one the unmount races

The previous session's D-0953 harness destroyed peer B and unmounted survivor A while A was taking over B's pages. On 0.84.x that takeover runs synchronously inside the elected replayer's recovery (`P-TAUTH-TAKEOVER-RUN why=recovery-complete`), and `put_super` waits for the recovery to complete before `DLM shutting down` — measured s588a: an unmount issued 139 s into a 7999-page pass returned after 105 s with the pass complete, `P-TAUTH-TAKEOVER-INTERRUPTED` never printed. The lap looked like a clean unmount and proved nothing about the fix.

The passes the departure WORKER runs outside recovery, which is where the s574xm crash stack was (`v5_depart_run -> v5_handoff_takeover`):
- `v5_settled_incarnation` — a node that left as the LAST member keeps its pages (`mxfs_dlm_handoff_depart`: nobody to hand them to); on its lone remount it settles its own predecessor and queues a takeover-only pass of ~all pages (15.6k behind 16000 creates, ~13 s per 1000 pages). This is "the sole survivor's ghost".
- goodbye / clean-release of a peer (usually few pages: the peer handed most off itself, via=frozen-msg).
- the orphan sweep queued after every departure and at a bootstrap mount.

The deterministic repro (tests/depart_takeover_unmount.sh DEATH=ghost): B unmounts, A builds alone, A unmounts as last member, A remounts alone, unmount A ~12 s later while `P-TAUTH-PAGE-MINE via=takeover` is still arriving.

Two things the ghost laps then found: (1) a joiner that mounts while the bootstrap's orphan sweep is in flight exhausts its root-inode retries on remaster and self-shuts down (D-0960; `MXFS_JOIN_WAIT_PATTERN` in module_swap_deploy.sh holds a harness re-form's joiners until the sweep line); (2) every departure queues a sweep, so the first full sweep is followed two seconds later by an empty one — read `tail -1` of the sweep lines and you score the leftover pages as never taken.
