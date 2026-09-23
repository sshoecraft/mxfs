<!-- sess487 RULE-5 ruling: in-tenure create 16 ms must fall to ~6 ms AND handoff <~31 ms/tenure; order dirsig release-only -> rfr once-per-tenure -> spli… -->
# GPT RULE-5 ruling on the chain-137 decomposition (sess487)

Input: shared in-tenure create 16.0 ms = icr 4.6 + dirsig 4.5 + other 2.3 +
rfr 1.1 + post 1.1 + dlk 1.0 + dia 0.8 + pdur 0.4 + cc 0.2; private 6.8
(dia 4.2). persig mode 2 not an ablation. Tenures K~10-11, gap p50 ~8 s.

## Arithmetic
T = N(c + h/K), N=3200. For 30 s: c < 9.375 - h/10 ms -> 7.9 (h=15), 6.4
(h=30), 4.4 (h=50). Removing dirsig + amortised rfr + icr excess gives c ~6.2
-> 24.7 s (h=15), 29.5 (h=30), 35.9 (h=50). Larger K (~16) is the second
lever only if handoff stays >~31 ms. The serial model explains 56-67 s of the
85-88 s: reconcile the gap (per-node rotation waits are not additive global
work; first-in-tenure tails; 2853/3069 samples vs ~3200) before predicting.

## Per term
- dirsig: release-only is correct IF invariant 1 holds. Invariant: once a
  peer can acquire a conflicting grant and cold-read, disk has every
  committed modification of the prior EX tenure. Proof: handoff test with
  deletes LAST, peer forced acquire + FUA reload, holder killed right after
  unlock in some runs, trace order last-mutation < drain-complete <
  unlock-visible < peer-reload; real row: dirsig ~0, one drain per tenure,
  handoff cost measured, no acquire timeouts / mass shutdown (the sess7 mode).
- rfr: replace `i_dlm_dir_gen > 0` with a current-EX-tenure validation
  token: held EX && validated_ex_epoch == current EX epoch && no
  invalidation/recovery/inode-recycle since && op admitted before the demote
  barrier. EX->PR->EX = new epoch. Expected ~1 ms/create.
- icr: split lookup vs xfs_icreate first; inside iget split cluster-buffer
  read (cache vs FUA) vs cluster-grant claim (queue vs CAW service). Control:
  a large private dir (~3200 entries). Per-node inode chunk affinity is a
  legitimate allocator PREFERENCE (fallback, no stranding, reclaim on
  failure) only if the split blames the shared cluster; not if lookup.

## First change
dirsig release-only (A: persig=1, B: no per-modify flush + mandatory drain
before downgrade). Both halves required: the sess48 cold-read test clean AND
the row's dirsig ~0 with handoff measured. Expected saving <= 14.4 s; not a
pass by itself.

## Not supported by the numbers
That the terms explain 85-88 s; that removing them guarantees a pass; that
all 4.3 ms icr excess is cluster contention; that 0.3 ms icr is attainable on
a 3200-entry dir; that mode 2 tested release-only; that larger K is required;
that means suffice (tails, counts, unsampled creates matter).
