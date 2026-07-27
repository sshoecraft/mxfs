---
name: ccloop-c7ee71c6-sess12-A-tcp-false-death-outbound-cb-ROOT-FIXED
description: sess12 ROOT+FIX (v0.11.114 71ABF349): 16/tcp collapse = outbound TCP reconnect never fired connect_cb → 40s timer declared LIVE peer dead → P164 exil…
metadata:
  type: project
tags: [tcp, peer, membership, p164, phantom-grant, rule4, rule6]
---

# sess12-A: TCP false-death of live peer — ROOT CAUSE + FIX (v0.11.113→114)

## Symptom (post-write-through-rebuild, idle cluster, NO fio load)
Fresh 16/tcp prep converged 16/16, then precond_readiness collapsed: test1 mkdir of
`.suite_readiness.*` in / needed EX on ino=128 (master=test2), got P-CONVBLK-DENY
(-EDEADLK, by design: PR→EX conversion denied), released PR, re-requested EX → 60×1.024s
P-LKTIMEOUT-REMOTE/P36-RETRY → rc=-110 twice → XFS shutdown → withdraw. 13 nodes had 2×
rc=-110 each. Survivors with 0 errors: test3+test8 — THE CULPRITS.

## Root chain (every step captured live)
1. Join storm t≈73: duplicate-connection churn (both sides initiate per id rule; accept
   path replaces existing conn) killed test3's socket to test16 0.86ms after "connected".
   v5 disconnect_cb → suspect armed: "deferring death 40000 ms".
2. ≤500ms later the announce-driven ensure-connected heal (v5_discovery_peer_cb) ran
   mxfs_peer_connect (test3 lower-id) → outbound reconnect SUCCEEDED. **peer_connect_impl
   never fired ctx->connect_cb (only accept path did, peer.c:405)** → suspect timer never
   cancelled; later announces see is_connected()==true → silent no-op.
3. t=113.7: v5_tcp_death_worker_fn declared test16 dead WHILE `ss -tn` showed ESTAB
   test3→test16:7600 (verified live; test8 identical). v5_tcp_declare_dead →
   mxfs_dlm_purge_node… wait, purge = ENTIRE local table wipe via update_active_nodes →
   test3's OWN live PR mirror on ino=128 (granted t=109.93 gen=28) vanished while master
   test2 kept the grant = MASTER-SIDE PHANTOM PR.
4. P164-DEAD-NOTE permanently exiled LIVE test16 (announces rejected 2/s forever);
   test3/test8 stuck at active_count=15 vs cluster 16 → hash-modulo resource_master
   DIVERGES → their FIX-20b P-PHANTOM-RECONCILE-SENT gen=0 releases (rc=0, ~90 sends)
   routed to the WRONG master (or self → silent return 0) → heal impossible.
5. BAST storm: master fired P7S-BAST-FIRE at all 15 PR holders; 13 released in ms;
   test3/test8 processed BAST but P6Z-REL-NOTHING (p_rel_gen==0, mirror empty) → skip.
   pr never reached 0 → EX starved forever. Amplifier: each 1s EX retry FREEs+re-ALLOCs
   the queued EX at master; PR re-grants slip into the gaps (readiness probes re-stat /).

## Fix (v0.11.114, srcver 71ABF349F3317056F4E4664)
- dlm/peer.c peer_connect_impl success tail: fire ctx->connect_cb (same cb accept fires;
  v5_peer_connect_cb_tcp is direction-agnostic: P164-gates, cancels pending death,
  re-registers lease, refreshes membership, engages memb-settle EX freeze).
- dlm/v5_mount.c v5_tcp_death_worker_fn: before declare-dead, if
  mxfs_peer_is_connected(peer)==ACTIVE → cancel ("suspect grace expired but peer socket
  is ACTIVE — cancelling death"). Invariant belt: never kill a peer with a live socket;
  half-dead ACTIVE can't hide (next send/recv errors re-arm suspect).

## Verification (deterministic repro)
`ss -K` the test5↔test11 DLM connection (RST both sides): both flap; test5 (lower id,
pre-fix would have declared test11 dead at t+40s) heals OUTBOUND in 0.64s with
"connected + cancelling pending death" from the NEW cb call (socket direction reversed
proves outbound); test11 heals inbound. 40s grace passed: zero declaring-dead/P164.
Fresh 16-node join after fix: 0 flaps, 0 deaths, 16/16 converged (216s prep).

## Revised sess11 disposition
The sess11-C "16/tcp collapse — likely infra (LIO write-back flood)" incident most
plausibly had THIS mechanism underneath (load → TCP drops → false deaths → divergence);
this session reproduced it at ZERO load, proving it load-independent mxfs defect.

## Related design notes (open, lower priority)
- update_active_nodes purges ENTIRE local table on ANY membership change (loses own live
  grants at surviving masters → phantom producer; FIX-20b/orphan-NAK are bandaids).
- EX queue-position loss on 1s retry re-queue + PR re-grants while EX queued (fairness).
- P164 retire on TCP-timeout death has no rejoin path for a live node (mitigated by fix).
- Membership has no cross-node consensus; views can fork silently (divergence detector?).
