---
name: sess40-FIX-tcp-flap-prevention-send-no-teardown
description: sess40 KEEPER build A985424B: dlm/peer.c flap-prevention (transient send timeout no longer tears down socket). Helps mass-fail mode; does NOT fix 799…
metadata:
  type: project
---

## sess40 (ccloop 4cb2d0a2) — KEEPER build `A985424B9BCBE303FCE35FA`. TCP flap-prevention.

### The fix (KEPT, dlm/peer.c mxfs_peer_send ~line 914)
A TRANSIENT send failure (`-ETIMEDOUT`/`-EAGAIN`/`-EWOULDBLOCK` = peer's receiver slow / sndbuf full under the 8-node storm, NOT dead) no longer `mxfs_pal_tcp_shutdown()`s the socket + fires `disconnect_cb`. It unlocks + returns `-EAGAIN`, keeping the connection up (caller retries; TCP still holds the buffered bytes). Only a HARD error (ECONNRESET/EPIPE/ENOTCONN/...) tears down + reconnects. True death still caught by TCP keepalive (~19s) + UDP lease (~75s). Reduces self-inflicted disconnect flaps + the membership SUSPECT churn under load.

### Effect (validated)
8/tcp dir_reuse 3/6 → **6/8**; 2/tcp dir_reuse **3/3** (no regression). Helps the MASS-FAIL (membership-flap >15s → declared-dead → split-brain) mode.

### IMPORTANT: this does NOT fix the readdir=799 single-dirent loss
PROVEN this session (see [[sess40-CORRECTION-799-is-concurrent-add-not-flap-bmbt-extent-fork]]): with this fix active, 8/tcp still loses one dirent at round 1 with ZERO flap events in dmesg. The 799 is a concurrent-add lost-update (likely the dir inode/bmbt EXTENT FORK, which dataclobber doesn't cover), NOT a transport flap. The flap↔loss correlation that motivated this fix was coincidental.

### REVERTED dead-end (do NOT repeat): kern.c mxfs_pal_tcp_send return-code change
Tried making `mxfs_pal_tcp_send` return `-EAGAIN` (done==0, nothing sent → safe keep) vs `-ECONNRESET` (done>0, partial sent → desync → reset) instead of uniform `-ETIMEDOUT`, to harden peer.c against a partial-send desync. Build `5A98FD22`. **REGRESSED 2/tcp dir_reuse to 0/3** (corrupt=0 = hang/timeout). ROOT: `mxfs_pal_tcp_send` has MANY callers (discovery/lease/journal/md_request) that retry-loop on `-EAGAIN` → infinite retry → hang. The flap-prevention must live ENTIRELY in dlm/peer.c (which treats `-ETIMEDOUT` as keep-socket); pal keeps returning `-ETIMEDOUT` uniformly. Reverted → reproduces A985424B exactly. The rare partial-send-then-timeout desync is tolerated (A985424B passes 2/tcp 3/3, 8/tcp 6/8; a desync self-heals via the eventual hard-error reset).

### NEXT (criterion still not met)
- The 799 = concurrent-add/extent-fork lost-update → add an inode/bmbt extent-fork write-chokepoint detector ([[sess40-CORRECTION-799-is-concurrent-add-not-flap-bmbt-extent-fork]]).
- The mass-fail/membership-flap mode → GPT-5.5 reliable-midcomms roadmap (seq/ack/resend-on-reconnect/dedup + grant-gen cookies) in [[sess40-REFRAME-799-is-tcp-flap-not-buffer-barrier-noop]].
- Re-verify 1/2/4 tcp on the keeper before any criterion claim.
