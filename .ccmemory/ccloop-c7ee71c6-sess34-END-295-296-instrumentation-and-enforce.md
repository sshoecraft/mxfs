---
name: ccloop-c7ee71c6-sess34-END-295-296-instrumentation-and-enforce
description: sess34 late: 295 (P239/P240 identity traces, myslot, SELF-ORPHAN detector) + 296 (pub_obligation_enforce=1) both boarded green; P239 first capture =…
metadata:
  type: project
---

# sess34 late — 295/296 state (follow-on to sess34-coldread-blindclose note)

## 0.11.295 (6E09D06EC14F20224BD303F) — instrumentation, board green
- P239-OVERLAY-ID (xfs_inode.c merge helper): unconditional trace at any
  overlay of a slot with flush!=durable — bp, relflush, dlm_mode, seqs.
- P240-COPYIN-ID (xfs_iflush tail, RELFLUSH-gated): ino+bp+seqs — the
  pairing side.
- P-ACQ-STUCK now prints myslot= (portable loop, NOT __ffs64 — dlm/
  builds user-mode); new P-ACQ-SELF-ORPHAN when sole wire holder ==
  own node_bit while our waiter starves.
- dlm_fairness FAILed 2× at budget under EXTERNAL host load (Wow.exe
  362% + worldserver 214%); PASS 15s/30s at load 17. Standing: check
  `ps -eo pcpu,comm --sort=-pcpu | head` before believing a budget FAIL.

## First P239 capture (amplified lap, fix27=25ms, disarmed after)
test5 ino 8390564: overlay condemned flush=7 dur=5 at relflush=0
dlm_mode=5 (EX) — the AUTHORITY-GAP class (provenance mismatch), comm=
xfsaild, bp=...c3641540; P240s for same ino show bp ...b953bb80 →
...b953f2c0 → ...b973bfc0 across 40s = THREE buffer instances for one
cluster — instance replacement ROUTINE (items detach at each iodone,
buffer reclaimed, fresh instance next flush). Merge/ledger design must
not assume buffer identity stability. Incident-class P239 (relflush=1)
not yet captured — the pairing is armed for it.

## 0.11.296 (46CF551A3D09E9A4C2B1315) — pub_obligation_enforce=1
Release-drain P146V re-log arm ON per Gemini 2b (re-log under current
tenure = principled provenance re-stamp via journal). Partners P236
gate. Full board 24 PASS. P176 engagement 0 so far.

## NEXT (in order)
1. Fail-closed copy-in (Gemini 2a) — CONSULT FIRST on the log-tail-
   pinning hazard: a refused mid-tenure item pins the log tail; needs a
   mid-tenure re-log worker (pattern at xfs_mxfs_dlm.c ~16118 trans_
   alloc+ilock_nowait arm) or an explicit ruling that release-time
   re-log suffices.
2. CAW abandoned-grant reap: WAIT for next orphan capture (myslot now
   names owners; harness self-captures). Reap design agreed (RELEASE
   not adopt, release_unconditional's seq-abort parries live grants) —
   implement after the birth path is named.
3. Ledger backlog: D-SILENT-MKDIR-LOSS reproducer, D-UNMOUNT-BUSY,
   D-RELEASE-BARRIER remaining GPT criteria, D-MATRIX, D-FOREIGN-REPLAY,
   pace pair, D-CAW-YIELD disposition review (292 fix shipped+A/B'd).
4. Rig: test19-23 ring drift FIXED (16M grub) — if ANY node shows tiny
   dmesg span again, check /proc/cmdline first (see rig-test19-23 note).
