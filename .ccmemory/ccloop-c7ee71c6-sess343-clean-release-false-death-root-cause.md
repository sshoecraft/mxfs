---
name: ccloop-c7ee71c6-sess343-clean-release-false-death-root-cause
description: sess343: sess342 mass-unmount incident ROOT-CAUSED — clean FLAG_EMPTY slot release read as death by peer monitors (no EMPTY arm); ledgered #92/#93; f…
metadata:
  type: project
---

# sess343 — mass-unmount false death root-caused, ledgered

## Disproved (sess342 theory)
"Heartbeat publishing stops at umount entry" is FALSE. Unmounting nodes' hb threads ran fresh timestamps until DLM shutdown (no P-HB-SLOW/P278/P236 anywhere). The "frozen" timestamp peers saw is the final record content of a slot that was already CLEANLY RELEASED.

## Proven mechanism (D-CLEAN-RELEASE-TREATED-AS-DEATH-PHANTOM-RECOVERY-526)
- mxfs_disklock_release_slot (dlm/disklock.c:2042) stamps FLAG_EMPTY, keeping node_id/epoch/last timestamp.
- Monitor loop has arms for pending(:1124)/WITHDRAWN(:1319)/inactive(:1343)/ACTIVE-ts(:1515) — NO clean-departure arm. EMPTY → :1343 → equal_samples++ → 31 checks (62s) → check_dead FUA confirm (:1608) requires flags==ACTIVE + advanced ts so can NEVER cancel → fire_dead → fence attempt + P163-RECOVERY-PENDING on a clean slice.
- hb_still_dead_stamp(:532) returns TRUE for EMPTY-with-victim-stamp → latch never self-clears → lone survivor (test2) livelocked re-electing replayer, all replays refused "no proven exclusion (-2)".
- Fence no-op was luck: P238-FENCE-NOINTENT rc=-116 because clean unmount already dropped victim's PR registration.
- Slot→host map (this fleet gen): slots 1,2,16,19,23,26,29,30,31 = test10,16,14,8,18,5,4,21,20; test3=13, test2=20... (full map in sess343 transcript).
- Evidence: tests/evidence/sess343_mass_unmount_false_death/.

## Also ledgered #93 D-MASS-UMOUNT-ROOT-EX-SERIALIZE-100S-526B
31-way simultaneous umount of QUIESCENT fs: each slow node blocked ~60s on root ino=128 EX handoff chain (test3 P139-LOCKTOTAL total_ms=60135 retries=3), teardown ~100s total. RULE 0 violation and the enabler that kept slow nodes' monitors alive to false-fire.

## Next (sess344+)
1. RULE-5 consult on fix shape: monitor EMPTY clean-departure arm (FUA-confirmed un-monitor, no fence/pending); pending-block EMPTY recognition to CLEAR latch; hb_still_dead_stamp EMPTY arm; EMPTY→claimant race.
2. Land, build (rev patch ver), deploy, re-prep (cluster is DIRTY but harvested — safe to re-prep).
3. Verify via d513_lone_mount_torn.sh step-1 mass unmount (the trigger), then resume #90 A5.
