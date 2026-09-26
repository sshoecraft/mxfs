---
name: trap-the-caw-timeout-classifier-runs-only-after-three-480s-attempts
description: TRAP (0.89.92): on CAW the 480 s liveness cap bounds ONE attempt; ilock_begin makes three, so the timeout classifier (P-LKWAIT-LIVE) runs only past 1…
metadata:
  type: feedback
tags: [caw, dlm, timeouts, trap]
---

The defect record for the live-holder self-shutdown said CAW reaches the classifier "at PAUSE_MS > 480 s". Measured wrong: at a 540 s holder pause the first CAW attempt hit 'disk lock acquisition timed out after 480061 ms' and mxfs_dlm_ilock_begin's second attempt was granted at 547 s — the classifier was never reached (caw0912_s2). Only at 1560 s did all three attempts time out and the classifier park the wait with P-LKWAIT-LIVE (caw0912_s3).

So: any lap meant to exercise the post-budget classifier on CAW needs the holder's pause past 3 x MXFS_CAW_WAIT_HARDCAP_MS (1440 s), not past one. TCP's equivalent is 3 x 60 x 1 s = 180 s. A lap that "passes" at 540 s has measured the retry, not the classifier.
