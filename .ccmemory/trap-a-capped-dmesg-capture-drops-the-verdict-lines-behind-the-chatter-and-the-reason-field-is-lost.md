---
name: trap-a-capped-dmesg-capture-drops-the-verdict-lines-behind-the-chatter-and-the-reason-field-is-lost
description: TRAP (0.90.12): dirshard_reuse_peer saved `dmesg | grep ... | head -80`; 442 SHELL-ADOPTED lines filled the cap and none of the 12 CORRUPT lines (rea…
metadata:
  type: feedback
tags: [harness, evidence, capture, dirshard]
---

# A capped capture keeps the chatter and drops the verdict

**What happened (2026-09-28, 4/cawd, chain 116 lap 3).** `tests/dirshard_reuse_peer_list.sh`
counted `P-DIRSHARD-CORRUPT=12` on the peer from a live `dmesg | grep -c`, then saved the
evidence with one grep over every dirshard probe piped through `head -80`. The 442
`P-DIRSHARD-SHELL-ADOPTED` lines came first in the ring, so the saved `dmesg_test3.txt` held
80 of them and not one CORRUPT line. The defect record was opened with a count and no
`reason=` field; the reason (`manifest-block reason=blk_owner aux=120`, the stale block's
previous owner) had to be recovered a session later from the node's journal, which only
worked because the node had not rebooted.

**The rule.** A capture that feeds a verdict saves the verdict-bearing lines in full and caps
only the chatter, in a separate grep. If the rare lines and the frequent lines share one
pipe, the cap always chooses the frequent ones. The count in the markers file is not the
evidence: the line with its fields is.

**Fixed in** `tests/dirshard_reuse_peer_list.sh` (two greps: CORRUPT/STRANGER/GONE/
UNCONVERGED/LOAD-FAIL/IGET-FAIL/splats uncapped, SHELL/BLK chatter capped).
