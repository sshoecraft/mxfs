---
name: trap-an-old-caw-key-is-the-multipath-rig-while-released-caw-was-cawd
description: TRAP (0.90.37): old key `N/caw` = disk/caw/mpath; released CAW was `cawd` = disk/caw/direct. Mapping prose "8 caw" mechanically mislabels releases.
metadata:
  type: feedback
tags: [configuration, criteria, defects, migration]
---

Before 0.90.37 the rig keyed configurations with condition codes. `caw` meant CAW over dm-multipath (the 32-node campaign rig), while every CAW *release* (0.90.7, 0.90.24, 0.90.36) was graded on `cawd` = CAW over direct single-path iSCSI. Release prose (README, CHANGELOG "8 caw --release") used `caw` loosely to mean "the CAW transport".

What bit: the mechanical rewriter (scripts/rekey_invocations.py) mapped README's `tools/defects.py 8 caw --release` to `8/disk/caw/mpath` — a configuration that was never released. Had to be hand-corrected to `8/disk/caw/direct`.

Also: `tcp` history before 2026-09-26 ran on LIO/QNAP (XML-wired /dev/sda), not direct iSCSI; it migrated under net/mesh/direct.

How to apply: when reading pre-0.90.37 records, `N/caw` is the mpath rig; "CAW release" means disk/caw/direct. Any mechanical translation of release-claim prose must be checked by hand. Map: tcp→net/mesh/direct, cawd→disk/caw/direct, caw→disk/caw/mpath, cawp→disk/caw/pass, tcpmp→net/mesh/mpath (data/configurations.json retired_keys).
