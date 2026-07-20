---
name: sess20-PROVEN-bgen0-leaf-clobber-discriminator
description: sess20 PROVEN (RULE 4): crash_consistency/cc_blockdir leaf-hash clobber = xfsaild flushing a leaf with b_mxfs_dir_gen=0 (stale image) over disk super…
metadata:
  type: project
---

## sess20 (ccloop 8ddb16a2) — DECISIVE image-origin discriminator captured.

Build 5E54558B (E99A445B + bgen added to P16-DIRBLK-SUBMIT and P-LEAFWRITECLOBBER). cc_blockdir_probe 30 50 with dirwr=1, short at iter15: readdir=200 lookup_fail=1 (LEAF-HASH inconsistency), durable (pureLUN/direx/+8s all 199), missing node2_f48.md5, test2/LUN also lacks it.

## CAUGHT (test2 dmesg): `P-LEAFWRITECLOBBER daddr=2097480 buf_cnt=119 disk_cnt=202 bufgen=0 comm=xfsaild/sda`. The clobbering leaf buffer has **b_mxfs_dir_gen=0** (the value set by mxfs_dir_evict_data_blocks at acquire, or fresh-init) — a STALE image that was repopulated/kept WITHOUT being re-stamped to current gen (GPT Hole B: readahead-style repopulation; readahead bypasses xfs_da_read_buf stamping).

## CONTRAST (same dir, same node, P16-DIRBLK-SUBMIT): the legit current-tenure DATA/BLOCK writes show `nl=0 dgen=270 lgen=270 bgen=270` and `dgen=284 bgen=284` — bgen==dgen (properly stamped, fresh). So the discriminator is clean: **bgen < i_dlm_dir_gen = stale-base image; bgen == i_dlm_dir_gen = current/fresh.**

## WHY existing guards miss it: mxfs_buf_xfsaild_skip_dir_write skips only nl_released (NL) or tenure_mismatch (detector-only, disabled — false-pos on fresh leaf w/ unset owner). The clobber is nl=0 (EX held) + b_tenure_id==epoch (touch-stamped current) yet STALE CONTENT. Tenure stamp = touch, not image-origin. b_mxfs_dir_gen IS the image-origin epoch (stamped at read; 0 after evict; modify path stamps only b_tenure_id NOT b_mxfs_dir_gen).

## FIX (sess20, being implemented): write-submit chokepoint always-on guard. For a leaf1/leafn write, multi-node: look up owner dir i_dlm_dir_gen (mxfs_buf_xfsaild_skip_dir_write fills dsi.dir_gen). If bp->b_mxfs_dir_gen >= dir_gen → normal write (fast path, no disk read). Else (bgen<dgen): plain-bdev read disk leaf; if valid LEAF1/LEAFN magic AND disk owner==buffer owner AND disk_cnt > buf_cnt → SKIP the write (emulate clean ioend like P61) + clear XBF_DONE|_XBF_FUA_FRESH so next read refetches the durable superset. SAFE: bgen==dgen covers all legit current-tenure adds AND removes (no disk read); fresh-leaf creation has disk!=valid-leaf or different owner; create-on-fresh-base has disk_cnt<=buf_cnt. Disk read only on rare bgen<dgen leaf writes (perf-bounded, RULE 0).

## NOTE: dirwr=1 HIDES the race in crash_consistency (passed 2/2) but cc_blockdir_probe (harsher) still fires it under dirwr=1. Default dir_no_reada=0, dirskip default on. Reproducer: MXFS_EXTRA_MODARGS="dirwr=1" then cc_blockdir_probe 30 50. [[sess19-GPT2-dir-index-freshness-barrier-fix-spec]] [[sess19-PROVEN-xfsaild-stale-leaf-reflush-clobber]] [[sess16-FIX-LEAD-extend-chokepoint-skip-to-dir-dirent-blocks]]
