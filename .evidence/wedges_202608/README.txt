wedgeA_boot_20260820_deflooded.klog.gz
  source: journalctl -b -2 -k  (2026-08-20 15:26:39 .. 19:24:43 CDT)
  total kernel lines in that boot: 1075008
  dropped (SCST per-IO atomicity trace flood): 994223
  kept: 80785

NOTE: this journal has NO BUG:/Oops lines - journald stopped writing when
the root ext4 wedged.  That boot's nine oopses are in pstore, NOT here.
See docs/host-safety.md and /var/lib/systemd/pstore/7675903811256320028.
