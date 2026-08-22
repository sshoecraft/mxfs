The three guard_20260821_1501*/1504* directories are SYNTHETIC selftest
artifacts from validating tools/clyde_kmsg_guard.sh on 2026-08-21 (a benign
"Too big response data len 1 (max 0) (dev selftest)" line injected into
/dev/kmsg, and a benign kmsg flood).  They are NOT real incidents.
Real guard trips name a genuine kernel message in trigger.txt.
