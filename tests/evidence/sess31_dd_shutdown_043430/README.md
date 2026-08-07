# sess31 dd-shutdown evidence — 32-node capture

Cited by `tests/criteria/OPEN_DEFECTS.json` and by ccmemory
`ccloop-c7ee71c6-sess31-ROOT-FIXED-caw-yield-starvation-shutdown`.

- `btime_test1..32` — per-node boot times, kept uncompressed (they are tiny
  and are the thing you usually want first).
- `dmesg-all-32-nodes.tar.gz` — the full dmesg from all 32 nodes.
  188.6MB loose, 21.0MB archived (9.0x). Verified byte-identical on
  round-trip before the loose copies were removed.

Restore with:

    tar xzf dmesg-all-32-nodes.tar.gz

Read one node without unpacking the rest:

    tar xzOf dmesg-all-32-nodes.tar.gz dmesg_test19 | less

The archive is committed rather than the loose files because 188.6MB of
dmesg in git history is not a reasonable cost for evidence that compresses
9:1. Nothing was summarised or truncated — RULE 6 evidence is preserved in
full, only its on-disk form changed.
