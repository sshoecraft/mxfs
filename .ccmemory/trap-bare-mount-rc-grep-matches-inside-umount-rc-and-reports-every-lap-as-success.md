---
name: trap-bare-mount-rc-grep-matches-inside-umount-rc-and-reports-every-lap-as-success
description: TRAP (sess570): grep -o 'mount_rc=[0-9]*' also matches INSIDE 'umount_rc=0', which is printed FIRST — so every death lap read as mount_rc=0, includin…
metadata:
  type: feedback
tags: [trap, harness, sess570, mis-reporting, d0944]
---

# `mount_rc=` is a substring of `umount_rc=`, and the unload line comes first

## What happened

`tests/d0944_death_rejoin_ab.sh` extracted the death-lap verdict with

```sh
mrc=$(grep -ao 'mount_rc=[0-9]*' "$OUT/lap_$i.log" | head -1 | cut -d= -f2)
```

The harness prints, in this order:

```
  INFO UNLOAD umount_rc=0 umount_ms=5800 rmmod_rc=0 loaded=0
  INFO INSMOD_OK sv=... REJOIN mount_rc=32 mount_ms=3209 mounted=0
```

`grep -o` matched **inside `umount_rc=0`**, `head -1` took it, and every lap in
every arm reported `mount_rc=0`. The driver's own `rejoin_ok/rejoin_bad` tally
was therefore uniformly "all clean" — on a run where **5 of 7 control laps had
actually failed to mount with rc=32**.

The A/B looked like "control 4/6 ok, fix 6/6 ok" — a weak, unconvincing result.
The truth was "control 5 of 7 FAILED, fix 8 of 8 clean", which is the opposite
in strength and is what the fix actually did.

## Why this one is dangerous

It fails in the direction of **good news** and it is *silent*: no error, no
missing field, a plausible number in every row. It also survived a second
instrument — the shadow-verdict vector printed beside it was correct, so the two
lines in the same report disagreed and nothing complained.

This is the second time this project has produced the sentence "my summary said
`mount_rc=0` for a round that had failed at 32" (sess567 said it too). Treat any
unanchored `grep -o '<field>=[0-9]*'` as suspect when another field in the same
stream **ends with** that field's name.

## The rule

- Anchor the extraction to the line that owns it:
  `sed -n 's/.*REJOIN mount_rc=\([0-9]*\).*/\1/p'`.
- Prefer the node's own evidence file (`rejoin_$A.txt`) over the harness's
  stdout: fewer neighbouring fields, one line, one meaning.
- When a driver summarises a harness that already prints PASS/FAIL, cross-check
  the driver's verdict against the harness's own `ck` line at least once. Here
  `FAIL test1 rejoined the cluster with no operator action got=mount_rc=32` was
  sitting in the same file the driver was parsing.

## Related trap in the same driver

`ATOMIC-SKIP` and `P227-FR-TORN-UNPUBLISHED` are printed by the **survivor's
kernel**, not by the harness. Counting them from the harness's stdout returns 0
on a lap that refused the whole slice. Read them from node B's dmesg.
