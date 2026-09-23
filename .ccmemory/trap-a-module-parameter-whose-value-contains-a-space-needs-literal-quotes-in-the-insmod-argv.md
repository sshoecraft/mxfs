---
name: trap-a-module-parameter-whose-value-contains-a-space-needs-literal-quotes-in-the-insmod-argv
description: TRAP (s80): the kernel joins insmod's argv into one string and splits on whitespace, so a charp param value with a space arrives truncated unless the…
metadata:
  type: feedback
---

## What happened

0.89.13 added `target_retire_contract`, a `charp` module parameter whose value is
`<vendor>:<product>:<revision>:<lun>:<clause>` — and this target's product id is
`iSCSI Storage`, with a space in it.

Passing it the obvious way delivered only the first word:

```
insmod mxfs.ko target_retire_contract="QNAP:iSCSI Storage:4.0:naa.…:clause"
  → /sys/module/mxfs/parameters/target_retire_contract == "QNAP:iSCSI"
```

The module then refused every certificate for a product mismatch it had invented
itself (`the contract names product 'iSCSI'; this LUN reports 'iSCSI Storage'`).

## Why

The shell strips the quotes, so `insmod` receives ONE argv element containing a
space. kmod joins argv with spaces into a single options string, and the kernel
splits that string on whitespace in `next_arg()` (`/src/linux/lib/cmdline.c:227`).
`next_arg` honours `"` — it keeps spaces while `in_quote` — but the quotes have to
still be THERE when the kernel sees the string.

## The form that works

The argv element must contain literal quote characters:

```sh
insmod mxfs.ko 'target_retire_contract="QNAP:iSCSI Storage:4.0:naa.…:clause"'
# or, from a bash array (tests/setup/prep_node.sh):
ARGS+=("target_retire_contract=\"${VALUE}\"")
insmod "$KO" $MODARGS ${ARGS[@]+"${ARGS[@]}"}
```

Verified on test2: with the escaped form the sysfs readback is the whole
five-field string; without it, `QNAP:iSCSI`.

## The lesson beyond the quoting

The bug was caught only because the harness asserted, as a non-vacuity gate,
that the module actually held the value the arm intended
(`cat /sys/module/mxfs/parameters/<name>` compared to what was passed) before
grading anything. Without that gate the lap would have read as "the gate refuses
even on a qualified LUN" — a false FAIL against the feature under test. Any
harness that configures the module through a parameter should read the parameter
back and assert it, not assume the load took.
