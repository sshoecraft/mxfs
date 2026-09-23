---
name: trap-a-module-param-holding-a-u32-node-id-must-be-uint-or-half-of-all-ids-are-refused-and-read-back-zero
description: TRAP (s136): pr_fence_submit_inject_victim was module_param int; node ids above INT_MAX are refused -ERANGE and the knob reads 0, which means "any vi…
metadata:
  type: feedback
tags: [kernel, module-param, injector, node-id, harness]
---

## What bit us

`mxfs_node_id_t` is `uint32_t` (`include/mxfs/mxfs_common.h:52`), and this rig
generates node ids uniformly across that range, so roughly every second one is
above `INT_MAX`.

`dlm/scsipr.c` declared the injector's victim filter as

    static int mxfs_pr_fence_submit_inject_victim;
    module_param_named(pr_fence_submit_inject_victim, ..., int, 0644);

A sysfs write of `2585738898` to an `int` param is refused with `-ERANGE` by
`kstrtoint`, so the stored value stays **0** — and 0 is the knob's documented
"apply to ANY victim" value. The injector therefore degrades silently from a
victim-filtered one-shot into a global one-shot, which the fence-matrix ruling
explicitly refuses.

Two laps died on it, ~9 minutes of rig each:

    FAIL A armed mode 1 for victim 2585738898 got=ARMED=1 victim=0
    FAIL A armed mode 2 for victim 2431490331 got=ARMED=2 victim=0

The MODE param beside it read back correctly, which is what makes this look
like an arming bug in the harness rather than a type bug in the module.

## Why the obvious workaround is not one

Writing the signed representation (`2585738898 - 2^32 = -1709228398`) does land
in an `int` param, but the take() guard was `if (victim > 0 && ...)`, so a
negative value skips the filter entirely — the same global one-shot, now
without even an error to notice.

## The rule this gives

**Any module parameter whose value is a node id, an inode number, an agino or
anything else the code treats as unsigned 32-bit must be declared `uint`, and
its "unset" test must be `!= 0`, never `> 0`.** Slot numbers (0..63) and agnos
are small and safe as `int`; node ids and aginos are not.

## What caught it, and keep doing this

The harness wrote the value and then **read it back and compared**:

    echo ARMED=$(cat .../pr_fence_submit_inject) victim=$(cat .../pr_fence_submit_inject_victim)
    ck "A armed mode $MODE for victim $VNODE" "$(...)" "ARMED=$MODE victim=$VNODE"

An arm step that only writes would have run all five laps to a verdict with the
injector catching whichever fence attempt arrived first.
