---
name: compiled-module-param-type-and-sysfs-arming-traps
description: Module-param injector knobs silently disarm or stay armed: int vs u32 node id, bash signed 64-bit PR keys, charp holding a newline. Read back after a…
metadata:
  type: feedback
tags: [compiled, kernel, module-param, injector, harness, sysfs]
---

Three traps share one shape: a debug/injector module parameter armed or cleared through sysfs ends up in a state different from the one the harness meant, and nothing errors. The knob either degrades to its "apply to anything" value, stays disarmed, or stays armed. Each cost at least one rig lap measuring nothing.

## 1. A u32 id in an `int` param is refused and reads back 0

[[trap-a-module-param-holding-a-u32-node-id-must-be-uint-or-half-of-all-ids-are-refused-and-read-back-zero]]

- `mxfs_node_id_t` is `uint32_t`; ids on this rig are uniform over the range, so about half exceed `INT_MAX`.
- `pr_fence_submit_inject_victim` was `module_param int`. `kstrtoint` refuses e.g. `2585738898` with `-ERANGE`, the stored value stays 0, and 0 means "any victim". The victim-filtered one-shot silently became a global one-shot. Two laps (~9 min of rig each) died on it. The MODE param beside it read back fine, which made it look like a harness arming bug.
- Writing the signed representation does not help: the take() guard was `victim > 0`, so a negative value skips the filter entirely.
- Rule: any param holding a node id, inode number, agino or other unsigned-32 value is declared `uint`, and its "unset" test is `!= 0`, never `> 0`. Slot numbers (0..63) are safe as `int`.
- Keep the harness practice that caught it: write, read back, compare (`ck "A armed mode ..." ...`). A write-only arm step would run all laps with the injector catching whichever fence arrived first.

## 2. A 64-bit PR key through bash `$(( ))` goes negative

[[trap-a-pr-key-overflows-bash-signed-arithmetic-so-half-of-them-silently-fail-to-arm-a-ullong-knob]]

- PR keys are random 64-bit; about half have the top bit set. `$(( 0xf5413d536ca66aed ))` is negative in bash.
- Echoing that into a `ullong` param (`dbg_prout_lose_key`) makes `param_set_ullong` reject it; the knob stays 0 and the lap runs disarmed (`got=ARMED=0x0 want=ARMED=0xf541...`). `normkey()` built on `printf '0x%016x' "$(( $1 ))"` also cannot render it.
- Intermittent by construction: one lap's key had the top bit clear and passed, the next failed. Same family as the zero-top-nibble padding trap.
- Fix: do key normalization and decimal conversion in `python3` masked with `0xFFFFFFFFFFFFFFFF`. Write the decimal or the `0x` string (`kstrtoull(val, 0, ...)` accepts the prefix). Compare readback decimal to decimal, since `param_get_ullong` prints `%llu`. Never put a 64-bit key through `$(( ))` or assert on bash-rendered hex of one.

## 3. A `charp` param cleared with `echo ''` holds a newline

[[trap-a-charp-module-parameter-cleared-with-echo-empty-holds-a-newline-and-stays-armed]]

- A sysfs store hands a `charp` param the bytes written; `echo ''` writes `"\n"`. `tests/lu_reset_fence.sh` cleared `lu_reset_krel_probe` that way, the module's `!p || !p[0]` disarm test saw a non-empty string, and the refusal injector stayed armed with a substitute release of `"\n"`.
- Effect: later fences refused `kernel-unaudited` with an empty release in the log, indistinguishable from an operator-cleared knob. The LOGICAL UNIT RESET arm never reached admission (`admit_run=0`), so the clause under test went unmeasured and the harness aborted on an empty field instead of a filesystem verdict.
- Rule: an armable knob must be disarmable. The reader of every `charp`/string param trims surrounding whitespace and treats all-whitespace as OFF. Do not paper over it in the harness with a sentinel string; the next caller will use `echo ''`. `int`/`bool` params are unaffected because `kstrto*` skips the trailing newline.
- Same class as the unpadded-kernel-hex-key trap: two strings naming the same thing compare unequal; normalize at the one place that decides.

## Checklist for any new sysfs injector knob

1. Declare the param type to match the full range of the value (`uint` for u32 ids, `ullong` for keys); unset test is `!= 0`.
2. The kernel reader tolerates whitespace/newline for string params.
3. The harness arms with python-computed decimals, never bash arithmetic on 64-bit values.
4. The harness reads the knob back and compares to the intended value before the lap proceeds, and again after disarm.
