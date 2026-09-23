---
name: trap-a-userspace-scsi-tool-that-sets-fua-in-the-cdb-fails-every-command-on-the-shipping-lun
description: TRAP (s84): the 2/tcp LUN answers READ(16) carrying FUA or DPO with ILLEGAL REQUEST 24/00; the kernel latches a fallback, tools/recov_forge did not.
metadata:
  type: feedback
---

# The shipping LUN rejects FUA in the CDB, and only the kernel knew

`tools/recov_forge` failed its very first command against the 2/tcp LUN:

```
SG_IO read failed: status=2 host=0 driver=8 sense=05/24/00
```

05/24/00 is ILLEGAL REQUEST / invalid field in CDB. Measured directly with
`sg_raw` on test1, which is what settled it rather than reading code:

```
88 08 00 …  READ(16) + FUA  -> Illegal Request, invalid field in cdb
88 00 00 …  READ(16)        -> returns the sector
88 10 00 …  READ(16) + DPO  -> Illegal Request, invalid field in cdb
```

So the target takes neither FUA nor DPO on a READ(16).

**The kernel already knew and nothing else did.** `pal/linux/kern.c` catches
`sense_key == ILLEGAL_REQUEST` on its READ(16)+FUA passthrough, latches
`mxfs_fua_read_unsupported`, warns once, and serves that and every later FUA
read as a plain bio read. Every userspace tool in `tools/` that builds its own
CDB — `recov_forge`, `caw_slotdump`, anything new — is a separate
implementation of the same passthrough and inherits none of that. On this LUN
such a tool does not read one byte.

**What to do when writing or reviving one of these tools:**

- Mirror the fallback: on CHECK CONDITION with sense key 5, clear FUA, retry
  once, latch it for the run, and say on stderr that you did.
- Say what was given up. Without FUA the target may answer from its own cache
  instead of the platter. That is the same coherency the kernel runs under here
  ("write-through backstore assumed"), and it is fine for reading back a sector
  you wrote yourself through the same nexus — it is NOT fine for an argument
  that some other initiator's write did or did not reach the platter.
- Do not "fix" this by removing FUA unconditionally. On a target that accepts
  it, FUA is the reason the tool reads the same image the kernel does.

Adjacent trap, same file: `tools/recov_forge` is built by **no Makefile**. The
checked-in binary was 8 days older than its source. A harness that uses it must
`cc` it first — `tests/fence_kind_matrix.sh` does — or it silently runs code
nobody has looked at.
