---
name: ccloop-c7ee71c6-sess48-disklock-record-recon-epoch-exists
description: sess48 recon REFINED: disklock record epoch = NODE-INSTANCE (mount incarnation) = ruling's owner_boot_epoch; per-acquisition grant_epoch is the missi…
metadata:
  type: project
---

# Token campaign step-1 seed: disklock record layout + epoch semantics (VERIFIED)

`dlm/disklock.h` `struct mxfs_disklock_record` — exactly 512 bytes (one sector, CAW-atomic):
```
uint32_t magic; uint32_t flags; struct mxfs_resource_id resource;
mxfs_node_id_t owner; uint8_t mode; uint8_t state; uint8_t pad[2];
uint64_t granted_at_ms; mxfs_epoch_t epoch; uint8_t reserved[448];
```

## Epoch semantics (verified in dlm/disklock.c)
The existing `epoch` field = **node-instance epoch** (`ctx->epoch`, new per mount/rejoin — "same node, new epoch — its own mount" comment at ~line 476; HB records carry it for liveness identity, and the record-CRC at line ~153 covers "identity (fs_gen, node_id, epoch)"). That is exactly the GPT ruling's `owner_boot_epoch` — ALREADY PERSISTED AND CRC-COVERED.

## The missing piece
A per-ACQUISITION `grant_epoch` (durable, non-reused, bumps on every acquire/release of that resource, persisted BEFORE the grantee's first AG metadata modification, unique per continuous exclusive ownership interval). Add to `reserved[448]` of the LOCK record + write it at grant time in the disklock lock path; plumb up through the DLM layer to the mount so the buffer-log token writer can read it. Note: there IS a record CRC mechanism already (line ~153-186 area, covering feature fields + identity) — extend coverage to the new field per the ruling's torn-write requirement.

## Other facts
- `granted_at_ms` is per-node boottime — never cross-node compare (sess43).
- HB-embedded rings (eviction ring precedent) = cheap way to publish the recovery descriptor digest without new CAW traffic.
- `dlm.h` has request/current epoch types for message plumbing precedents.

Ruling: `ccloop-c7ee71c6-sess48-GPT-ruling-foreign-replay-token-design`. Campaign entry: `ccloop-c7ee71c6-sess48-HANDOFF-foreign-replay-campaign-entry`. Implementation order there stands: (1) grant_epoch persist-at-grant, (2) CIL-drain-at-release audit (does bast_work_fn Phase 2 guarantee CIL formatting stability for AG items — likely needs xlog_cil_force before unlock), (3) v2 blf token + log-incompat flag, (4) recovery descriptor + DONE marker rework of the P163 foreign-replay flow, (5) token gate replaces P223 untagged-skip + foreign_replay_ab.sh A/B + 5-point fault injection.
