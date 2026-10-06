---
name: reference-drbd-84-runs-the-fence-peer-handler-for-a-disconnected-secondarys-promotion-too
description: DRBD 8.4 calls fence-peer not only for a Primary that lost its link but for drbdadm primary on a disconnected Secondary (SS_PRIMARY_NOP / SS_NO_UP_TO…
metadata:
  type: reference
tags: [drbd, fencing, reference]
---

DRBD 8.4 (in-kernel, /src/linux/drivers/block/drbd) runs the fence-peer handler in two situations, and a handler that cannot tell them apart can elect both sides of a split:

1. A Primary loses its link: sanitize_state sets susp_fen (drbd_state.c ~1193), after_state_ch starts conn_try_outdate_peer_async — the handler runs asynchronously in a kthread, role still Primary at the start, but the node can demote while it runs (open_cnt 0).
2. `drbdadm primary` on a disconnected Secondary: is_valid_state returns SS_PRIMARY_NOP (fencing >= resource, conn < Connected, pdsk >= DUnknown) for an UpToDate disk, SS_NO_UP_TO_DATE_DISK for a Consistent one; drbd_set_role (drbd_nl.c ~707-747) calls conn_try_outdate_peer synchronously, up to 4 tries. drbd_adm_set_role releases genl_lock first, so drbdadm calls inside the handler do not deadlock (adm_mutex + state_mutex are held).

Exit codes (conn_try_outdate_peer): 7/4 -> pdsk Outdated, I/O resumes or the promotion proceeds; 5 -> pdsk Outdated ONLY if the local disk is UpToDate (so 5 on an UpToDate Secondary GRANTS the promotion); 6 -> outdates the local disk; anything else (1) -> "helper broken", returns false: Primary stays frozen, promotion fails.

MDF_PEER_OUT_DATED is set while pdsk is Inconsistent..Outdated and written to disk only by the drbd_md_sync at the end of after_state_ch, so a crash in between leaves it stale; at attach it is what turns a Consistent disk UpToDate ("attaches UpToDate/Outdated").

How it bit us (2026-10-06, 0.90.68): mxfs-drbd-fence-self granted promotions on the tie-break and let participant 1 continue on an ssh snapshot of an idle peer — both sides could win (D-DRBD-SELF-AUTHORITY-CAN-ELECT-BOTH-SIDES). Fixed in 0.90.69: a non-Primary caller is a promotion, granted only under participant 0's own inhibit, refused with 1.
