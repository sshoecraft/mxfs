---
name: technique-drbd-84-fence-handler-resumes-io-itself-to-avoid-the-rcu-sleep-warning
description: DRBD 8.4: a fence-peer exit 4/7 with I/O frozen makes the driver write md inside rcu_read_lock (kernel WARNING); `drbdadm resume-io` first avoids it
metadata:
  type: reference
---

**What bites:** with `fencing resource-and-stonith`, a Primary that loses its link freezes I/O (susp_fen=1, NEW_CUR_UUID set). When the fence-peer handler exits 4 or 7, DRBD 8.4 (drivers/block/drbd/drbd_state.c after_conn_state_ch, "case1: The outdate peer handler is successful") calls drbd_uuid_new_current() for each device inside rcu_read_lock(); it writes the metadata and sleeps → kernel WARNING "Voluntary context switch within RCU read-side critical section!" (WARN_ONCE per boot, stack drbd_md_sync <- drbd_uuid_new_current <- w_after_conn_state_ch), and RCU grace periods wait on the md write. Proxmox 6.17 (drbd 8.4.11) and Ubuntu 6.8 both show it. Exit 3 and 5 also set pdsk <= Outdated, so no exit code avoids it.

**Technique (0.90.89, tools/mxfs_drbd_fence_self.py resume_frozen_io):** once the peer is excluded, run `drbdadm resume-io <res>` from the handler BEFORE exiting 7. drbd_nl.c drbd_adm_resume_io does the same NEW_CUR_UUID rotation under adm_mutex (no RCU), clears susp/susp_fen and tl_clear()s the lost link's requests; the exit code then only records pdsk Outdated and case1 is skipped (susp_fen already 0). Verified nested pair 2026-10-07: `susp( 1 -> 0 )` 8 ms after the handler's decision, then "fence-peer helper returned 7", "pdsk( DUnknown -> Outdated )", no warning on a freshly booted participant 0, the peer resynced as SyncTarget.

**Only safe on the lost-link path:** that handler runs on DRBD's own `drbd_async_h` kthread (conn_try_outdate_peer_async, drbd_receiver.c conn_disconnect), holding no lock resume-io takes. A promotion runs the handler synchronously inside `drbdadm primary` under the resource adm_mutex — resume-io there would deadlock; never call it for a node that is not Primary. Bound the wait with Popen+poll and never block on a child that may be stuck in the kernel (subprocess.run(timeout) kills then waits).

**Test it on a fresh boot:** the warning is WARN_ONCE, so a host that already printed it this boot proves nothing — restart the excluding host first (tests/pve_fence_rcu_check.sh does).
