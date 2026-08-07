---
name: ccloop-c7ee71c6-sess21-tcp-wedge-root-sleep-in-atomic
description: sess21 ROOT: 32/tcp rsync_paired wedge = sleeping rwsem under pag_ici_lock (NOT ping-pong starvation). sess20 fixed only the CAW arm. Fix v0.11.163 +…
metadata:
  type: project
---

# sess21 — 32/tcp wedge root: sleep in atomic context (TCP arm)

## sess20's diagnosis was wrong
sess20 called this "AG-level ping-pong starvation" from `readopt=49`.
readopt=49 over 781 s is ~1 re-adoption per **16 seconds** — that is not a
ping-pong. Do not re-chase fairness/quantum tuning for this symptom.

## Actual root (proven byte-exact)
`mxfs_v5_dlm_inode_held_nb()` promises "never blocks". sess20 fixed only the
CAW arm (returns -EWOULDBLOCK). The **TCP arm** called
`mxfs_dlm_held_mode()`, whose `ctx->table_rwlock` is a
**`struct rw_semaphore`** in the kernel PAL. `down_read()` schedules.

    mxfs_pal_rwlock_rdlock <- down_read <- rwsem_down_read_slowpath <- schedule()
    mxfs_dlm_held_mode
    mxfs_v5_dlm_inode_held_nb
    mxfs_submit_partial_inode_write   <- preempt_count 0x2 (pag_ici_lock)
    xfs_buf_submit_bio ... xfsaild

The call-site comment literally claimed "the mirror answers for free" on TCP.
It does not — the mirror is behind a sleeping lock.

## Why it wedges the whole cluster
`mxfs_ici_lock()` (xfs/xfs_icache.c:87) is an **unbounded**
`while (!spin_trylock(&pag->pag_ici_lock))` loop. Once xfsaild sleeps holding
that spinlock and corrupts preempt_count, any peer CPU entering `mxfs_ici_lock`
spins forever:
- test31: `soft lockup - CPU#2 stuck for 522s! [rsync:2073]`, **zero context
  switches**, repeated rcu_preempt stalls, sshd unreachable.
- test31 never released its AG grants -> 31 peers starved: 9210
  `P-LKTIMEOUT-REMOTE`, 8590 `P36-RETRY`. AG 32's master logged one holder for
  255 s straight.

## Fix (v0.11.163, srcver DA8635094C76C6D9EA7A86D)
- `mxfs_pal_rwlock_tryrdlock()` — kernel `down_read_trylock`, user
  `pthread_rwlock_tryrdlock`. Only rwlock acquire legal with a spinlock held.
- `mxfs_dlm_held_mode_nb()` (dlm/dlm.c) — trylock form, -EWOULDBLOCK when busy.
- `mxfs_v5_dlm_inode_held_nb` TCP arm uses it.
- `mxfs_pal_may_sleep()` (pal/) + **`P191-SLEEP-IN-ATOMIC`** tripwire on the
  blocking `mxfs_dlm_held_mode`. This bug class shipped TWICE (sess19 SCSI read,
  sess20 rwsem) because nothing checked. Keep the tripwire.

## Validation (paired, same 32 nodes, same workload)
| marker | 0.11.162 | 0.11.163 |
|---|---|---|
| scheduling while atomic | 14 / 7 nodes + test31 | 0 |
| soft lockup | 522 s | 0 |
| rcu stall | 3+ | 0 |
| blk-mq WARNING | present | 0 |
| P-LKTIMEOUT-REMOTE | 9210 | 8 |
| P36-RETRY | 8590 | 7 |
| rsync_paired | wedged >300 s | PASS 8 s |

**32/tcp condition: 20/20 PASS** (was 13 PASS + wedge).

## Technique worth reusing
When a node stops answering SSH, `ps`/`dmesg` over ssh returns NOTHING and the
node looks merely "slow". Read the libvirt serial console instead:
`/var/log/libvirt/qemu/<vm>-serial.log` (needs sudo). That is where the soft
lockup / rcu stall / atomic BUG evidence was — invisible to every ssh-based
capture. The VM pings fine and `virsh domstate` says running, so liveness
checks do not catch it either.

## Audit note
Entire `pag_ici_lock` region (pal/linux/xfs_buf.c 3078-3514) was swept for
other sleeping calls. Only remaining call is `mxfs_sf_disk_names` — pure
`scnprintf`, safe. P191 fired 0 times post-fix.
