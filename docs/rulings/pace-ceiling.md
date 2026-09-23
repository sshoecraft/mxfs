<!-- sess481 RULE-5 ruling: directory-handoff tuning cannot fix crash_consistency (needs f_H>=64.8%, measured 5-16%); the binding term is the private-arm… -->
# RULE-5 ruling — sess481, D-32NODE-SHARED-DIR-CREATE-PACE ceiling

Consulted with the full sess481 measurement package (phase markers, P291-EXWIN
distribution, P138-BAST su/sw/sx split, `mxfs_inode_mht_ms=300`, the record's own
private-vs-shared arm numbers). Cited by the ledger record's `next_step`.

## 1. The ceiling arithmetic — UPHELD, with my rotation figures CORRECTED

Removing all handoff cost gives at most `S_max = 1/(1 - f_H)`, where `f_H` is the
handoff fraction of the serialized critical path.

- Current: 3200 creates / 85 s = **37.6 creates/s**.
- Target (fit setup in 30 s, leaving 60 s for the verify): 106.7 creates/s.
- Required speedup **2.84x** ⇒ requires **f_H ≥ 64.8%**.

Measured `P138-BAST` release on the shared dir: n=15, p50 14.9 ms, p90 52.7 ms,
max 97.1 ms, against turns of ~170-320 ms ⇒ **f_H ≈ 5-16% ⇒ ceiling 1.05-1.19x.**
So handoff-only tuning cannot close the row. **The queued fastpoll A/B cannot
close it either** — but keep running it, reframed (see §2).

**Two of my numbers were inconsistent and are corrected here:**

- I claimed "~50 ms handoff vs a 2 s hold = 2.4%, which over 32 handoffs is 23%".
  Wrong: summing 32 handoffs also sums 32 holds, so it stays 2.4%. To get 1.6 s of
  handoff in a 7 s rotation, the hold must be **(7−1.6)/32 ≈ 169 ms**, not 2 s.
- "12 creates per 2 s hold" implies 6 creates/s cluster-wide, contradicting the
  measured 37.6. Cross-check: 3200/12 ≈ 267 turns over 85 s ⇒ **~318 ms per turn**.

**Do not reconstruct ownership epochs from one node's wait spacing.** Instrument the
epoch directly: acquire-complete ts, release-start ts, release-complete ts, creates
retired in that epoch, quiet-gate extensions, owner + lock generation. Then sum
owned time and transition time cluster-wide. Use the **mean** handoff, not p50/p90.

**Two further qualifications on the 26.6 ms/create figure:** the 85 s includes
barriers and drop_caches, so 3200/85 is a lower bound on the create-phase rate —
bracket steps 1-2 specifically. And these are not bare creates: `dd oflag=sync`,
the data write, close and log force may dominate, so "native XFS creates in tens of
µs" is not apples-to-apples unless the native measurement carries the same
synchronous write+close sequence.

## 2. Fastpoll A/B — keep it, but reframe it

Its effect is NOT necessarily bounded to the handoff term. 31 waiters polling the
shared LUN can delay the owner's metadata and log I/O, inflate CAW latency, consume
the device queue, contend for the 64 lock-table slots, and slow unrelated AG / log /
SB traffic — i.e. fastpoll may inflate the WORK term `W` as well as `H`. Run it as a
**LUN-load / poll-storm experiment**, and collect SCSI command counts, latency and
queue residence by opcode and sector range — not just wall time.

## 3. Priority ranking

1. **Diagnose the mount-wide 32-node degradation** (private arm 4.6 → 27.8 ms/create
   with nothing shared but the mount). Highest-priority shipping issue; it also caps
   any sharding solution. Caveat: 32 private ops can overlap, so 27.8 ms of latency
   is not automatically 27.8 ms of serialized service demand — establish how much of
   it lands on the critical path while a node holds EX.
2. **Make directory sharding transparent/automatic.** Sharding is legitimate
   architecture, not a workaround — but *internal, automatic* name/bucket locking is
   legitimate, an application-issued ioctl is an opt-in mitigation, and switching the
   board row to per-node subdirectories is papering over the defect.
3. **File the CAW unlock latency separately** (done: `D-CAW-WIRE-UNLOCK-100MS-CONTENDED-INODE-SLOT`).
   15-100 ms for one CAS is unacceptable on its own terms; do not close it merely
   because fixing it cannot make this row pass.
4. **Fix the reporting semantics.** "1 check passed" when the durability assertions
   never ran is invalid. The harness must report the performance phase as budget
   exhausted AND the durability assertions as **NOT RUN**, never as passed.

## 4. Ranked mechanisms for the private-arm 6x, each with its cheapest test

Before per-hypothesis runs, add **mutually exclusive** critical-path buckets for one
operation (DLM acquire / AG lock / SB counter / trans reserve / local metadata work /
log commit+force / block I/O / CAW poll / workqueue delay). Without exclusive
buckets several probes all claim the same 20 ms.

1. **Shared log + synchronous commit/force serialization** — leading suspect given
   `oflag=sync`. Test: per op record reserve start/end, commit start/end, log-force
   start/end, target and completed LSN, whether the force was coalesced, and any
   distributed log-lock wait. Confirmed if the extra 23 ms is in force/log-lock waits
   and rises with node count.
2. **CAW/poll traffic congesting the LUN.** Test: at block/SCSI submit+complete,
   aggregate by opcode, by lock-table sector range vs fs/log range, service time,
   queue residence, queue depth, CAW miscompares, poll reads per acquisition. This is
   also the measurement the fastpoll A/B needs.
3. **AG contention and node→AG placement.** Test: per create, record selected inode
   AG and data AG, wait per AG-related lock, lock owner + waiter count, allocation
   retries/reselection; then compare unique-AG nodes against collided-AG nodes *in
   the same run*. **Correction to our standing claim:** 32 nodes over 25 AGs
   guarantees ≥7 excess placements, but "14 nodes share an AG" only follows if those
   are 7 disjoint pairs — the minimum in non-singleton AGs is **8**.
4. **Global SB/inode counters, quota, counter refills.** Test: count and time
   distributed acquisitions per global resource, especially slow-path batch refills;
   report refills per 100 creates. A sawtooth (many cheap creates, then a long
   refill) is diagnostic.
5. **DLM slot hashing / false contention in the 64-slot table** — logically
   independent locks may multiplex onto one physical slot. Test: log logical resource
   class+id, physical slot, attempts, miscompares, slot busy time; per-slot heat map.
6. **Flush/FUA behaviour of the shared LUN** — CAW may carry stronger ordering than a
   normal write and drain the device queue. Test: count flush/FUA-bearing commands
   and the interval each blocks later completions.
7. **Hidden common-parent activity** — verify the "private" arm truly mutates no
   common parent, xattr, quota object or control file. Test: record every distributed
   resource one private-dir create acquires, grouped by id; anything acquired by all
   32 nodes is immediately visible.

**Recommended single next fleet run:** critical-path buckets + logical→physical slot
map + SCSI opcode/sector-range latency + selected AG + log-force timing. That one run
separates log serialization, DLM/LUN congestion and AG contention.

## 5. Legitimate ways to make the directory term fundamentally cheaper

All replace the serialization point rather than tuning it.

- **Hash-partitioned name locks** (most practical here): hash each name to one of N
  shard lock resources; same-name creates still serialize so atomic `EEXIST` holds;
  structural ops take a higher-level lock; rename takes source+dest in canonical
  order; rmdir/emptiness take all shards; `fsync(dir)` must cover all shard state.
  **The hard part is not locking names — it is letting shards update the physical XFS
  directory structure concurrently. If every shard still updates one B-tree root or
  leaf under one inode transaction lock, logical sharding buys no concurrency.**
- **Per-node durable create-intent logs** (LSM/delta directory): powerful, far more
  invasive — needs name-scoped conflict arbitration, visibility before the syscall
  returns, durable replay, fencing before reclaiming a dead node's intent area, and
  `fsync(dir)` spanning all intent logs.
- **Delegations / hierarchical cohort locking**: delegating the WHOLE directory only
  improves handoffs and does not move the per-create ceiling. Delegating independent
  hash ranges or leaves does.
- **Reserved name ranges**: only works via hashing — applications choose arbitrary
  names, so per-node lexical ranges are not generally usable.
- **Batched create transactions / group commit**: real amortization under synchronous
  workloads, but a syscall cannot return before its durability contract is met, so it
  does not by itself remove directory-wide serialization.
- **Optimistic versioned directory updates**: viable only if updates touch disjoint
  leaves and installation is atomic; with one inode-wide transaction lock, retries
  just replace queueing with wasted work.
