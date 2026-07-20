---
name: caw-multipath-ladder-progress-sess-5bea4199
description: CAW-multipath ladder (ccloop 5bea4199): 1/2/4/8 caw ALL 17/17 PASS. 8 completed this session on build 591A76FB (dir_reuse+fnp+soak). 16/32 in progres…
metadata:
  type: project
---

## CAW-on-multipath ladder — live progress (ccloop 5bea4199, 2026-07-06)

**Criterion**: `MXFS_DEV=/dev/mapper/mpatha MXFS_EXTRA_MODARGS="dirwr=1 dirland=1" ./run.sh N caw`
all-tests-PASS at N=1,2,4,8,16,32, on ONE build. Marker file:
`/src/mxfs/.ccloop/runs/5bea4199-3457-479e-b232-40fd8072683e/criteria-met`.

### Ladder status (criteria.json = source of truth; verify with the python matrix below)
- **1/caw 17/17, 2/caw 17/17, 4/caw 17/17** — PASS but on MIXED older builds (656E89B4 etc.).
- **8/caw 17/17 PASS** — COMPLETED this session on build **591A76FB**. The 3 that were missing
  (dir_reuse_coherency, fault_netpartition, soak) all PASS. dir_reuse fixed by P6L leaf scan
  (see [[caw-8node-dir-reuse-FIXED-p6l-leafscan]]). soak PASSED with dirwr=1 + probes active →
  dump_stack probes are soak-safe in healthy runs (empirically, RULE 4), no need to strip them.
- **16/caw, 32/caw**: IN PROGRESS. Each runs the SAME 17 multi-node tests as 8.

### Build decision: 591A76FB is the candidate final build — do NOT rebuild speculatively
- dirwr=1 is LOAD-BEARING, not just diagnostic: the `dirwr||instr`-gated block in
  `pal/linux/xfs_buf.c` (~3992) does a FUA read-back + dco "COHERENT" restore with a functional
  early-return (`xfs_buf_ioend; return`) — part of dir coherency, not removable. Keep dirwr=1.
- Pure-diagnostic parts still active under dirwr=1: P-LEAFDROP (pr_err+dump_stack ≤40),
  P-LEAFWRITE (pr_warn ≤50000 lines — heavy), P-DIR-DELALLOC-TRIP (dump_stack ≤12). These did
  NOT break 8/caw. RULE 4: only strip them if 16/32 shows a timing/log-volume/dump_stack FAIL
  with proof. If stripped, it's log-only → keep pr_err counters as canaries.

### Method (proven this session)
- `./run.sh N caw [tests...]` self-preps (teardown→mkfs→form→join→srcversion-assert→converge→run→record). Nodes clean between runs. mpatha present. Pass MXFS_DEV=/dev/mapper/mpatha.
- Long runs: launch `nohup timeout <big> env ... ./run.sh ... >log 2>&1 &`, poll with a foreground `while kill -0 PID; sleep` waiter (set Bash tool `timeout` param up to 570000; default is 120s!).
- 16-node dir_reuse isolated from the rest (run separately) to avoid a dir_reuse timeout poisoning fence/fault/soak (run104 cascade).
- Matrix check:
  `python3 -c "import json,re;d=json.load(open('criteria.json'));m={};[m.setdefault(t['name'],{}).__setitem__(re.match(r'(\d+)/caw',k).group(1),v['status']) for c in d['categories'] for t in c['tests'] for k,v in (t.get('runs') or {}).items() if re.match(r'(\d+)/caw',k)];[print(n,sum(1 for x in m if m[x].get(n)=='PASS'),'/',sum(1 for x in m if m[x].get(n))) for n in ['1','2','4','8','16','32']]"`

### NEXT
16/caw Run1 (16 tests minus dir_reuse) → Run2 (dir_reuse) → 32/caw same split → final one-build
full-ladder rerun 1..32 → write marker. Watch RULE 0 timing at scale (dir_reuse 140*N; 32→4480s).
