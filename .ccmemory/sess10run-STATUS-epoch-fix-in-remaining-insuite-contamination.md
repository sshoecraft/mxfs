---
name: sess10run-STATUS-epoch-fix-in-remaining-insuite-contamination
description: sess10(ccloop) STATUS build E4540ADC: dir coherency FIXED (4/tcp dir_reuse PASS standalone). Remaining: in-suite contamination — tests pass standalon…
metadata:
  type: project
---

## sess10 (ccloop 4cb2d0a2) STATUS — build E4540ADC (dir_epoch_adopt=1 default)

### DONE & VERIFIED
- **Coherency FIXED**: dir_epoch_adopt=1 default → `./run.sh 4 tcp dir_reuse_coherency` standalone = PASS 4/4 (was 0/4). See [[sess10run-FIX-dir_epoch_adopt-default-on-fixes-4tcp]].
- **2/tcp full suite**: 14/17 PASS incl. ALL coherency (cache_coherency, strong_consistency, dlm_fairness, zero_silent_loss, crash_consistency, dir_reuse, etc).
- **4/tcp full suite**: 13/17 PASS incl. all coherency tests EXCEPT dir_reuse (which failed IN-SUITE 0/4 but PASSES 4/4 STANDALONE).

### REMAINING BLOCKER = IN-SUITE CONTAMINATION (NOT a coherency bug, NOT caused by epoch fix)
The SAME tests pass standalone but fail in the full `./run.sh N tcp`:
- 2/tcp: fence_during_write, fault_netpartition, tcp_dlm_scaling FAIL in-suite — **all 3 PASS 2/2 standalone** (verified this session).
- 4/tcp: dir_reuse_coherency(0/4) + fence_during_write(2/4) + fault_netpartition(3/4) + tcp_dlm_scaling(3/4) FAIL in-suite — dir_reuse PASSES 4/4 standalone.

**Suspected source**: run.sh preps ONCE then runs all 17 tests on the same cluster with NO inter-test recovery. Disruptive tests (crash_consistency reboots a node; fence/netpartition fence/iptables-partition) leave the cluster degraded for the NEXT test. dir_reuse runs immediately AFTER crash_consistency at 4/tcp → suspect crash_consistency's node-reboot doesn't cleanly recover before dir_reuse (at 2 nodes it recovered → dir_reuse passed in-suite). VERIFYING with `./run.sh 4 tcp crash_consistency dir_reuse_coherency`.

### Candidate fixes for contamination (next)
1. run.sh: between tests, verify all N nodes mounted+healthy; recover (virsh start + wait + remount) any that aren't. Most general; matches operator. Harness change.
2. Make disruptive tests fully restore+rejoin the cluster before returning PASS.
3. If a rebooted node fails to cleanly rejoin/remount at 4-node = FS recovery bug (in scope).
sess58 got clean 2/tcp 17/17×8 on build 60EFBE5E WITHOUT harness recovery, so 4-node degradation is either a regression (sess59-69) or needs more recovery time.

### Cluster: test1-8 all running/reachable. Reset: virsh -c qemu:///system destroy+start. Criterion = clean full ./run.sh 1/2/4/8 tcp all 100%.
