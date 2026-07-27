---
name: physrig-qnap-PR-reconstruction-CLOSED
description: PR mystery CLOSED: QTS purges registrations on session events silently + UNREGISTER doesn't bump PRgen (both measured). Cycle ledger consistent. Fix…
metadata:
  type: project
tags: [qnap, scsi-pr, root-cause, fix-program, rule-5-gpt, physical-rig]
---

# QNAP PR forensics — CLOSED reconstruction + fix program (supersedes open questions in physrig-qnap-battery-defect-dossier)

## Measured QTS TS-453 Pro PR quirks (sg_persist, decisive)
- **Purges ALL registrations on iSCSI logout/login WITHOUT PRgen bump** (0xdeadbeef test: gen 0x7c→0x7c, key gone). Non-conformant; registration lifetime = session event lifetime.
- **UNREGISTER does not bump PRgeneration** (0xaaaa1111/0xbbbb2222 test: gen 0x7e→0x7e, correct single-key removal).
- REGISTER bumps gen correctly; enforcement of WE-RO vs unregistered writers is STRICT (20/20 bounce probe).
- REGISTER_AND_IGNORE works (mxfs uses pr_ops PR_FL_IGNORE_KEY).

## Cycle-D ledger (now consistent)
0x77 → pve1 REG (0x78) → pve2 REG (0x79) → both write happily → **target silently purged pve2's key ~2512-2519** (trigger unattributed; class proven; GPT: likely invisible conn-recovery/nexus recreation — witness-session + tcpdump experiment if ever needed) → pve2 journal write EBADE @2519 → mxfs ATE the log error (no shutdown) → teardown unregisters gen-neutral → final 0x79, zero keys. No SPC paradox remains.

## Fix program (severity order; one at a time per RULE 4; rev patch ver each)
- **D1 (CRITICAL)**: journal/meta/data write -EBADE (BLK_STS_RESV_CONFLICT) = FENCING EVENT → xfs_force_shutdown + membership withdrawal. NEVER transparent retry (ordering unsafe). Site: log-slice writer dlm/mount.c:~5640 ("log I/O error -52" print, error swallowed).
- **D2 (CRITICAL)**: TCP branch v5_mount.c:1009-1019 proceeds unfenced on register failure → abort mount (parity w/ CAW branch ~1161).
- **D3**: clean teardown writes FUA release record (checksummed, tenure-stamped); mkfs zeroing needs flush+verify (old pwrite-O_SYNC durability issue re-proven on QNAP). stop_heartbeat (disklock.c:736) currently writes NOTHING.
- **D4**: PREEMPT hygiene: READ KEYS first; preempt only currently-registered victims; on conflict re-read + classify; if OWN key missing → SELF-FENCE (freeze, leave membership), NOT re-register (GPT: re-register resurrects a fenced node).
- **D5**: settle gate: call get_stale_slot_mask with wait-window (fn already implements snapshot+rescan liveness; gate passes threshold_ms=0 = snapshot-only). Skip wait when no ACTIVE-flagged foreign slots at all.
- **D6**: clean umount sends goodbye/withdraw (P-WITHDRAW-RELALL path exists for FS-shutdown) before TCP close → kills 40s survivor stall + retry storm + EX-frozen window.
- **D7 (perf)**: 4.68s EX-handoff constant — instrument per GPT: request-ID + boottime stamps at request create/send, remote recv, holder release, grant send, grant recv, acquire return + retry-timer delays. 19765 ≈ 15000(settle) + 4700(same path).
- **D8 (qualification)**: periodic PR self-check (READ KEYS): own-key-missing → WARN + self-fence path; provisioning-time PR conformance probe (like CAW/FUA probes); slot records should carry full tenure identity (64-bit tenure key + incarnation) long-term. On QNAP-class targets PR is advisory — lease/disklock fencing must not assume PR.

## Rig state at close of investigation
LUN has ghost ACTIVE slots 0-3 (harmless to data; will retrigger gates/evictions until D3 lands or re-mkfs). All PR keys clean. Both nodes unmounted, module loaded (srcver 8212BFC8). c1/c2 files intact on FS. Suite subset (task 5) + sysrq-b dead-peer finale still pending after fixes.
