---
name: infra-lio-for-tcp-scst-for-caw-rationale
description: Infra rationale (sess59): TCP DLM work runs on LIO (known-good, no wedge variable). CAW requires SCST+iSCSI rebuild (LIO fakes CAW). SCST source is a…
metadata:
  type: project
---

## Why LIO now, SCST later (user directive, sess59, 2026-06-22)

- Current test infra = **LIO/tcm_loop single shared LUN** (fileio over
  /home/steve/disk.img via virtio-scsi). See
  [[storage-backend-is-lio-fileio-not-scst]], [[test-cluster-scst-stack]].
- User deliberately switched TCP DLM testing to LIO because it is a
  **known quantity** — SCST had wedging issues (sess51 CAW↔READ atomic
  wedge, sess72 QNAP target crash under storm) and the user did not want
  an infra variable confounding the TCP DLM coherency debugging.
- **LIO fakes CAW** (reports CAS-success without persisting, sess26) so
  CAW cannot be validated on LIO — CAW work REQUIRES rebuilding the
  shared LUN as **SCST+iSCSI**.
- During CAW work the **SCST source code is available to modify** if SCST
  wedge bugs resurface — patching SCST is on the table, not just MXFS.
- SCST hosts BOTH transports (TCP only needs a shared block dev), so the
  SCST rebuild is permanent — no going back to LIO once done.

## Roadmap (sess59)
1. (in progress) Bounded TCP scale check on LIO: 4 nodes, then 8. NOT
   16/32 (TCP perf-ceiling-limited >16 by design, not ship target).
   Validates sess58 transport-independent inode-lock fixes scale.
2. SCST+iSCSI rebuild → 2-node CAW to 100% (priority, ship target).
3. Scale CAW up node counts on SCST; re-run TCP as regression gate.
See [[project-caw-priority-enterprise-vmware-proxmox-san]].
