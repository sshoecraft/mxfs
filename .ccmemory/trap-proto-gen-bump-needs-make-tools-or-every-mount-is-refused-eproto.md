---
name: trap-proto-gen-bump-needs-make-tools-or-every-mount-is-refused-eproto
description: TRAP (sess508): bumping MXFS_PROTO_GEN without `make tools` leaves mkfs_mxfs stamping the OLD gen; every prep mount fails EPROTO at the C7 gate.
metadata:
  type: feedback
---

# Trap: a protocol-generation bump needs `make tools` too

sess508, 0.75.0 (MXFS_PROTO_GEN 18 -> 19 in include/mxfs/mxfs_super.h):
`make modules` rebuilt mxfs.ko, the first prep mount failed with
"mount(2) system call failed: Protocol not supported" and the ten-step chain
aborted in 35 s. test1 dmesg: `C7 gate: filesystem cluster_proto_gen=18 but
this kernel speaks 19 — refusing mount`.

Cause: `tools/mkfs_mxfs.c` stamps `sup.cluster_proto_gen = MXFS_PROTO_GEN` at
mkfs time from the header, so the userspace binary carries the gen it was
COMPILED with. `make modules` does not rebuild `tools/`.

Rule: after any edit to MXFS_PROTO_GEN (or any on-disk header the tools
compile in), run `make tools` before the next prep. "Protocol not supported"
on the FIRST mount after a mkfs is this, not a transport-census refusal.
