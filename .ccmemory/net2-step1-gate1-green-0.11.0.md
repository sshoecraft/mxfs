---
name: net2-step1-gate1-green-0.11.0
description: NET2 §11 step 1 LANDED 0.11.0, gate 1 GREEN (76 checks, 1s/30s; kernel clean srcversion 5221BFFE...). MEPOCH needs evict 28→25 at step 5. Kbuild ask…
metadata:
  type: project
tags: [net2, dlm-plan, gate1, wire-format, harness]
---

# NET2 step 1 landed — gate 1 GREEN (0.11.0, 2026-07-17)

Implementation plan approved this session (plan-mode): repo copy at
`DLM_IMPL_PLAN.md` (living checklist w/ gate status line); design of record
stays `DLM_PLAN.md` v2.

## What landed (step 1 — protocol foundation)

- `include/mxfs/mxfs_ports.h` — port registry per §14. 9 call-site
  migrations (mount.c:34-35 defines, v5_mount.c 881/882/1022/1171/1173/1187,
  lease.h:61 → LEASE_LEGACY alias + deprecation comment, discovery.h:25,
  dlm_caw.h:105). Zero behavior change.
- `dlm/net2_wire.h` — 64B LE outer hdr. KEY DEVIATION FROM §6's literal
  struct: the §6 field order mis-aligns seq/ack (u64 @ wire offset 36) so a
  natively-ordered struct would be 72B; resolution = in-memory struct is
  alignment-ordered (u64→u32→u16→u8, sizeof==64 asserted) and pack/unpack
  are the wire authority (field-by-field LE at documented offsets — wire
  offsets ARE §6's order; nothing on the wire changed). Includes SYN TLV
  block (6 required types), feature bits, structural validate with
  per-reason error enum. Static asserts compile BOTH builds (kernel via
  v5_mount.c include, added this session; user via harness).
- `dlm/net2.h` — mxfs_net2_id, 5-class priority enum (cross-asserted vs
  wire PRI_COUNT), freeze scope/reason enums (§7.E, pre-declared for
  stats), `mxfs_net2_tunables` (ALL time/window constants; harness
  compresses time; defaults = spec values), cfg + lifecycle API.
- `dlm/net2_stats.h` — §13 evidence counters verbatim.
- `dlm/net2_fault.{c,h}` — dual-build deterministic fault engine:
  xorshift64*, PRNG advances exactly once per eval regardless of match
  (decision stream = f(seed, call seq)); rule string syntax
  `dir:class:type:action:prob_ppm:count:delay_ms` with shared parser for
  future kernel modparam + harness CLI. PURE logic, no PAL calls.
- `tests/net2/` — FIRST dlm-linking userspace binary. Standalone Makefile
  (`make -C tests/net2`; objects under obj/ so no Kbuild collision; NOT
  wired into top-level build — approval-gated at step 12). Harness
  scenarios: wire_golden (vs 8 checked-in vectors incl. offset
  spot-checks), wire_fuzz (1e5 seeded frames + exact-reason malformed
  corpus), tlv_roundtrip (truncation at every byte, unknown-type skip),
  fault_engine (PRNG + decision goldens, matching semantics, parser
  corpus). `gate1_wire.sh` with written RULE-0 derivation +
  RULE0_CALIBRATE support.

## Gate 1 results

76 checks PASS across 4 scenarios; harness wall 1s vs 30s budget (pinned in
TIMEOUT_BUDGETS.md); fuzz 100000 frames (20860 accepted/79140 rejected,
deterministic seed 0xF422). Kernel `make modules` clean, 262s incremental,
srcversion 5221BFFE305AF21A. Module behavior UNCHANGED (port indirection
only) — cluster deployment stays 0.10.120 / F2443A0C. VERSION → 0.11.0,
CHANGELOG entry added. pal.h user branch compiled first time ever, clean
under -Wall -Wextra -Werror (byteorder path).

## Standing items for next steps

- **Step 2 (link/midcomms/mesh)**: fork points peer.c accept_fn 190-409,
  connect_impl 643-856 (lower-node_id there; NET2 = lower-SLOT), recv_fn
  67-165; PAL has NO timer primitive — delayed-ack via egress
  cond_timedwait deadline. **Kbuild checkpoint A (explicit user go-ahead)
  BEFORE gate-2 kernel smoke** — present exact diff.
- **Step 5 MEPOCH layout**: HB record has only reserved[8] free (evict
  ring 464B took the sess55 reserve) — approved plan resolution: evict
  28→25 entries frees 48B; MEPOCH rec = 44B WITH leading magic (§7.C
  fields sum 40); HB flags bit MXFS_HB_F_MEPOCH; retarget disklock.h:142
  assert; chk_mxfs decode.
- No DLM stats surface exists — step 6 adds mxfs_pal_stats_register
  (kern: /proc/fs/mxfs/ per xfs_stats.c:149-159 precedent; user: registry).
- Discovery announce has NO slot field — identity rides SYN TLV; discovery
  gains only a capability flag bit.
- ccteam was standalone (NATS unreachable) — no claims possible.
