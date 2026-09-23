<!-- sess575 Astra ruling on D-FOREIGN-SLICE-INTENTS-ABANDONED: survivor-completes-EFI-directly is UNSAFE (two-journal ordering); BASE_STABLE is the missi… -->
# Astra ruling — D-FOREIGN-SLICE-INTENTS-ABANDONED (sess575)

Question asked: given EFI is the only live intent class, completion is a plain idempotent free, and
the survivor already holds a frozen exclusion window over the victim's AGs — what breaks if the
survivor just completes the dead node's EFIs in its own transactions before publishing?

## The simple shape is UNSAFE. Three reasons, in order of severity.

**1. Two journals describing successive states (the killer).** Victim replay installs older
AGF/btree images; survivor completion mutates that state in the SURVIVOR's journal; survivor dies;
a third node replays the survivor then replays the victim again — overwriting newer metadata with
older logged images. Re-checking free-space does not repair overwritten btree structure, AGFL
consumption or accounting. Reverse case too: the survivor's completion may already be checkpointed
out of its journal while a retry replays the victim's older images anyway.

**2. "Already free" is not general idempotence.** `xfs_alloc_has_records()` is a free-space
COVERAGE test, not proof the extent still belongs to this obligation. Complete EFI -> exclusion
lost -> another node allocates the extent -> later retry frees THE NEW ALLOCATION. Corruption.
Partially-free must NOT be blindly freed — classify as unexpected and stop.

**3. Frozen victim grants are exclusion, not authorization.** Needs a narrow recovery credential
that stays verifiable when the survivor's own journal is replayed after the survivor dies. Task
identity admits nothing. Without it the survivor either deadlocks on the freeze it created, or
writes transactions a later foreign replay refuses.

## Recommended shape: EFI-only, SERIALIZED recovery custodian

Durable obligation record promoted from evidence to authoritative state machine:

    PENDING -> BASE_STABLE -> COMPLETING -> DISCHARGED -> PUBLISHED

**`BASE_STABLE` is the missing primitive.** Durable marker meaning "victim base images replayed and
durable; on restart do NOT replay them again, resume obligations from here." It is what dissolves
the two-journal hazard. No completion transaction may start before it is durable.

Record must carry: victim slot + slice incarnation, recovery case + custody term, AG domain + grant
generations, validated obligation manifest (or digest of retained slice), current recovery owner's
slot + journal incarnation, replay/checkpoint phase, outstanding orphan obligations, completion
evidence. Torn/unreadable record means NOT complete. Must be readable BEFORE the journals it
governs are replayed — never buried in the recovery owner's own journal.

Completion runs OUTSIDE the shadow log, in the survivor's live transaction context.
**`kfree()` is not a drain** — the shadow AIL must be detached/cancelled/drained properly.

### Barrier order

| operation | ordering |
|---|---|
| victim base home writes | before durable BASE_STABLE and before any completion txn |
| survivor log force | after completion commits |
| completion home writes/checkpoint | before DISCHARGED |
| CAW grant purge/release | only after durable DISCHARGED — TCP must obey the SAME gate |
| heartbeat zero | last |

## Of the 10 stop-ships: 3 shrink, 7 stay

SHRINK: per-AG generation-bound TAKEOVER -> retained custody under ONE custodian (don't transfer
grants, keep the freeze); two-phase proof block -> committed manifest + checkpoint evidence;
overlapping-case machinery -> serialize recovery cases cluster-wide (unrelated AGs stay live).

STAY (essential): publication/purge guard; custody across failures; recovery credential;
residual-holder cleanup before release; zero-census-vs-no-record discriminator; prior recovery-owner
replay dependency; transient/terminal error matrix.

> "The largest justified simplification is 'retained recovery custody plus checkpoint-before-release',
> not 'EFI is idempotent, so durable custody and dependencies are unnecessary.'"

## AGI unlinked sweep is HARDER than EFI, and needs its own obligation type

- `nlink==0` does NOT imply safe to inactivate: a SURVIVING node may still hold the file open.
  Fencing the victim removes only the victim's references.
- `xfs_inactive` can touch extents in OTHER AGs and CREATE NEW INTENTS, so it cannot run under only
  the frozen grant for the inode's AG.
- Preferred: durable handoff to a cluster orphan worker under normal distributed locking. Terminal
  state may be "completed" OR "durably transferred" — never "added to sweep_pending_slots".

## Interim availability

Add durable `RECOVERY_REQUIRED`/`RECOVERY_BLOCKED` distinct from terminal quarantine (resumable,
retryable). Terminal reserved for invalid authority, malformed metadata, unreconcilable allocation
state. BUT: *"Until a correct completion path exists, changing 'terminal quarantine' to 'pending
recovery' does not restore the affected AGs safely."* Keep fail-before-purge as the backstop.

## Feature gating (verified in-parent sess575)

`tools/mkfs_mxfs.c:970-971` writes `features_ro_compat = FINOBT` only — no RMAPBT, no REFLINK — so
EFI IS the only loggable intent class on this geometry. Log recovery names only EFI/EFD/RUI/CUD_RT
and the latter two are unreachable. BUT the fork retains 68 `xfs_has_rmapbt` / 69 `xfs_has_reflink`
call sites, so a filesystem carrying those bits would activate them. **Gate on the mounted fs's
ACTUAL feature bits and refuse unsupported intent classes** — never assume mkfs output.

## Flagged as possibly foundational

If MXFS cannot guarantee completion transactions are durably outside the replayable journal interval
before releasing custody, that is a SEPARATE defect this fix cannot bypass. Architectural invariant
1 (no on-disk DLM unlock without a completed drain pipeline) suggests the machinery exists — prove
it rather than assume it.
