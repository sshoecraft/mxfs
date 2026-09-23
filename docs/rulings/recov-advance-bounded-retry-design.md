<!-- sess420 RULE-5 ruling on D-RECOV-ADVANCE-UNBOUNDED-RETRY fix shape: ship fail-stop withdraw (ii) at deadline/invariant; stage-aware classify; identit… -->
# sess420 GPT ruling — bounded completion retry (D-RECOV-ADVANCE-UNBOUNDED-RETRY)

Consult: gpt-5.6-sol. Reviewed my design A/B/C (v5_complete_fail classifier + blocked[].terminal latch + -ECANCELED to xfs).

## Verdict: the latch-only design converts an infinite retry into a PERMANENT in-memory stranded
recovery while the node stays the positional elected owner. Must be coupled to supersession,
durable decline, or fail-stop withdrawal.

## Rulings
1. Deadline outcome: SHIP OPTION (ii) — after a successful per-slot relinquish (owner->UNOWNED,
   exact freshly-read expected image, never blind), FAIL-STOP this mount: stop shared-LUN I/O,
   mark mount failed (not RO), withdraw heartbeat/election eligibility, so the next-lowest survivor
   claims the preserved descriptor. Relinquish failure -> same withdrawn path. Option (i) (terminal
   latch, node eligible) does NOT satisfy the ruling. Option (iii) (durable decline mask keyed by
   recovery gen + declining incarnation + victim epoch, deterministic next owner, all-decline
   policy) is the long-term availability design — separate protocol work.
2. Same-owner -EBUSY is an INVARIANT only if every auth-covered field is immutable while held:
   compare owner slot+incarnation, recovery gen, owner term, victim slot/node/epoch, cert identity,
   stage assumptions. Any legitimate refresh/renew that bumps a covered field must refresh the
   in-memory token or return a distinct 'local auth stale; reacquire'. Only -EBUSY FROM
   recov_auth_holds() counts — classify by typed site/reason, never errno alone.
3. INVARIANT: do NOT relinquish with the suspect auth; preserve descriptor+guard for diagnosis;
   but the outcome must be a loud FS failure + election withdrawal/self-fence, not a latch.
4. Missing classes: (a) committed-but-reported-failed — pass the INTENDED transition, re-read,
   classify by observed stage (>= intended: continue from durable state; at predecessor: retry;
   regressed/incompatible: invariant/superseded; unreadable: bounded transient). (b) -ENOENT only
   = 'published elsewhere' when it means a VERIFIED well-formed zero/consumable record; then run the
   idempotent recovered_cb retirement locally. (c) TAKEOVER cancels the CURRENT recovery identity
   (gen/term), never the whole victim epoch; unexpected UNOWNED -> allow a new election. (d) -EPERM
   not inherently terminal: split quarantined (terminal by design) / pre-fence / policy / stale cert.
   (e) manifest 'undecided' = safety-sensitive transient with deadline; victim-found-live = explicit
   abort path. (f) purge failure may have committed: re-read authority table + descriptor; never
   publish GRANTS_RELEASED without durable proof; takeover may repeat purge only if idempotent and
   scoped by victim/recovery identity. (g) heartbeat-zero failure belongs to fencing/certificate,
   bounded retry, deadline -> relinquish/escalate without weakening fencing. (h) AUDIT failures
   BEFORE auth is held (acquire/auth/entry gates/refresh) — the loop survives through them.
5. Backoff: exponential capped w/ jitter 5/10/20/40 s, schedule min(next, deadline-now). Deadline
   from the FIRST completion failure of THIS recovery identity + an absolute cap anchored on a
   DURABLE event (fence-certificate / acquisition time) so restart/latch loss cannot reset it.
   Key retry state by full recovery identity. Do NOT re-replay the slice once the durable
   descriptor proves IMAGES_REPLAYED — retry only the remaining ladder.
6. Distinct outcomes instead of -ECANCELED overload: PUBLISHED / SUPERSEDED / RETRY /
   FATAL_INVARIANT / FATAL_WITHDRAW. Only PUBLISHED retires the marker; SUPERSEDED cancels stale
   work but keeps monitoring; FATAL invokes the FS health/withdrawal path. Synchronize blocked[]
   + retry records against worker/election/callback concurrency. Diagnostics must carry site,
   expected pre/post stage, observed descriptor, full auth token, owner incarnation, cert id.
