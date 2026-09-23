#!/bin/bash
# sess454 chain 76: the 12 RETIRE_PENDING laps again on 0.60.0 (sv 0EB2C07B)
# with the harness count fixed — chain 74's joiner/unknown/unknownresv/
# joinerunk "FAIL"s were tests/retire_pending_admission.sh counting
# P163-RECOVERY-COMPLETE through the MARKS header, which never listed it
# (the joiner arm's evidence shows the fenced slot recovered 6.3 s after the
# WITHDRAWN stamp: D-0519 fixed).  This run is the D-0519 verification.
# Gated on chain 75 DONE (rig idle) AND on the go-file the session creates
# after editing the harness (never edit a bash script while it runs).
cd /src/mxfs || exit 1
GATE=tests/evidence/sess454_chain75_admission_arms_s454b.log
GO=tests/evidence/.sess454_chain76_go
while ! grep -q "^DONE" "$GATE" 2>/dev/null || [ ! -e "$GO" ]; do sleep 30; done
exec tests/sess452_chain71_retire_pending.sh "${1:-s454c}" "${2:-0EB2C07B99A80502A11C6B1}"
