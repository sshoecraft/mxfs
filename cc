#!/bin/bash
# Resume the most recent ccloop run for this project.
#
# The run to resume is the newest directory under .ccloop/runs/ (by mtime,
# i.e. the most recently active run).  Any extra args are passed through to
# ccloop and override the defaults below (last occurrence wins).
#
# The original run was started with:
#   ccloop --model=fable --effort=max --cutoff=145 \
#          "all known issues resolved" "read continue_troubelshooting.md for prompt"

. ~/.bashrc

cd "$(dirname "$(readlink -f "$0")")" || exit 1

runs_dir=.ccloop/runs

latest=$(ls -1dt "$runs_dir"/*/ 2>/dev/null | head -n1)
if [ -z "$latest" ]; then
    echo "cc: no ccloop runs found in $PWD/$runs_dir" >&2
    echo "cc: start one with: ccloop \"<criteria>\" \"<task>\"" >&2
    exit 1
fi

run_id=$(basename "$latest")

echo "cc: resuming ccloop run $run_id"
[ -f "$runs_dir/$run_id/task.md" ] && echo "cc: task — $(head -n1 "$runs_dir/$run_id/task.md")"

exec ccloop --model=fable --effort=high --cutoff=145 --resume-run "$run_id" "$@"
