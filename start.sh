#!/usr/bin/env bash
#   SESSION=name ./start.sh    use another tmux session name
#   tmux attach -t mxfs    watch it; Ctrl-b d to detach
#   tmux kill-session -t mxfs  stop it
set -euo pipefail

dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
session="${SESSION:-mxfs}"

command -v tmux >/dev/null || { echo "start.sh: tmux is not installed (brew install tmux)" >&2; exit 1; }
command -v ccloop >/dev/null || { echo "start.sh: ccloop is not on PATH" >&2; exit 1; }

if tmux has-session -t "$session" 2>/dev/null; then
  echo "already running: tmux attach -t $session"
  exit 0
fi

# Interactive TUI on the tmux pty: billed to the subscription. Never --headless here.
tmux new-session -d -s "$session" -c "$dir" './cc'
echo "started: tmux attach -t $session"
