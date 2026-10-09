#!/usr/bin/env bash
# Poll a GitHub Actions run until it reaches a terminal state, then print the
# per-step outcome. Designed to be run in the background; it prints a line only
# when something changes, so the log stays readable.
#
#   tools/ci_watch.sh <run-id> [repo]
set -uo pipefail

RUN_ID="${1:?usage: ci_watch.sh <run-id> [repo]}"
REPO="${2:-MaiHaobo/Luna}"
API="https://api.github.com/repos/${REPO}/actions/runs/${RUN_ID}"

last=""
for _ in $(seq 1 200); do
  json="$(curl -sS -H "Accept: application/vnd.github+json" "$API" 2>/dev/null)" || { sleep 20; continue; }

  status="$(printf '%s' "$json" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("status",""))' 2>/dev/null)"
  conclusion="$(printf '%s' "$json" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("conclusion") or "")' 2>/dev/null)"

  [ -z "$status" ] && { sleep 20; continue; }

  line="${status}/${conclusion}"
  if [ "$line" != "$last" ]; then
    echo "[$(date -u +%H:%M:%S)] run ${RUN_ID}: ${line}"
    last="$line"
  fi

  case "$status" in
    completed) break ;;
  esac
  sleep 20
done

echo
echo "=== steps ==="
curl -sS -H "Accept: application/vnd.github+json" \
  "https://api.github.com/repos/${REPO}/actions/runs/${RUN_ID}/jobs" 2>/dev/null \
| python3 -c '
import json, sys

data = json.load(sys.stdin)
marks = {"success": "ok  ", "failure": "FAIL", "skipped": "skip", "cancelled": "cncl"}
for job in data.get("jobs", []):
    conclusion = job.get("conclusion") or job.get("status")
    print("job: {}  ->  {}".format(job["name"], conclusion))
    for step in job.get("steps", []):
        mark = marks.get(step.get("conclusion") or "", "..  ")
        print("   {} {:2d}. {}".format(mark, step["number"], step["name"]))
'
