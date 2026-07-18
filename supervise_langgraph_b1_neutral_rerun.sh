#!/usr/bin/env bash
set -euo pipefail

root=/home/wjt/CardDiffBench_transfer_full_20260716
cd "$root"
[[ "$(id -un)" == "wjt" ]] || exit 1

set -a
. ./.env
set +a

result_dir=results/transfer_full/langgraph_b1_neutral_rerun
output="$result_dir/details.jsonl"
ids=attacks/carddiff/transfer_full/langgraph_b1_neutral_rerun_ids.json
pidfile=logs/transfer_full/langgraph_b1_neutral_rerun.pid
log=logs/transfer_full/langgraph_b1_neutral_rerun.log
mkdir -p "$result_dir" logs/transfer_full

runner_alive() {
  local pid owner cmd
  [[ -f "$pidfile" ]] || return 1
  pid="$(cat "$pidfile")"
  [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null || return 1
  owner="$(ps -o user= -p "$pid" | xargs)"
  cmd="$(tr '\0' ' ' < "/proc/$pid/cmdline")"
  [[ "$owner" == "wjt" && "$cmd" == *"harness.transfer_framework.runner"* && "$cmd" == *"$output"* ]]
}

start_runner() {
  printf '\n[%s] supervisor restart\n' "$(date -Is)" >> "$log"
  nohup .venv-framework/bin/python -m harness.transfer_framework.runner \
    configs/transfer_full/langgraph.yaml \
    --output "$output" \
    --case-id-manifest "$ids" \
    --resume >> "$log" 2>&1 &
  echo "$!" > "$pidfile"
  echo "restarted runner PID $!"
}

audit() {
  .venv-framework/bin/python - <<'PY'
import json
from pathlib import Path

root = Path("results/transfer_full/langgraph_b1_neutral_rerun")
output = root / "details.jsonl"
wanted = set(json.loads(Path("attacks/carddiff/transfer_full/langgraph_b1_neutral_rerun_ids.json").read_text(encoding="utf-8"))["langgraph"])
rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines() if line.strip()] if output.exists() else []
ids = [str(row["target_case_id"]) for row in rows]
if len(ids) != len(set(ids)):
    raise RuntimeError("Duplicate target_case_id in neutral rerun")
unexpected = sorted(set(ids) - wanted)
if unexpected:
    raise RuntimeError(f"Unexpected neutral rerun IDs: {unexpected[:3]}")
missing = wanted - set(ids)
errors = {str(row["target_case_id"]) for row in rows if row.get("error") is not None}
plan = {
    "expected": len(wanted),
    "rows": len(rows),
    "missing": len(missing),
    "errors": len(errors),
    "retry_ids": sorted(missing | errors),
}
(root / "repair_plan.json").write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(plan, sort_keys=True))
PY
}

repair_round=0
while true; do
  while runner_alive; do sleep 60; done
  audit
  retry_count="$(.venv-framework/bin/python -c 'import json; print(len(json.load(open("results/transfer_full/langgraph_b1_neutral_rerun/repair_plan.json"))["retry_ids"]))')"
  [[ "$retry_count" == 0 ]] && break
  repair_round=$((repair_round + 1))
  (( repair_round <= 3 )) || {
    echo "Repair limit exceeded with $retry_count cases remaining." >&2
    exit 2
  }
  [[ -f "$output" ]] && cp "$output" "$output.pre_repair_$repair_round"
  .venv-framework/bin/python - <<'PY'
import json
from pathlib import Path

root = Path("results/transfer_full/langgraph_b1_neutral_rerun")
output = root / "details.jsonl"
retry = set(json.loads((root / "repair_plan.json").read_text(encoding="utf-8"))["retry_ids"])
rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines() if line.strip()] if output.exists() else []
kept = [row for row in rows if str(row["target_case_id"]) not in retry]
output.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in kept), encoding="utf-8")
PY
  start_runner
done

.venv-framework/bin/python - <<'PY'
import datetime
import json
import subprocess
from collections import Counter
from pathlib import Path

root = Path("results/transfer_full/langgraph_b1_neutral_rerun")
rows = [json.loads(line) for line in (root / "details.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
old_rows = [
    json.loads(line)
    for line in Path("results/transfer_full/langgraph/details.jsonl").read_text(encoding="utf-8").splitlines()
    if line.strip() and json.loads(line).get("attack_type") == "B1"
]

def summarize(values, planned):
    completed = len(values)
    judged = sum(row.get("native_execution_valid") is True for row in values)
    successes = sum(row.get("success") is True for row in values)
    return {
        "planned": planned,
        "completed": completed,
        "judged": judged,
        "successes": successes,
        "errors": sum(row.get("error") is not None for row in values),
        "asr_planned": successes / planned,
        "asr_judged": successes / judged if judged else None,
        "choices": {
            f"{capability}|{interface}": count
            for (capability, interface), count in sorted(
                Counter(
                    (
                        (row.get("decision") or {}).get("capability_id"),
                        (row.get("decision") or {}).get("interface_index"),
                    )
                    for row in values
                ).items()
            )
        },
    }

summary = summarize(rows, 450)
summary["by_domain"] = {
    domain: summarize([row for row in rows if row["domain"] == domain], 150)
    for domain in sorted({row["domain"] for row in rows})
}
summary["by_variant"] = {
    variant: summarize([row for row in rows if row["variant"] == variant], 150)
    for variant in sorted({row["variant"] for row in rows})
}
(root / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
comparison = {
    "old_leaky_labels": summarize(old_rows, 450),
    "new_neutral_labels": summary,
}
(root / "comparison.json").write_text(json.dumps(comparison, indent=2, sort_keys=True) + "\n", encoding="utf-8")
completed = {
    "completed_at": datetime.datetime.now(datetime.timezone.utc).astimezone().isoformat(),
    "git_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
    "summary": summary,
}
(root / "completed.json").write_text(json.dumps(completed, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print("LANGGRAPH_B1_NEUTRAL_RERUN_COMPLETE", summary["successes"], summary["asr_planned"])
PY
