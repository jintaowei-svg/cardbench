#!/usr/bin/env bash
set -euo pipefail

root=/home/wjt/CardDiffBench_transfer_full_20260716
cd "$root"
[[ "$(id -un)" == "wjt" ]] || exit 1

set -a
. ./.env
set +a
export CARDDIFF_AGNTCY_DIRCTL_PATH="$root/.runtime/agntcy/dirctl-linux-amd64"
export CARDDIFF_AGNTCY_DIRECTORY_ADDRESS=127.0.0.1:8888

targets=(anp nlip agntcy autogen langgraph)
mkdir -p logs/transfer_full

runner_alive() {
  local target="$1" pidfile="logs/transfer_full/$1.pid" pid owner cmd
  [[ -f "$pidfile" ]] || return 1
  pid="$(cat "$pidfile")"
  [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null || return 1
  owner="$(ps -o user= -p "$pid" | xargs)"
  cmd="$(tr '\0' ' ' < "/proc/$pid/cmdline")"
  [[ "$owner" == "wjt" && "$cmd" == *"harness.transfer_"*".runner"* && "$cmd" == *"configs/transfer_full/$target.yaml"* ]]
}

start_target() {
  local target="$1" python module output log pid
  case "$target" in
    anp|nlip)
      python="$root/.venv-native/bin/python"
      module=harness.transfer_native.runner
      ;;
    agntcy)
      (echo > /dev/tcp/127.0.0.1/8888) >/dev/null 2>&1 || {
        echo "AGNTCY directory unavailable during repair." >&2
        return 1
      }
      python="$root/.venv-agntcy/bin/python"
      module=harness.transfer_native.runner
      ;;
    autogen|langgraph)
      python="$root/.venv-framework/bin/python"
      module=harness.transfer_framework.runner
      ;;
  esac
  output="results/transfer_full/$target/supplement.jsonl"
  log="logs/transfer_full/$target.log"
  printf '\n[%s] supervisor restart %s\n' "$(date -Is)" "$target" >> "$log"
  nohup "$python" -m "$module" "configs/transfer_full/$target.yaml" \
    --output "$output" \
    --case-id-manifest attacks/carddiff/transfer_full/run_case_ids.json \
    --resume >> "$log" 2>&1 &
  pid="$!"
  echo "$pid" > "logs/transfer_full/$target.pid"
  echo "restarted $target PID $pid"
}

audit_and_plan_repairs() {
  .venv-native/bin/python - <<'PY'
import json
from pathlib import Path

root = Path("results/transfer_full")
wanted = json.loads(Path("attacks/carddiff/transfer_full/run_case_ids.json").read_text(encoding="utf-8"))
retry = {}
status = {}
for target in ("anp", "nlip", "agntcy", "autogen", "langgraph"):
    path = root / target / "supplement.jsonl"
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()] if path.exists() else []
    ids = [str(row["target_case_id"]) for row in rows]
    if len(ids) != len(set(ids)):
        raise RuntimeError(f"{target}: duplicate target_case_id in supplement")
    expected = set(map(str, wanted[target]))
    unexpected = sorted(set(ids) - expected)
    if unexpected:
        raise RuntimeError(f"{target}: unexpected IDs: {unexpected[:3]}")
    missing = expected - set(ids)
    errors = {str(row["target_case_id"]) for row in rows if row.get("error") is not None}
    retry[target] = sorted(missing | errors)
    status[target] = {
        "expected": len(expected),
        "rows": len(rows),
        "missing": len(missing),
        "errors": len(errors),
        "retry": len(retry[target]),
    }
plan = {"retry": retry, "status": status, "total_retry": sum(map(len, retry.values()))}
(root / "supervisor_repair_plan.json").write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(plan, sort_keys=True))
PY
}

repair_round=0
while true; do
  while true; do
    alive=0
    for target in "${targets[@]}"; do
      runner_alive "$target" && alive=1
    done
    [[ "$alive" == 0 ]] && break
    sleep 60
  done

  audit_and_plan_repairs
  total_retry="$(.venv-native/bin/python -c 'import json; print(json.load(open("results/transfer_full/supervisor_repair_plan.json"))["total_retry"])')"
  [[ "$total_retry" == 0 ]] && break
  repair_round=$((repair_round + 1))
  if (( repair_round > 3 )); then
    echo "Repair limit exceeded with $total_retry cases remaining." >&2
    exit 2
  fi

  for target in "${targets[@]}"; do
    retry_count="$(.venv-native/bin/python -c "import json; print(len(json.load(open('results/transfer_full/supervisor_repair_plan.json'))['retry']['$target']))")"
    [[ "$retry_count" == 0 ]] && continue
    output="results/transfer_full/$target/supplement.jsonl"
    [[ -f "$output" ]] && cp "$output" "$output.pre_repair_$repair_round"
    .venv-native/bin/python - "$target" "$output" <<'PY'
import json, sys
from pathlib import Path

target, output = sys.argv[1:]
path = Path(output)
rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()] if path.exists() else []
retry = set(json.loads(Path("results/transfer_full/supervisor_repair_plan.json").read_text(encoding="utf-8"))["retry"][target])
kept = [row for row in rows if str(row["target_case_id"]) not in retry]
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in kept), encoding="utf-8")
PY
    start_target "$target"
  done
done

.venv-native/bin/python scripts/finalize_transfer_full.py > logs/transfer_full/finalize.json
.venv-native/bin/python - <<'PY'
import datetime, json, subprocess
from pathlib import Path

summary = json.loads(Path("results/transfer_full/summary.json").read_text(encoding="utf-8"))
for target, payload in summary.items():
    if payload["missing"] != 0 or payload["completed"] != payload["planned"]:
        raise RuntimeError(f"Incomplete final result: {target}: {payload}")
marker = {
    "completed_at": datetime.datetime.now(datetime.timezone.utc).astimezone().isoformat(),
    "git_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
    "summary": summary,
}
Path("results/transfer_full/completed.json").write_text(json.dumps(marker, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print("TRANSFER_FULL_COMPLETE")
PY
