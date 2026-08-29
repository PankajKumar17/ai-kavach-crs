#!/usr/bin/env bash
# RCA variance study: N runs of the unified C pipeline, collecting
# rca/cwe/time_taken/patch_tier/verified per run into a CSV for comparison.
set -u
REPO="/mnt/c/Users/panka/OneDrive/Desktop/hack/ai-kavach-crs"
WS_BASE="/tmp/kavach_rca_study"

rm -rf "$WS_BASE"; mkdir -p "$WS_BASE" /tmp/kavach_runs
cd "$REPO"

# Build two workspaces: sample_vuln (crash in main) and unknown_target (crash one call deep)
for tgt in sample_vuln unknown_target; do
  mkdir -p "$WS_BASE/$tgt/target"
  cp "$REPO/targets/$tgt/vuln.c" "$WS_BASE/$tgt/target/"
  cp "$REPO/targets/build_target.sh" "$WS_BASE/$tgt/"
done

export FUZZ_TIMEOUT_S=30

RUNS=4
for i in $(seq 1 $RUNS); do
  for tgt in sample_vuln unknown_target; do
    RID="rca_${tgt}_$i"
    echo "=== RUN $RID ==="
    .venv-wsl/bin/python -m ai_kavach.orchestrator \
      --target "$WS_BASE/$tgt/target" \
      --run-id "$RID" \
      --runs-dir /tmp/kavach_runs > "/tmp/kavach_runs/${RID}.log" 2>&1 || \
      echo "PIPELINE FAILED (see log)"
  done
done

# Extract the fields we care about into one CSV
echo "run_id,target,rca_len,cwe,time_taken_s,patch_tier,verified,status,total_time_s" > /tmp/kavach_runs/rca_variance.csv
.venv-wsl/bin/python - <<'EOF'
import json
from pathlib import Path

rows = ["sample_vuln", "unknown_target"]
out = []
for tgt in rows:
    for i in range(1, 5):
        rid = f"rca_{tgt}_{i}"
        p = Path(f"/tmp/kavach_runs/{rid}/summary.json")
        if not p.exists():
            out.append(f"{rid},{tgt},MISSING,,,,,,,,")
            continue
        d = json.loads(p.read_text())
        v = (d.get("vulnerabilities") or [{}])[0]
        out.append(",".join([
            rid, tgt,
            str(len(v.get("rca") or "")),
            v.get("cwe", "?").replace(",", ";"),
            str(v.get("time_taken", "?")),
            v.get("patch_tier", "?"),
            str(v.get("verified")),
            v.get("status", "?"),
            str(round(d.get("total_time_s") or 0, 1)),
        ]))
print("\n".join(out))
EOF
