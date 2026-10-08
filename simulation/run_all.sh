#!/bin/bash
# run_all.sh -- builds the REVISED ECC-HMAC ns-3 simulation, runs the unit
# tests, then sweeps N x seed x dutyCycle (section 5 of the task spec, run
# under both the realistic duty-cycled radio scenario and the always-on
# "stress test" scenario for comparison) and the optional AUTH_M1/AUTH_M2
# loss experiment (duty-cycled only), writing all CSV outputs under results/.
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NS3_DIR="$SCRIPT_DIR/ns-3.37"
BIN="$NS3_DIR/build/scratch/ns3.37-ecc-hmac-revised"
TESTBIN="$NS3_DIR/build/scratch/ns3.37-ecc-hmac-tests"
RESULTS_DIR="$SCRIPT_DIR/results"
RAW_DIR="$RESULTS_DIR/raw"
LOSS_RAW_DIR="$RESULTS_DIR/raw_loss"

mkdir -p "$RAW_DIR" "$LOSS_RAW_DIR"

echo "== Building ns-3 targets (scratch_ecc-hmac-revised, scratch_ecc-hmac-tests) =="
(cd "$NS3_DIR/cmake-cache" && ninja scratch_ecc-hmac-revised scratch_ecc-hmac-tests)

echo "== Running unit tests (section 3.3) =="
"$TESTBIN" | tee "$RESULTS_DIR/unit_test_results.txt"

# ---------------------------------------------------------------------------
# Main experiment: section 5 -- N in {100..1000,1200}, 5 seeds each, run
# under both duty-cycled (realistic, default) and always-on ("stress test",
# reproduces the pre-duty-cycling behaviour) radio scenarios for comparison.
# ---------------------------------------------------------------------------
N_VALUES="100 200 300 400 500 600 700 800 900 1000 1200"
SEEDS="1 2 3 4 5"
DUTY_CYCLES="1 0"

echo "== Main sweep: N in {$N_VALUES}, seeds {$SEEDS}, dutyCycle in {$DUTY_CYCLES} =="
for DC in $DUTY_CYCLES; do
    for N in $N_VALUES; do
        for SEED in $SEEDS; do
            OUT="$RAW_DIR/N${N}_seed${SEED}_dc${DC}"
            "$BIN" --N=$N --seed=$SEED --dutyCycle=$DC --outPrefix="$OUT" >"${OUT}.log" 2>&1
            echo "N=$N seed=$SEED dutyCycle=$DC -> $(tail -1 "${OUT}.log")"
        done
    done
done

echo "== Aggregating main sweep CSVs =="
SUMMARY="$RESULTS_DIR/summary_all.csv"
PERNODE="$RESULTS_DIR/pernode_all.csv"
first=1
for f in "$RAW_DIR"/*_summary.csv; do
    if [ $first -eq 1 ]; then
        head -1 "$f" >"$SUMMARY"
        first=0
    fi
    tail -n +2 "$f" >>"$SUMMARY"
done
first=1
for f in "$RAW_DIR"/*_pernode.csv; do
    if [ $first -eq 1 ]; then
        head -1 "$f" >"$PERNODE"
        first=0
    fi
    tail -n +2 "$f" >>"$PERNODE"
done
echo "Wrote $SUMMARY ($(wc -l <"$SUMMARY") lines) and $PERNODE ($(wc -l <"$PERNODE") lines)"

# ---------------------------------------------------------------------------
# Optional extra experiment: section 5 -- N=100, AUTH_M1/AUTH_M2 loss sweep
# ---------------------------------------------------------------------------
LOSS_PROBS="0 0.05 0.1 0.2 0.3"
echo "== Loss experiment: N=100, lossProb in {$LOSS_PROBS}, seeds {$SEEDS} =="
for LP in $LOSS_PROBS; do
    for SEED in $SEEDS; do
        OUT="$LOSS_RAW_DIR/N100_loss${LP}_seed${SEED}"
        "$BIN" --N=100 --seed=$SEED --lossProb=$LP --outPrefix="$OUT" >"${OUT}.log" 2>&1
        echo "loss=$LP seed=$SEED -> $(tail -1 "${OUT}.log")"
    done
done

echo "== Aggregating loss experiment CSVs =="
LOSS_SUMMARY="$RESULTS_DIR/loss_experiment_summary.csv"
first=1
for f in "$LOSS_RAW_DIR"/*_summary.csv; do
    if [ $first -eq 1 ]; then
        head -1 "$f" >"$LOSS_SUMMARY"
        first=0
    fi
    tail -n +2 "$f" >>"$LOSS_SUMMARY"
done
# lossProb is not itself a CSV column -- recover it from the file name so the
# plotting/report stage does not need to re-derive it.
python3 - "$LOSS_RAW_DIR" "$LOSS_SUMMARY" <<'PYEOF'
import csv
import glob
import os
import re
import sys

raw_dir, out_path = sys.argv[1], sys.argv[2]
rows = []
header = None
for f in sorted(glob.glob(os.path.join(raw_dir, "*_summary.csv"))):
    m = re.search(r"N100_loss([0-9.]+)_seed(\d+)_summary\.csv$", f)
    if not m:
        continue
    loss_prob = m.group(1)
    with open(f, newline="") as fh:
        r = csv.reader(fh)
        h = next(r)
        if header is None:
            header = ["lossProb"] + h
        for row in r:
            rows.append([loss_prob] + row)

with open(out_path, "w", newline="") as fh:
    w = csv.writer(fh)
    w.writerow(header)
    w.writerows(rows)
print(f"Wrote {out_path} ({len(rows)} rows)")
PYEOF

echo "== run_all.sh complete =="
