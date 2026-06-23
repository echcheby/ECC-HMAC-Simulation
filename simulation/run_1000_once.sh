#!/usr/bin/env bash
set -euo pipefail

cd /home/mohamed/NS3/ns-3-dev
BIN="build/scratch/ns3-dev-cooja-ecc-hmac-translated-ns3"
OUT="scratch/simulation_Ecc_Hmac/results/sweep"

mkdir -p "$OUT"
"$BIN" \
  --numClients=1000 \
  --simStop=200 \
  --startWindow=80 \
  --enableAnim=false \
  --animFile="$OUT/log1000.xml" \
  | tee "$OUT/log1000.log" >/dev/null

grep '^CSV,' "$OUT/log1000.log" > "$OUT/log1000.csv" || true

echo "[DONE] $OUT/log1000.log"
echo "[DONE] $OUT/log1000.csv"
