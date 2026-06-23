#!/usr/bin/env bash
set -euo pipefail

cd /home/mohamed/NS3/ns-3-dev
export PATH="$HOME/.local/bin:$PATH"

# Force rebuild + sanity run using the root scratch target used by sweep binary
./ns3 run "scratch/cooja-ecc-hmac-translated-ns3 --numClients=2 --simStop=20 --startWindow=2 --enableAnim=false --animFile=scratch/simulation_Ecc_Hmac/results/manual/ecc_warmup.xml" \
  > scratch/simulation_Ecc_Hmac/results/manual/ecc_rebuild_warmup.log 2>&1

# Requested sweep 100..900
bash scratch/simulation_Ecc_Hmac/run_sweep_metrics.sh "100 200 300 400 500 600 700 800 900" 200 80 false fixed \
  > scratch/simulation_Ecc_Hmac/results/sweep/ecc_real_sweep_100_900.log 2>&1

echo "[DONE] warmup log: scratch/simulation_Ecc_Hmac/results/manual/ecc_rebuild_warmup.log"
echo "[DONE] sweep log : scratch/simulation_Ecc_Hmac/results/sweep/ecc_real_sweep_100_900.log"
