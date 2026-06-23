#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
NS3_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
OUT_DIR="${SCRIPT_DIR}/results"

NUM_CLIENTS="${1:-30}"
SIM_STOP="${2:-120}"
START_WINDOW="${3:-20}"

mkdir -p "${OUT_DIR}"

LOG_FILE="${OUT_DIR}/translated-log${NUM_CLIENTS}.log"
CSV_FILE="${OUT_DIR}/translated-log${NUM_CLIENTS}.csv"
XML_FILE="${OUT_DIR}/translated-log${NUM_CLIENTS}.xml"

echo "[INFO] Running translated Cooja protocol on ns-3"
echo "[INFO] numClients=${NUM_CLIENTS}, simStop=${SIM_STOP}, startWindow=${START_WINDOW}"

cd "${NS3_ROOT}"
./ns3 run "scratch/simulation_Ecc_Hmac/cooja-ecc-hmac-translated-ns3 --numClients=${NUM_CLIENTS} --simStop=${SIM_STOP} --startWindow=${START_WINDOW} --enableAnim=true --animFile=${XML_FILE}" | tee "${LOG_FILE}"

grep '^CSV,' "${LOG_FILE}" > "${CSV_FILE}" || true

echo "[DONE] Log: ${LOG_FILE}"
echo "[DONE] CSV: ${CSV_FILE}"
echo "[DONE] NetAnim XML: ${XML_FILE}"
