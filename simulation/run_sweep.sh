#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
NS3_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
OUT_DIR="${SCRIPT_DIR}/results/sweep"
GRAPH_DIR="${OUT_DIR}/graphs"
BIN="${NS3_ROOT}/build/scratch/ns3-dev-cooja-ecc-hmac-translated-ns3"

COUNTS_STR="${1:-10 20 50 100}"
SIM_STOP="${2:-40}"
START_WINDOW="${3:-3}"
ENABLE_ANIM="${4:-false}"
TIMING_MODE="${5:-adaptive}"

mkdir -p "${OUT_DIR}" "${GRAPH_DIR}"

if [[ ! -x "${BIN}" ]]; then
  echo "[ERROR] Binary not found: ${BIN}"
  echo "Build it once from ns-3-dev with a working cmake toolchain."
  exit 1
fi

SUMMARY="${OUT_DIR}/sweep_summary.csv"
echo "num_iot,client_count,success_rate,avg_server_auth_ms,avg_scenario_total_ms,avg_tx_bytes,avg_rx_bytes,avg_tx_pkts,avg_rx_pkts,avg_energest_cpu,avg_energest_lpm,avg_energest_tx,avg_energest_rx,avg_energy_mj" > "${SUMMARY}"

echo "[INFO] Sweep counts: ${COUNTS_STR}"

for N in ${COUNTS_STR}; do
  LOG_FILE="${OUT_DIR}/log${N}.log"
  CSV_FILE="${OUT_DIR}/log${N}.csv"
  XML_FILE="${OUT_DIR}/log${N}.xml"

  RUN_SIM_STOP="${SIM_STOP}"
  RUN_START_WINDOW="${START_WINDOW}"

  # With large N, fixed short timing causes artificial failures due contention.
  # Adaptive mode scales simulation time and start jitter with node count.
  if [[ "${TIMING_MODE}" == "adaptive" ]]; then
    RUN_SIM_STOP=$(( SIM_STOP + (N / 4) ))
    RUN_START_WINDOW=$(( START_WINDOW + (N / 20) ))
  fi

  echo "[RUN] num_iot=${N} simStop=${RUN_SIM_STOP} startWindow=${RUN_START_WINDOW} mode=${TIMING_MODE}"
  "${BIN}" \
    --numClients="${N}" \
    --simStop="${RUN_SIM_STOP}" \
    --startWindow="${RUN_START_WINDOW}" \
    --enableAnim="${ENABLE_ANIM}" \
    --animFile="${XML_FILE}" \
    | tee "${LOG_FILE}" >/dev/null

  grep '^CSV,' "${LOG_FILE}" > "${CSV_FILE}" || true

  awk -F',' -v n="${N}" '
    BEGIN {
      c=0; auth=0; scen=0; txb=0; rxb=0; txp=0; rxp=0; cpu=0; lpm=0; txe=0; rxe=0; en=0;
    }
    $1=="CSV" && $2=="client" {
      c++;
      auth += $4; scen += $5; txb += $6; rxb += $7;
      txp += $8; rxp += $9; cpu += $10; lpm += $11;
      txe += $12; rxe += $13; en += $14;
    }
    END {
      if(c==0){
        printf "%d,0,0,0,0,0,0,0,0,0,0,0,0,0\n", n;
      } else {
        sr = c / n;
        printf "%d,%d,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f\n",
          n,c,sr,auth/c,scen/c,txb/c,rxb/c,txp/c,rxp/c,cpu/c,lpm/c,txe/c,rxe/c,en/c;
      }
    }
  ' "${CSV_FILE}" >> "${SUMMARY}"
done

plot_svg() {
  local col_idx="$1"
  local title="$2"
  local y_label="$3"
  local out_name="$4"
  awk -F',' -v col="${col_idx}" -v t="${title}" -v yl="${y_label}" -v out="${GRAPH_DIR}/${out_name}" '
    function esc(s){gsub("&","&amp;",s); gsub("<","&lt;",s); gsub(">","&gt;",s); return s}
    BEGIN {
      w=1200; h=700; ml=90; mr=40; mt=50; mb=120;
      n=0; minx=1e18; maxx=-1e18; miny=1e18; maxy=-1e18;
    }
    NR>1 {
      n++;
      x[n]=$1+0;
      y[n]=$(col)+0;
      if(x[n]<minx) minx=x[n]; if(x[n]>maxx) maxx=x[n];
      if(y[n]<miny) miny=y[n]; if(y[n]>maxy) maxy=y[n];
    }
    END {
      if(n==0) exit 1;
      if(maxx==minx) maxx=minx+1;
      if(maxy==miny) maxy=miny+1;

      print "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\""w"\" height=\""h"\">" > out;
      print "<rect width=\"100%\" height=\"100%\" fill=\"white\"/>" >> out;
      print "<text x=\""(w/2)"\" y=\"28\" text-anchor=\"middle\" font-size=\"22\" font-family=\"Arial\">" esc(t) "</text>" >> out;

      x0=ml; y0=h-mb; x1=w-mr; y1=mt;
      print "<line x1=\""x0"\" y1=\""y0"\" x2=\""x1"\" y2=\""y0"\" stroke=\"black\"/>" >> out;
      print "<line x1=\""x0"\" y1=\""y0"\" x2=\""x0"\" y2=\""y1"\" stroke=\"black\"/>" >> out;

      for(i=1;i<=n;i++){
        px = x0 + (x[i]-minx)*(x1-x0)/(maxx-minx);
        py = y0 - (y[i]-miny)*(y0-y1)/(maxy-miny);
        xp[i]=px; yp[i]=py;
      }

      pts="";
      for(i=1;i<=n;i++) pts = pts sprintf("%.2f,%.2f ", xp[i], yp[i]);
      print "<polyline fill=\"none\" stroke=\"#006d77\" stroke-width=\"3\" points=\"" pts "\"/>" >> out;

      for(i=1;i<=n;i++){
        print "<circle cx=\""xp[i]"\" cy=\""yp[i]"\" r=\"4\" fill=\"#d62828\"/>" >> out;
        print "<text x=\""xp[i]"\" y=\""(y0+20)"\" text-anchor=\"middle\" font-size=\"11\" font-family=\"Arial\">" x[i] "</text>" >> out;
      }

      print "<text x=\""(w/2)"\" y=\""(h-20)"\" text-anchor=\"middle\" font-size=\"14\" font-family=\"Arial\">Number of IoT nodes</text>" >> out;
      print "<text x=\"30\" y=\""(h/2)"\" transform=\"rotate(-90 30,"(h/2)")\" text-anchor=\"middle\" font-size=\"14\" font-family=\"Arial\">" esc(yl) "</text>" >> out;
      print "</svg>" >> out;
    }
  ' "${SUMMARY}"
}

plot_svg 3  "Success rate vs IoT"                "success ratio"       "success_rate_vs_iot.svg"
plot_svg 4  "Auth latency average vs IoT"        "ms"                  "auth_latency_avg_vs_iot.svg"
plot_svg 5  "Scenario time average vs IoT"       "ms"                  "scenario_total_avg_vs_iot.svg"
plot_svg 6  "TX bytes average vs IoT"            "bytes"               "tx_bytes_avg_vs_iot.svg"
plot_svg 7  "RX bytes average vs IoT"            "bytes"               "rx_bytes_avg_vs_iot.svg"
plot_svg 8  "TX packets average vs IoT"          "packets"             "tx_pkts_avg_vs_iot.svg"
plot_svg 9  "RX packets average vs IoT"          "packets"             "rx_pkts_avg_vs_iot.svg"
plot_svg 10 "Energest CPU average vs IoT"        "ticks"               "energest_cpu_avg_vs_iot.svg"
plot_svg 11 "Energest LPM average vs IoT"        "ticks"               "energest_lpm_avg_vs_iot.svg"
plot_svg 12 "Energest TX average vs IoT"         "ticks"               "energest_tx_avg_vs_iot.svg"
plot_svg 13 "Energest RX average vs IoT"         "ticks"               "energest_rx_avg_vs_iot.svg"
plot_svg 14 "Energy average vs IoT"              "mJ"                  "energy_avg_vs_iot.svg"

echo "[DONE] Summary CSV: ${SUMMARY}"
echo "[DONE] Graphs dir : ${GRAPH_DIR}"
