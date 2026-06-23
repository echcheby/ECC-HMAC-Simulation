#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
NS3_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
BIN="${NS3_ROOT}/build/scratch/ns3-dev-cooja-ecc-hmac-translated-ns3"
OUT_BASE="${SCRIPT_DIR}/results/comparison"
COUNTS="${1:-100 200 300 400 500 600 700 800 900}"
SIM_STOP="${2:-200}"
START_WINDOW="${3:-80}"

mkdir -p "${OUT_BASE}/mock" "${OUT_BASE}/ecc"

if [[ ! -x "${BIN}" ]]; then
  echo "[ERROR] Missing binary: ${BIN}"
  exit 1
fi

aggregate_mode() {
  local mode="$1"
  local use_mock="$2"
  local out_dir="${OUT_BASE}/${mode}"
  local summary="${out_dir}/summary.csv"

  echo "num_iot,client_count,success_rate,avg_server_auth_ms,avg_energy_mj" > "${summary}"

  for n in ${COUNTS}; do
    local log_file="${out_dir}/log${n}.log"
    local csv_file="${out_dir}/log${n}.csv"
    local xml_file="${out_dir}/log${n}.xml"

    echo "[RUN][${mode}] N=${n}"
    "${BIN}" \
      --numClients="${n}" \
      --simStop="${SIM_STOP}" \
      --startWindow="${START_WINDOW}" \
      --enableAnim=false \
      --useMockEcc="${use_mock}" \
      --animFile="${xml_file}" \
      | tee "${log_file}" >/dev/null

    grep '^CSV,' "${log_file}" > "${csv_file}" || true

    awk -F',' -v n="${n}" '
      BEGIN { c=0; auth=0; en=0; }
      $1=="CSV" && $2=="client" {
        c++;
        auth += $4;
        en += $14;
      }
      END {
        if (c==0) {
          printf "%d,0,0,0,0\n", n;
        } else {
          printf "%d,%d,%.6f,%.6f,%.6f\n", n, c, c/n, auth/c, en/c;
        }
      }
    ' "${csv_file}" >> "${summary}"
  done

  plot_svg "${summary}" 4 "Auth time vs IoT (${mode})" "Authentication time (ms)" "${out_dir}/auth_time_vs_iot.svg"
  plot_svg "${summary}" 5 "Energy vs IoT (${mode})" "Energy (mJ)" "${out_dir}/energy_vs_iot.svg"

  echo "[DONE][${mode}] ${summary}"
}

plot_svg() {
  local summary="$1"
  local col_idx="$2"
  local title="$3"
  local ylabel="$4"
  local out_svg="$5"

  awk -F',' -v col="${col_idx}" -v t="${title}" -v yl="${ylabel}" -v out="${out_svg}" '
    function esc(s){gsub("&","&amp;",s); gsub("<","&lt;",s); gsub(">","&gt;",s); return s}
    BEGIN {
      w=1200; h=700; ml=110; mr=40; mt=50; mb=120;
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
      ypad=(maxy-miny)*0.08;
      minyp=miny-ypad; maxyp=maxy+ypad;

      x0=ml; y0=h-mb; x1=w-mr; y1=mt;
      print "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\""w"\" height=\""h"\">" > out;
      print "<rect width=\"100%\" height=\"100%\" fill=\"white\"/>" >> out;
      print "<text x=\""(w/2)"\" y=\"28\" text-anchor=\"middle\" font-size=\"22\" font-family=\"Arial\">" esc(t) "</text>" >> out;
      print "<line x1=\""x0"\" y1=\""y0"\" x2=\""x1"\" y2=\""y0"\" stroke=\"black\"/>" >> out;
      print "<line x1=\""x0"\" y1=\""y0"\" x2=\""x0"\" y2=\""y1"\" stroke=\"black\"/>" >> out;

      for(i=0;i<=6;i++) {
        v=miny + (maxy-miny)*i/6.0;
        py=y0 - (v-minyp)*(y0-y1)/(maxyp-minyp);
        print "<line x1=\""x0"\" y1=\""py"\" x2=\""x1"\" y2=\""py"\" stroke=\"#dddddd\"/>" >> out;
        print "<line x1=\""(x0-6)"\" y1=\""py"\" x2=\""x0"\" y2=\""py"\" stroke=\"black\"/>" >> out;
        printf "<text x=\"%g\" y=\"%g\" text-anchor=\"end\" font-size=\"12\" font-family=\"Arial\">%.2f</text>\n", (x0-10), (py+4), v >> out;
      }

      pts="";
      for(i=1;i<=n;i++) {
        px = x0 + (x[i]-minx)*(x1-x0)/(maxx-minx);
        py = y0 - (y[i]-minyp)*(y0-y1)/(maxyp-minyp);
        xp[i]=px; yp[i]=py;
        pts = pts sprintf("%.2f,%.2f ", px, py);
      }
      print "<polyline fill=\"none\" stroke=\"#1d3557\" stroke-width=\"3\" points=\""pts"\"/>" >> out;

      for(i=1;i<=n;i++) {
        print "<circle cx=\""xp[i]"\" cy=\""yp[i]"\" r=\"4\" fill=\"#e63946\"/>" >> out;
        printf "<text x=\"%g\" y=\"%g\" text-anchor=\"middle\" font-size=\"10\" font-family=\"Arial\">%.2f</text>\n", xp[i], (yp[i]-8), y[i] >> out;
        print "<line x1=\""xp[i]"\" y1=\""y0"\" x2=\""xp[i]"\" y2=\""(y0+6)"\" stroke=\"black\"/>" >> out;
        print "<text x=\""xp[i]"\" y=\""(y0+20)"\" text-anchor=\"middle\" font-size=\"11\" font-family=\"Arial\">" x[i] "</text>" >> out;
      }

      print "<text x=\""(w/2)"\" y=\""(h-20)"\" text-anchor=\"middle\" font-size=\"14\" font-family=\"Arial\">Number of IoT nodes</text>" >> out;
      print "<text x=\"30\" y=\""(h/2)"\" transform=\"rotate(-90 30,"(h/2)")\" text-anchor=\"middle\" font-size=\"14\" font-family=\"Arial\">" esc(yl) "</text>" >> out;
      print "</svg>" >> out;
    }
  ' "${summary}"
}

aggregate_mode "mock" "true"
aggregate_mode "ecc" "false"

echo "[DONE] Comparison output: ${OUT_BASE}"
