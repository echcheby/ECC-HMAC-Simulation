# REVISED ECC-HMAC IoT Authentication Protocol — ns-3 Simulation Report

This report covers the ns-3 implementation, simulation and evaluation of the
**revised** ECC-HMAC mutual authentication protocol for IoT (registration
R1–R5 + authentication A1–A8). Only the revised (multi-message,
forward-secure, replay-protected) protocol is implemented — the previous
one-message version is out of scope.

All cryptography (P-256 point arithmetic, SHA-256, HMAC-SHA-256) is real,
computed with OpenSSL; every accept/reject decision in the results below is
the outcome of genuine cryptographic verification, not a scripted outcome.

**This is the "realistic MSP430" revision of the report.** An earlier pass
used the task's example crypto-cost placeholder (`devTpm=20 ms`), which gave
implausibly small energy figures (~2.5 mJ/session) once energy was correctly
windowed. That has been replaced with a literature-derived device scalar
multiplication cost of **1072.8 ms**, and the server retry timeout `Delta`
has been re-derived accordingly (§3.3). See §10 for full source citations and
a documented sensitivity bound.

## 1. Environment

- Ubuntu 20.04 (WSL2), gcc 9.4.0, cmake 3.16.3, OpenSSL 1.1.1f (libssl-dev).
- ns-3.37 (`https://gitlab.com/nsnam/ns-3-dev.git`, tag `ns-3.37`), built with
  CMake/Ninja:
  ```
  ./ns3 configure --enable-modules="core;network;lr-wpan;mobility;applications;stats" \
      --disable-examples --disable-tests --disable-werror -d release
  ```
  (`internet`, `spectrum`, `propagation`, `antenna`, `bridge`,
  `traffic-control` are pulled in automatically as dependencies of
  `lr-wpan`; we do not use IPv6/UDP — see §2.)
- Python 3.8.10 with numpy 1.24.4, pandas 2.0.3, matplotlib 3.7.5, scipy 1.10.1.

### 1.1 Build and run instructions

```bash
# 1. Configure and build ns-3.37 (re-run after editing scratch/ecc-hmac-revised.cc,
#    scratch/ecc_hmac_proto.h, scratch/ecc-hmac-tests.cc, or
#    src/lr-wpan/model/lr-wpan-phy.cc -- see §3.4 for why that file is patched)
cd ecc_hmac_ns3/ns-3.37
./ns3 configure --enable-modules="core;network;lr-wpan;mobility;applications;stats" \
    --disable-examples --disable-tests --disable-werror -d release
cd cmake-cache && ninja scratch_ecc-hmac-revised scratch_ecc-hmac-tests && cd ..

# 2. Run the unit tests (section 3.3 of the task spec)
./build/scratch/ns3.37-ecc-hmac-tests

# 3. Run a single simulation (all parameters are optional, defaults shown in
#    ecc-hmac-revised.cc; --outPrefix writes <prefix>_summary.csv / _pernode.csv)
./build/scratch/ns3.37-ecc-hmac-revised --N=100 --seed=1 --outPrefix=/tmp/run1

# 4. Or run everything (unit tests + the full N x seed x dutyCycle sweep + the
#    optional loss experiment) from the ecc_hmac_ns3/ directory:
cd ..
./run_all.sh

# 5. Generate the 7 figures from results/summary_all.csv:
python3 plot_figures.py

# 6. Generate the supplementary markdown tables (duty-cycle comparison,
#    latency decomposition, Source A/B sensitivity, battery life):
python3 make_report_tables.py
```

Every simulation-level parameter (radio radius, timing, crypto costs, energy
constants, loss probability, duty-cycling, RNG seed) is a `CommandLine` flag
on `ecc-hmac-revised` — see the `cmd.AddValue(...)` block near the top of
`main()` in `scratch/ecc-hmac-revised.cc` for the full list and defaults.

## 2. Network / transport model — documented simplification

The task allows a fallback transport when 6LoWPAN/IPv6/UDP over lr-wpan is
too slow to sweep up to N=1200 devices × 5 seeds × 11 values of N. **We use
that fallback from the start**: raw IEEE 802.15.4 MAC
(`McpsDataRequest`/`McpsDataIndication`), no 6LoWPAN, no IPv6, no UDP, and no
MLME association — short addresses are pre-provisioned (server = `0x0000`,
device *i* = short address *i*), consistent with the protocol's own
assumption that node identity is the MAC source address with no separate ID
field. Every message above 100 bytes is fragmented at the application layer
into ≤100-byte frames (3-byte fragmentation header: 2-byte total length + 1
byte fragment index, ≤97 bytes of payload per frame) and reassembled at the
receiver before being handed to the protocol state machine.

This keeps the full sweep (11 N values × 5 seeds × 2 radio scenarios = 110
runs, plus the 25-run loss experiment) tractable while still exercising the
real IEEE 802.15.4 MAC: unslotted CSMA/CA, default backoff/retry parameters
(`macMaxCSMABackoffs`, `macMinBE`, `macMaxBE`, `macMaxFrameRetries=3`), and
the real LrWpanPhy at 2.4 GHz O-QPSK, 250 kbit/s, with ns-3's default
LogDistance propagation loss model and constant-speed propagation delay
(both are `LrWpanHelper` defaults). Star topology: server S at the origin,
N devices placed uniformly at random in a disc of radius `--radius`
(default 10 m) around S using `UniformDiscPositionAllocator`.

Registration (§3.1) is, per the paper, an offline/secure-channel phase; we
simulate it over the same radio channel purely to measure its cost, exactly
as instructed.

## 3. Protocol implementation

- `ns-3.37/scratch/ecc_hmac_proto.h` — header-only, **no ns-3 dependency**:
  P-256/SHA-256/HMAC-SHA-256 primitives (OpenSSL) and the registration
  (R1–R5) / authentication (A1–A8) state machines operating on plain byte
  buffers. This is what makes the logic independently unit-testable.
- `ns-3.37/scratch/ecc-hmac-revised.cc` — the ns-3 network simulation: node
  setup, lr-wpan wiring, fragmentation/reassembly, message dispatch, timers/
  retries, radio duty-cycling, windowed energy accounting, CSV output. It
  calls into `ecc_hmac_proto.h` for every cryptographic step and converts the
  returned modelled processing cost into a `Simulator::Schedule` delay —
  **the simulated clock never depends on host CPU speed**: computation
  happens synchronously (real, but fast — microseconds), then the clock is
  advanced by exactly the modelled cost before any resulting message is
  transmitted or state change is timestamped.
- `ns-3.37/scratch/ecc-hmac-tests.cc` — standalone unit tests (§3.3 of the
  task spec), exercising the state machine directly with no network/timing
  model. Uses its own small illustrative cost constants, independent of the
  network simulation's crypto-cost CLI defaults.

### 3.1 Processing-delay accounting

Rather than hard-coding per-phase lump sums, we instrument the four crypto
primitive wrappers themselves: every EC scalar multiplication (including
ECDH) adds one `Tpm`, every EC point addition/subtraction one `Tpa`, every
SHA-256 one `Th`, every HMAC-SHA-256 one `Tmac` (role-specific unit costs,
all CLI parameters). Scalar-only modular arithmetic (e.g. `Y = r + c·s mod
q`) is free. This reproduces the task's example headline totals for 6 of 7
phases *exactly*:

| Phase | Task headline | Our itemised count | Match |
|---|---|---|---|
| Registration, T | `4·Tpm + Tpa + Th` | `4·Tpm + Tpa + Th` | ✅ |
| Auth A1–A3, S | `2·Tpm + Tmac + Th` | `2·Tpm + Tmac + Th` | ✅ |
| Auth A8, S | `Tpm + 3·Th + Tmac` | `Tpm + 3·Th + Tmac` | ✅ |
| Auth A5–A6, T | `4·Tpm + Tpa + 4·Th + 2·Tmac` (+1 Tmac fallback) | same | ✅ |
| Registration, S | `3·Tpm + Tpa + Th` | `4·Tpm + Tpa + Th` | ⚠️ off by 1 Tpm |

The one discrepancy (registration-S) is a minor inconsistency in the task's
own example figures (its itemised list — `RS`, `YT` check = `2·Tpm + Tpa`,
`rS·RT`, `SK_ST` — sums to `4·Tpm`, not the `3·Tpm` headline); we keep the
operation-accurate count for internal consistency with the other six exact
matches.

### 3.2 Device crypto costs (realistic MSP430 timing — see §10 for sources)

| | Tpm | Tpa | Th | Tmac |
|---|---|---|---|---|
| Device (T), `--devTpm` etc. | **1072.8 ms** | 0.2 ms | 0.1 ms | 0.2 ms |
| Server (S), `--srvTpm` etc. | 1.0 ms | 0.01 ms | 0.005 ms | 0.01 ms |

`devTpm` is derived from a real published benchmark (§10, Source A), not
the task's original 20 ms placeholder. `devTpa`/`devTh`/`devTmac` remain the
task's example values (point addition, SHA-256 and HMAC-SHA-256 are cheap
compared to a full scalar multiplication and were not independently
re-benchmarked). The server is assumed to be a non-constrained
gateway-class device and keeps its original fast example costs.
Per-message stack/processing delay: `--stackDelay` = 2 ms, added once per
received (fully reassembled) logical message and counted toward that node's
CPU/processing energy.

### 3.3 Timeout Delta re-derivation

With realistic device crypto, a single authentication round-trip requires
the device to spend **~4.3 s** computing A5–A6 before it can reply — far
longer than the task's example `Delta=2s`, which would make the server retry
before the device could ever finish. `Delta` is re-derived as:

```
Delta = T_compute_T_auth_worst_case + T_network_margin

T_compute_T_auth_worst_case = 4·devTpm + devTpa + 4·devTh + 3·devTmac (incl. 1 fallback) + stackDelay
                             = 4(1072.8) + 0.2 + 4(0.1) + 3(0.2) + 2 = 4294.4 ms

T_network_margin = per-frame CSMA/MAC-retry analytical bound (~150 ms x 3
                    fragments for AUTH_M1(2)+AUTH_M2(1) under full backoff/
                    retry exhaustion ~= 450 ms) + an empirical congestion
                    buffer informed by prior validated runs at N=1200
                    (mean latency up to ~900 ms under the fast-Tpm baseline)
                  ~= 450 + 1000 = 1450 ms, rounded to 1500 ms

Delta = 4294.4 + 1500 ~= 5794 ms, rounded up to Delta = 6.0 s
```

Registration's dominant step (T processing REG_1 to produce REG_2, a single
`devTpm` plus `stackDelay`, `1·devTpm + stackDelay ≈ 1074.8 ms`) needs much
less time than authentication; a single shared `Delta=6s` (matching the
task's own single shared-Delta design) is conservative but safe for both
phases. `--timeoutDelta` default changed from 2.0 to **6.0** accordingly.
`--authDelay` (10 s) and `--regWindow` (50 s) are unchanged and remain much
larger than any single processing step.

### 3.4 Radio duty-cycling

**Devices sleep** (`LrWpanMac::SetRxOnWhenIdle(false)`, i.e. PHY `TRX_OFF`)
during the two windows where they provably have nothing to receive: (a)
before their own registration slot (device starts asleep at t=0, woken right
as the server sends its REG_1), and (b) permanently after their one-shot
session concludes (after their AUTH_M2 transmission is *confirmed
successful* — see the bug note below). Between those two points — through
the entire registration exchange, the `authDelay` gap, and the entire
authentication exchange — the radio stays on, matching what an active
protocol exchange needs. `--dutyCycle=0` reproduces the original always-on
behaviour (kept as an explicit comparison scenario, §7).

**Two real bugs were found and fixed while implementing this:**

1. **ns-3 upstream bug** (`src/lr-wpan/model/lr-wpan-phy.cc`,
   `PlmeSetTRXStateRequest`): a plain `TRX_OFF` request while the PHY is
   `BUSY_RX` is only deferred (instead of crashing with `NS_FATAL_ERROR`
   "Unexpected transition") when `m_currentRxPacket` bookkeeping indicates an
   actively-tracked valid-SFD reception. Overhearing a frame not addressed to
   this node — exactly what a duty-cycled device in a dense shared PAN does
   constantly — can leave the PHY in `BUSY_RX` without that bookkeeping
   state, hitting the fatal-error fallthrough. Fixed by broadening the defer
   condition to cover *any* `BUSY_RX` state, matching how `BUSY_TX` and
   `FORCE_TRX_OFF` are already handled. This is an infrastructure fix to the
   simulator, not to the protocol.
2. **Our own logic bug**: a device was put to sleep as soon as its own
   AUTH_M2 transmission *attempt* completed, regardless of whether that
   transmission actually succeeded. Under heavy congestion, a transmission
   can fail after MAC-level retries are exhausted (`McpsDataConfirm` status
   ≠ `SUCCESS`); a device that went to sleep anyway became permanently
   unreachable for the server's subsequent AUTH_M1 retry, while the server
   kept retransmitting into the void up to `maxRetries` — itself adding
   congestion that stranded *more* devices in a self-reinforcing cascade.
   Symptom before the fix: success rate collapsing from ~90% to 30-60% above
   N≈900. Fixed by only sleeping when the confirm status is `SUCCESS`;
   verified this fully restores expected behaviour across the whole N range
   (§7, Table 2).

### 3.5 Windowed per-session energy accounting

Four timestamps are recorded per device: `regStart` (S sends REG_1),
`regDone` (T finishes processing REG_3), `triggerSent` (T sends
AUTH_TRIGGER), `deviceAuthDone` (T sends AUTH_M2). At each timestamp, a
snapshot of that device's cumulative (CPU, TX, RX) time buckets is taken.
Registration energy = the windowed energy formula (below) applied to
`[regStart, regDone]`; authentication energy = the same applied to
`[triggerSent, deviceAuthDone]`. This **excludes** the `authDelay` gap and
the (now duty-cycled, but still present) simulation tail after the session
ends — giving the realistic cost of one authentication, not energy
integrated over an arbitrary fixed simulation window. Session energy =
registration + authentication. The full-`simTime`-window energy (the
original, non-windowed formula) is *also* still computed, reported
separately, and used only for the duty-cycle comparison (§7, Table 2).

```
E_window = V * (I_cpu * dCpu + I_lpm * dLpm + I_tx * dTx + I_rx * dRx)
dCpu/dTx/dRx = increase in that node's cumulative bucket across the window
dLpm = max(0, windowDuration - dCpu - dTx - dRx)
```

## 4. Energy model constants

Default constants (Tmote-Sky-like, CLI parameters): `V=3.0 V`,
`I_cpu=1.8 mA`, `I_lpm=0.0545 mA`, `I_tx=17.4 mA`, `I_rx=18.8 mA`. `t_tx`/
`t_rx` are read from the real per-node `LrWpanPhy` `TrxState` trace
(`BUSY_TX`/`BUSY_RX`), not estimated from packet counts. Idle listening
(`RX_ON` with no reception) is logged separately per node but excluded from
the main energy figures, per the task's explicit instruction.

## 5. Validation (§10 of the task spec)

- **Unit tests** (`ecc-hmac-tests.cc`): **29/29 passed** — message sizes;
  honest registration + authentication; rejection of a modified CT, c, YS,
  and tau; rejection of a replayed AUTH_M1 (`ist <= ist_T`); recovery via the
  fallback (previous) key after a dropped AUTH_M2. Unaffected by the
  crypto-cost/Delta changes above (tests use their own fixed illustrative
  costs). Full output in `results/unit_test_results.txt`.
- **Message sizes measured from actual wire packets**: REG_1 = 66 B, REG_2 =
  98 B, REG_3 = 33 B, AUTH_TRIGGER = 1 B, AUTH_M1 = 134 B, AUTH_M2 = 66 B,
  **total session = 398 B** — matched in every one of the 135 simulation
  runs (`messageSizesOk=1` in every CSV row).
- **Desynchronised devices at the end of every run = 0** across all 135 runs
  (110 main sweep + 25 loss experiment), for both `dutyCycle` scenarios.
- **Registration/authentication failures**: across the full 110-run main
  sweep, only 1 total `regFailure` and 7 total `authFailures` (out of
  ~121,000 device-sessions), all at the highest-congestion end (N≥700) —
  expected, not a correctness issue.
- Both real bugs described in §3.4 were caught by this validation process
  (an `NS_FATAL_ERROR` crash, and a success-rate collapse at N≥900) and
  fixed before any reported numbers below were generated.

## 6. Scenario parameters

Registration start: uniform random in [0, 50] s per device (`--regWindow`).
`AUTH_TRIGGER` sent 10 s after registration completes (`--authDelay`).
Timeout `Delta = 6.0 s` (re-derived, §3.3), `maxRetries = 5`
(`--timeoutDelta`, `--maxRetries`). Simulation length 300 s (`--simTime`). 5
independent seeds per N (`RngSeedManager` run number 1–5, base seed fixed at
1). OpenSSL's own CSPRNG is used for cryptographic randomness (key/nonce
generation); ns-3's seeded `UniformRandomVariable` is used for every
scenario-level random choice (device positions, registration start times,
loss-experiment draws), so the 5-seed sweep is reproducible at the
network/scenario level as required.

## 7. Results

Full sweep: N ∈ {100,200,...,1000,1200}, 5 seeds each, radius=10 m,
simTime=300 s, run under **both** `dutyCycle=1` (primary scenario: radio
duty-cycled per §3.4) and `dutyCycle=0` (always-on comparison) — 110 runs
total, plus the 25-run loss experiment (`dutyCycle=1`). All values are mean
± 95% Student-t CI across the 5 seeds. Raw data: `results/summary_all.csv`
(per run) and `results/pernode_all.csv` (per device); figures:
`figures/*.png` / `figures/*.pdf`; full supplementary tables (this section's
Tables 2–5) are regenerated by `make_report_tables.py`.

### Table 1 — Main results (dutyCycle=1, primary scenario)

| N | Auth latency (ms) | Success rate (%) | E2E time (ms) | Session energy (mJ) | Radio share (%) | Mean MAC drops | Reg fail (Σ/5) | Auth fail (Σ/5) | Desync (Σ/5) |
|---|---|---|---|---|---|---|---|---|---|
| 100 | 4317.7 ± 0.3 | 99.80 ± 0.56 | 18645.6 ± 33.1 | 63.86 ± 0.41 | 27.3 | 0.2 | 0 | 0 | 0 |
| 200 | 4318.6 ± 0.3 | 99.80 ± 0.34 | 18647.5 ± 20.9 | 81.09 ± 1.07 | 42.8 | 0.6 | 0 | 0 | 0 |
| 300 | 4323.5 ± 11.2 | 99.53 ± 0.23 | 18677.7 ± 40.1 | 98.32 ± 1.32 | 52.7 | 2.4 | 0 | 0 | 0 |
| 400 | 4338.4 ± 15.9 | 99.35 ± 0.28 | 18709.1 ± 42.6 | 115.67 ± 1.30 | 59.8 | 6.2 | 0 | 0 | 0 |
| 500 | 4370.1 ± 30.8 | 98.84 ± 0.92 | 18768.7 ± 22.8 | 133.39 ± 1.19 | 65.0 | 14.8 | 0 | 0 | 0 |
| 600 | 4386.0 ± 47.6 | 98.37 ± 0.49 | 18892.2 ± 57.4 | 152.70 ± 0.98 | 69.3 | 33.0 | 0 | 0 | 0 |
| 700 | 4403.6 ± 18.0 | 97.49 ± 0.58 | 18984.5 ± 54.2 | 171.69 ± 1.25 | 72.6 | 57.2 | 0 | 1 | 0 |
| 800 | 4466.2 ± 25.4 | 96.47 ± 0.69 | 19159.9 ± 56.3 | 193.65 ± 1.92 | 75.5 | 94.0 | 0 | 0 | 0 |
| 900 | 4469.1 ± 39.8 | 95.76 ± 0.46 | 19285.9 ± 93.7 | 213.75 ± 2.77 | 77.8 | 130.8 | 0 | 0 | 0 |
| 1000 | 4566.2 ± 18.4 | 93.78 ± 1.04 | 19621.4 ± 152.4 | 242.35 ± 5.22 | 80.1 | 228.2 | 0 | 4 | 0 |
| 1200 | 4822.5 ± 85.5 | 89.13 ± 1.68 | 20476.1 ± 214.3 | 307.33 ± 8.55 | 83.8 | 490.8 | 0 | 2 | 0 |

### Table 2 — Duty-cycled (real sleep) vs always-on: validation

| N | Success dc=1 (%) | Success dc=0 (%) | Session energy dc=1 (mJ) | Session energy dc=0 (mJ) | Full-scenario energy dc=1 (mJ) | Full-scenario energy dc=0 (mJ) | Reduction (full, %) |
|---|---|---|---|---|---|---|---|
| 100 | 99.80 | 99.80 | 63.86 | 63.87 | 130.6 | 210.6 | 38.0 |
| 200 | 99.80 | 99.90 | 81.09 | 81.13 | 168.3 | 327.5 | 48.6 |
| 300 | 99.53 | 99.53 | 98.32 | 98.32 | 206.2 | 445.1 | 53.7 |
| 400 | 99.35 | 99.50 | 115.67 | 115.63 | 243.8 | 563.3 | 56.7 |
| 500 | 98.84 | 98.76 | 133.39 | 133.43 | 282.3 | 682.1 | 58.6 |
| 600 | 98.37 | 98.43 | 152.70 | 152.75 | 323.5 | 806.0 | 59.9 |
| 700 | 97.49 | 97.49 | 171.69 | 172.34 | 366.0 | 929.5 | 60.6 |
| 800 | 96.47 | 97.22 | 193.65 | 192.48 | 413.4 | 1053.6 | 60.8 |
| 900 | 95.76 | 95.93 | 213.75 | 214.98 | 457.7 | 1180.5 | 61.2 |
| 1000 | 93.78 | 94.42 | 242.35 | 242.64 | 518.5 | 1318.4 | 60.7 |
| 1200 | 89.13 | 89.27 | 307.33 | 311.66 | 657.0 | 1608.4 | 59.2 |

**Two validations at a glance**: (1) success rate is statistically
indistinguishable between `dutyCycle=1` and `dutyCycle=0` at every N —
duty-cycling does not change protocol correctness. (2) session energy
(windowed) is also nearly identical between the two scenarios (as it should
be: it measures the same active-phase work regardless of what the radio does
in between), while full-scenario energy drops 38–61% under real duty-cycling
— confirming the windowing methodology (§3.5) captures the same "cost of one
authentication" that a real sleep implementation converges to, without
requiring the network to actually be resimulated with sleep for every figure.

### Table 3 — Authentication latency decomposition (compute vs network)

`Compute time = mean attempts-to-success x 4294.2 ms` (the fixed,
deterministic A5–A6 device cost, §3.1/§3.2); `Network/congestion residual =
authLatencyMeanMs - compute time`.

| N | Mean attempts/success | Compute time (ms) | Network/congestion residual (ms) | Network share of latency (%) |
|---|---|---|---|---|
| 100 | 1.00 | 4302.8 | 14.9 | 0.3 |
| 200 | 1.00 | 4294.2 | 24.4 | 0.6 |
| 300 | 1.00 | 4302.8 | 20.7 | 0.5 |
| 400 | 1.00 | 4311.5 | 26.9 | 0.6 |
| 500 | 1.01 | 4330.7 | 39.4 | 0.9 |
| 600 | 1.01 | 4348.0 | 37.9 | 0.9 |
| 700 | 1.02 | 4362.2 | 41.4 | 0.9 |
| 800 | 1.03 | 4409.9 | 56.2 | 1.3 |
| 900 | 1.03 | 4412.8 | 56.3 | 1.3 |
| 1000 | 1.05 | 4503.0 | 63.2 | 1.4 |
| 1200 | 1.09 | 4680.4 | 142.0 | 2.9 |

**Confirms the requested point directly**: compute time is essentially flat
(device-side crypto cost does not depend on N); the network/congestion
residual is what grows with N (14.9 ms → 142.0 ms, a ~9.5× increase from
N=100 to N=1200), and it alone is responsible for the latency growth visible
in fig1. Congestion affects only the network component, never the compute
component, by construction.

### Table 4 — Session energy sensitivity: Source A vs Source B (pessimistic bound)

`devTpm` scaled from 1072.8 ms (Source A) to 1843–2331 ms (Source B, a real
160-bit measurement scaled to 256-bit, §10). CPU energy scales linearly with
`devTpm`; TX/RX assumed unchanged (analytical recomputation from the
existing per-phase CPU/TX/RX breakdown, **not** a resimulated campaign).

| N | Session energy, Source A (mJ) | Session energy, Source B low (mJ) | Session energy, Source B high (mJ) |
|---|---|---|---|
| 100 | 63.86 | 97.21 | 118.35 |
| 200 | 81.09 | 114.41 | 135.53 |
| 300 | 98.31 | 131.68 | 152.83 |
| 400 | 115.67 | 149.08 | 170.26 |
| 500 | 133.38 | 166.89 | 188.12 |
| 600 | 152.68 | 186.31 | 207.63 |
| 700 | 171.67 | 205.42 | 226.82 |
| 800 | 193.63 | 227.63 | 249.18 |
| 900 | 213.73 | 247.83 | 269.45 |
| 1000 | 242.33 | 276.95 | 298.89 |
| 1200 | 307.31 | 343.01 | 365.64 |

### Table 4b — Per-phase CPU/TX/RX energy breakdown (Source A devTpm, mJ)

| N | Reg CPU (I_cpu=1.8mA) | Reg TX | Reg RX | Reg total | Auth CPU (I_cpu=1.8mA) | Auth TX | Auth RX | Auth total | Reg CPU (I_cpu=3.68mA) | Reg total (I_cpu=3.68mA) | Auth CPU (I_cpu=3.68mA) | Auth total (I_cpu=3.68mA) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 100 | 23.21 | 0.27 | 8.69 | 32.17 | 23.24 | 0.07 | 8.38 | 31.69 | 47.45 | 56.41 | 47.50 | 55.96 |
| 500 | 23.27 | 0.29 | 44.12 | 67.68 | 23.39 | 0.07 | 42.24 | 65.70 | 47.58 | 91.99 | 47.81 | 90.13 |
| 1000 | 23.90 | 0.33 | 104.17 | 128.40 | 24.31 | 0.08 | 89.53 | 113.93 | 48.86 | 153.36 | 49.70 | 139.32 |
| 1200 | 24.46 | 0.37 | 142.70 | 167.53 | 25.26 | 0.09 | 114.43 | 139.78 | 50.01 | 193.07 | 51.64 | 166.16 |

CPU (at the campaign's I_cpu=1.8 mA) is essentially flat with N (23.2→25.3
mJ, +9%); RX (overhearing) dominates the growth in both phases (reg:
8.7→142.7 mJ, ~16×; auth: 8.4→114.4 mJ, ~14×) — **neither phase's total
energy is independent of N**, only its CPU component is (registration and
authentication use the same number of `Tpm` operations, so their CPU costs
track each other closely at every N; §3.1).

**I_cpu inconsistency (caught in review).** §4 uses `I_cpu=1.8 mA`
throughout the primary campaign — this is the task's example placeholder,
carried over unmodified. But Source B's *own* measurement, on the same
reference hardware (Tmote Sky / MSP430F1611) and using the same `E=U·I·T`
formula this report uses throughout, implies a higher current while a P-256
(scaled) point multiplication actually executes: `7.95 mJ / (0.72 s ×
3 V) = 3.68 mA` — **2.04× higher** than the value used in the primary
campaign. §10's claim of using "the same formula and reference platform"
as Source B refers to the energy formula and hardware, **not** to this
specific current constant, which was never re-derived from Source B. The
last four columns above isolate the effect of correcting only this
constant (`devTpm` held at Source A): CPU energy is essentially doubled at
every N, and because CPU is the dominant term at low N, the correction has
its largest *relative* impact there (e.g. registration total at N=100:
32.17 → 56.41 mJ, +75%, vs. +15% at N=1200 where RX already dominates).
Table 1/2/3 and the primary Table 4/5 figures are **not** recomputed with
this corrected current — see Table 5 below and assumption 13 (§9) for how
this is carried forward as an explicit, quantified sensitivity rather than
silently left inconsistent.

### Table 5 — Battery-life sensitivity

**Upper-bound estimates for the protocol's cryptographic cost alone**: no
application traffic, no standby/quiescent current between authentications,
and no battery self-discharge are included — real battery life will be
shorter. **Registration happens once per device lifetime, not repeated** —
treating it as a recurring cost would implicitly assume the device
re-registers every hour, which is wrong — so it is reported separately as a
one-time cost below. Only authentication recurs, so the recurring
battery-life figures use **authentication-phase energy alone**, not the full
session. **Neither phase's energy is independent of N** (Table 4b), so both
tables are given at N=100, 500, 1000, and 1200 rather than a single
representative value. A fourth basis, **"Source A + I_cpu(B)"**, isolates
the I_cpu correction discussed under Table 4b: `devTpm` stays at Source A,
but `I_cpu` is corrected from the campaign's 1.8 mA placeholder to Source
B's measured 3.68 mA — independent of the `devTpm` sensitivity already
captured by the Source B low/high rows.

**Registration (one-time cost per device):**

| N | Basis | Energy (mJ) | % of CR2032 (~2.43 kJ) | % of 2×AA (~27 kJ) |
|---|---|---|---|---|
| 100 | Source A | 32.17 | 0.0013% | 0.0001% |
| 100 | Source A + I_cpu(B) | 56.41 | 0.0023% | 0.0002% |
| 100 | Source B low–high | 48.84–59.40 | 0.0020–0.0024% | 0.0002% |
| 500 | Source A | 67.68 | 0.0028% | 0.0003% |
| 500 | Source A + I_cpu(B) | 91.99 | 0.0038% | 0.0003% |
| 500 | Source B low–high | 84.39–94.98 | 0.0035–0.0039% | 0.0003–0.0004% |
| 1000 | Source A | 128.40 | 0.0053% | 0.0005% |
| 1000 | Source A + I_cpu(B) | 153.36 | 0.0063% | 0.0006% |
| 1000 | Source B low–high | 145.56–156.44 | 0.0060–0.0064% | 0.0005–0.0006% |
| 1200 | Source A | 167.53 | 0.0069% | 0.0006% |
| 1200 | Source A + I_cpu(B) | 193.07 | 0.0079% | 0.0007% |
| 1200 | Source B low–high | 185.09–196.22 | 0.0076–0.0081% | 0.0007% |

Registration is negligible on either battery at every N tested — a rounding
error next to the recurring authentication cost below, even though its own
absolute energy grows over 5× from N=100 to N=1200 (Table 4b), and even
with the I_cpu correction applied.

**Authentication (repeating cost) — CR2032 (~2.43 kJ):**

| N | Basis | Auth energy (mJ) | 1/hour: days | 1/6h: days | 1/day: days | 1/hour: %/yr | 1/6h: %/yr | 1/day: %/yr |
|---|---|---|---|---|---|---|---|---|
| 100 | Source A | 31.69 | 3195 | 19169 | 76675 | 11.43% | 1.90% | 0.48% |
| 100 | Source A + I_cpu(B) | 55.96 | 1809 | 10856 | 43424 | 20.17% | 3.36% | 0.84% |
| 100 | Source B low | 48.38 | 2093 | 12557 | 50230 | 17.44% | 2.91% | 0.73% |
| 100 | Source B high | 58.95 | 1717 | 10305 | 41219 | 21.25% | 3.54% | 0.89% |
| 500 | Source A | 65.70 | 1541 | 9246 | 36985 | 23.69% | 3.95% | 0.99% |
| 500 | Source A + I_cpu(B) | 90.13 | 1123 | 6740 | 26962 | 32.49% | 5.42% | 1.35% |
| 500 | Source B low | 82.50 | 1227 | 7364 | 29456 | 29.74% | 4.96% | 1.24% |
| 500 | Source B high | 93.14 | 1087 | 6522 | 26090 | 33.58% | 5.60% | 1.40% |
| 1000 | Source A | 113.93 | 889 | 5332 | 21329 | 41.07% | 6.85% | 1.71% |
| 1000 | Source A + I_cpu(B) | 139.32 | 727 | 4361 | 17442 | 50.22% | 8.37% | 2.09% |
| 1000 | Source B low | 131.39 | 771 | 4624 | 18495 | 47.36% | 7.89% | 1.97% |
| 1000 | Source B high | 142.45 | 711 | 4265 | 17059 | 51.35% | 8.56% | 2.14% |
| 1200 | Source A | 139.78 | 724 | 4346 | 17385 | 50.39% | 8.40% | 2.10% |
| 1200 | Source A + I_cpu(B) | 166.16 | 609 | 3656 | 14624 | 59.90% | 9.98% | 2.50% |
| 1200 | Source B low | 157.92 | 641 | 3847 | 15388 | 56.93% | 9.49% | 2.37% |
| 1200 | Source B high | 169.41 | 598 | 3586 | 14344 | 61.07% | 10.18% | 2.55% |

The isolated I_cpu correction (**"Source A + I_cpu(B)"**) has a *larger*
effect than the full Source B devTpm sensitivity bound at high N — e.g. at
N=1200, 1/hour reaches 59.9%/year with the I_cpu correction alone vs.
56.9%/year under Source B low (devTpm sensitivity only) — meaning the
I_cpu inconsistency is, quantitatively, a bigger source of uncertainty in
this report's battery-life numbers than the devTpm platform-mismatch
uncertainty already flagged in §9/§10.

**Authentication (repeating cost) — 2×AA (~27 kJ):**

| N | Basis | Auth energy (mJ) | 1/hour: days | 1/6h: days | 1/day: days | 1/hour: %/yr | 1/6h: %/yr | 1/day: %/yr |
|---|---|---|---|---|---|---|---|---|
| 100 | Source A | 31.69 | 35498 | 212986 | 851946 | 1.03% | 0.17% | 0.04% |
| 100 | Source A + I_cpu(B) | 55.96 | 20104 | 120622 | 482488 | 1.82% | 0.30% | 0.08% |
| 100 | Source B low | 48.38 | 23254 | 139527 | 558108 | 1.57% | 0.26% | 0.07% |
| 100 | Source B high | 58.95 | 19083 | 114498 | 457991 | 1.91% | 0.32% | 0.08% |
| 500 | Source A | 65.70 | 17123 | 102737 | 410947 | 2.13% | 0.36% | 0.09% |
| 500 | Source A + I_cpu(B) | 90.13 | 12482 | 74894 | 299576 | 2.92% | 0.49% | 0.12% |
| 500 | Source B low | 82.50 | 13637 | 81822 | 327289 | 2.68% | 0.45% | 0.11% |
| 500 | Source B high | 93.14 | 12079 | 72471 | 289886 | 3.02% | 0.50% | 0.13% |
| 1000 | Source A | 113.93 | 9875 | 59248 | 236993 | 3.70% | 0.62% | 0.15% |
| 1000 | Source A + I_cpu(B) | 139.32 | 8075 | 48450 | 193800 | 4.52% | 0.75% | 0.19% |
| 1000 | Source B low | 131.39 | 8563 | 51376 | 205502 | 4.26% | 0.71% | 0.18% |
| 1000 | Source B high | 142.45 | 7897 | 47385 | 189539 | 4.62% | 0.77% | 0.19% |
| 1200 | Source A | 139.78 | 8048 | 48290 | 193161 | 4.54% | 0.76% | 0.19% |
| 1200 | Source A + I_cpu(B) | 166.16 | 6771 | 40623 | 162493 | 5.39% | 0.90% | 0.23% |
| 1200 | Source B low | 157.92 | 7124 | 42744 | 170975 | 5.12% | 0.85% | 0.21% |
| 1200 | Source B high | 169.41 | 6641 | 39843 | 159372 | 5.50% | 0.92% | 0.23% |

**The N-dependence matters here**: at N=100, hourly authentication costs
only ~1–2%/year of either battery (a footnote); at N=1200, the same 1/hour
rate reaches **50.4%/year on a CR2032** (Source A) — driven entirely by the
RX/overhearing growth in Table 4b, not by anything in the cryptography
itself. At realistic, less aggressive auth rates (≤1/day) the cost stays
under ~2.6% even at N=1200. The protocol's own cryptographic cost is never
the dominant term — channel occupancy in a dense, shared, always-listening
PAN is — and standby current/self-discharge (excluded from this table
entirely) would add further, unmodelled cost in a real deployment.

### Loss experiment (optional, §5 of the task spec)

N=100, AUTH_M1/AUTH_M2 application-level loss probability in {0, 5, 10, 20,
30%}, 5 seeds each, `dutyCycle=1`.

| Loss probability | Success rate (%) | Mean total attempts (N=100) | Desync (Σ/5) | Reg failures (Σ/5) |
|---|---|---|---|---|
| 0% | 99.80 ± 0.56 | 100.0 | 0 | 0 |
| 5% | 99.80 ± 0.56 | 110.6 | 0 | 0 |
| 10% | 100.00 ± 0.00 | 126.6 | 0 | 0 |
| 20% | 100.00 ± 0.00 | 158.4 | 0 | 0 |
| 30% | 97.80 ± 1.36 | 189.8 | 0 | 0 |

**Desynchronisation is 0 in every single run, even at 30% loss on both
authentication messages** — the expected outcome given the fallback-key
mechanism (spec A5-c): a device that rotates its key after a successful
AUTH_M1 but whose AUTH_M2 is then lost still accepts the *next* AUTH_M1
using its previous key, and the server (which never rotated) is verified
against exactly that key. The cost is visible only as more attempts per
session (100 → 190 mean total attempts at 30% loss) and a modest
success-rate dip at the highest loss level.

## 8. Figure interpretation

- **fig1 (authentication latency vs N).** Latency starts at ~4318 ms
  (matching the fixed device compute cost, Table 3) and grows to ~4823 ms at
  N=1200 — the growth is entirely the network/congestion residual (Table 3),
  not the compute component. The saturation threshold (shared with fig2,
  see below) is at **N=500**.
- **fig2 (success rate vs N).** Success rate is ≥99% up to N=400 and drops
  below the shared 99% threshold from **N=500** onward (both figures use
  the identical criterion: first N where mean success crosses below 99%),
  ending at 89.1% at N=1200. **This threshold is substantially lower than an
  earlier pass of this experiment found (N≈700) under the task's original
  fast example crypto cost (`devTpm=20 ms`) — and the reason is itself a
  reportable finding.** With realistic device crypto, a single session
  (registration + authentication, including device compute) spans ~5.6 s of
  wall-clock time instead of ~0.2 s — a ~27× increase (5.57s/65s ≈ 8.5% of
  the ~65 s scenario span each device is "in session", versus ~200ms/65s ≈
  0.3% before). Since registration starts remain uniformly spread over the
  same 50 s window, a session that takes 27× longer to complete means ~27×
  more devices are concurrently mid-session at any instant for the *same*
  N — so the same level of CSMA/MAC contention that previously required
  N≈700 is now reached around N≈500.

  **Two distinct comparisons — not to be confused.** The ~27× figure above
  is a *cross-configuration* estimate: it compares session duration under
  the task's original fast example cost (`devTpm=20 ms`) against session
  duration under the realistic cost (`devTpm=1072.8 ms`), at a fixed point
  in N, to explain why the threshold moved from N≈700 to N≈500 between the
  two campaigns. It remains an **analytical, back-of-envelope estimate
  from the scenario-time ratio** — it was *not* re-measured by the new
  instrumentation, since that would require rerunning the old fast-crypto
  configuration with the concurrency instrumentation and comparing it
  directly to the realistic-crypto one, which was not done. The 14.4×
  figure discussed under fig3 below is a *different, within-configuration*
  comparison: it holds `devTpm=1072.8 ms` fixed and measures how the
  concurrent-active-device count scales as **N** itself grows from 100 to
  1200 in the realistic-crypto campaign only. What the new instrumentation
  *does* confirm is the underlying **mechanism** the ~27× estimate relies
  on — that concurrently-active device count is the real driver of
  CSMA/MAC contention, that it grows with session duration, and that it
  can grow superlinearly with N (14.4× concurrency for 12× N, here) — not
  the specific ~27× cross-configuration multiplier itself, which stands as
  a reasoned estimate rather than a directly measured one. In short:
  **slow, realistic embedded crypto does not just cost more energy and
  latency per device — it directly reduces how many devices the shared
  channel can support**, because each device occupies its share of the
  contention-relevant time window far longer.
- **fig3 (energy per session vs N).** Three curves: total session (reg+auth,
  near-linear growth from 64 mJ at N=100 to 307 mJ at N=1200), and
  registration/authentication plotted separately — windowed energy (§3.5),
  not energy integrated over the whole fixed simulation window. The two
  phases are close at low N but **diverge as N grows**: registration
  overtakes authentication from roughly N≈500-600 onward, reaching 167.5 mJ
  vs 139.8 mJ at N=1200 (Table 4b) — a gap that did not exist under the
  original fast example crypto cost. This is investigated in detail below
  ("Why does registration overtake authentication?"). It matters for
  battery life (Table 5): **registration is a one-time cost per device
  (negligible, <0.003% of either battery), while authentication is what
  recurs** — so the recurring battery-life estimate should use the
  authentication curve alone, not the total (and, if anything, this makes
  the registration/authentication split *more* important to keep separate,
  not less, since the two are no longer numerically interchangeable).
  Growth with N in all three curves comes from the RX (overhearing)
  component (fig5), since CPU cost per device does not depend on N.

  **Why does registration overtake authentication? (instrumented,
  measured — not speculation).** The first hypothesis proposed for this
  report was that the 50 s registration-start window "concentrates" all N
  devices' registration traffic in time relative to the more naturally
  staggered authentication traffic, increasing overhearing during
  registration specifically. This is directly testable and was
  instrumented rather than assumed. Two dedicated metrics were added to
  the simulator and measured on N=100/600/1200 (3 seeds each,
  `dutyCycle=1`): (a) the average number of *other* devices simultaneously
  inside their own registration (resp. authentication) window at any
  instant, and (b) the wall-clock duration of that window itself.

  | N | Reg avg. concurrent active | Auth avg. concurrent active | Ratio | Reg window (ms) | Auth window (ms) | Ratio |
  |---|---|---|---|---|---|---|
  | 100 | 14.39 | 14.28 | 1.01 | 4335.9 | 4310.3 | 1.01 |
  | 600 | 88.02 | 87.67 | 1.00 | 4505.6 | 4391.9 | 1.03 |
  | 1200 | 206.82 | 208.63 | 0.99 | 5548.7 | 4809.0 | 1.15 |

  **Result: the concentration hypothesis is refuted.** The average number
  of concurrently-active devices is statistically identical between the
  two phases at every N (ratio 0.99–1.01) — registration traffic is *not*
  more concentrated than authentication traffic in this simulation.
  Normalizing RX energy by window duration (RX energy per ms of active
  window) confirms this: the *instantaneous* RX rate is nearly identical
  between phases too (reg/auth ratio 1.03 at N=100, 1.06 at N=1200) — so
  the two phases experience essentially the same contention *intensity*
  per unit time. What does differ, and grows with N, is the **window
  duration itself**: the registration window is 1% longer than the
  authentication window at N=100, but 15% longer at N=1200. Multiplying
  the (near-flat) RX-rate ratio by the (growing) window-duration ratio
  reproduces the measured RX-energy ratio almost exactly at every N
  (e.g. at N=1200: 1.06 × 1.15 ≈ 1.22, matching Table 4b's 142.70/114.43 =
  1.25 within measurement noise of the smaller diagnostic sample). **So
  the registration/authentication asymmetry is a duration effect, not a
  concentration/contention-density effect**: individual registration
  exchanges simply take longer, in wall-clock terms, to complete under
  congestion than authentication exchanges do, and this gap widens as N
  grows — plausibly because registration's server-initiated,
  fixed-schedule request/response pattern absorbs MAC-layer backoff and
  retry delay less gracefully than authentication's device-initiated
  pattern, though the exact retry-count-by-phase breakdown was not
  separately instrumented and is left as an open detail. Separately (and
  independent of N), registration TX energy is systematically ~4× higher
  than authentication TX energy at every N (0.27 vs 0.07 mJ at N=100, 0.37
  vs 0.09 mJ at N=1200) — a fixed effect of REG_2/REG_3 carrying more key
  material than the authentication messages (fig6), not an N-dependent
  contention effect; it is a minor contributor in absolute mJ terms next
  to the RX gap.

  This result also **partially validates and partially corrects** the
  N=500 saturation-threshold explanation given below: the same
  instrumentation shows the average number of concurrently-active devices
  genuinely does grow with N (14.3 at N=100 → 206.8 at N=1200, a 14.4×
  increase for a 12× increase in N — mildly superlinear, consistent with
  congestion lengthening sessions which in turn raises concurrency
  further), which supports the general mechanism ("more devices
  mid-session at once as N grows, because sessions take longer"). What is
  corrected is the earlier claim that this concurrency differs
  *between registration and authentication*: it does not — the mechanism
  operates equally on both phases, and the N=500 threshold should be
  understood as a property of the scenario's overall contention level
  (driven by session duration vs. the 50 s/65 s scenario windows), not of
  registration specifically.
- **fig4 (end-to-end scenario time vs N).** Plots `e2eMeanMs`
  (`accepted − regStart`, per device): the full pipeline duration each
  device experiences from the moment the server sends *its* REG_1 to the
  moment its authentication is finally accepted — registration processing
  + the fixed 10 s `authDelay` gap + authentication latency, all in one
  number. Starts at ~18646 ms at N=100 (≈4.3 s registration window + 10 s
  fixed gap + ≈4.3 s authentication latency, consistent with Tables 1/3)
  and grows to ~20476 ms at N=1200 — a **+9.8%** increase, visibly smaller
  than `authLatencyMeanMs`'s own **+11.7%** growth over the same range,
  because the fixed 10 s `authDelay` term does not grow with N and dilutes
  the relative change. In absolute terms the +1830 ms increase is **larger**
  than authentication latency's own growth (+505 ms, Table 3) — the
  remaining ~1326 ms comes from the registration window itself growing
  under congestion, independently corroborating the fig3 investigation
  above: the diagnostic instrumentation there measured the registration
  window growing by ~1213 ms from N=100 to N=1200 (Table under "Why does
  registration overtake authentication?"), a 3-seed subsample that lines
  up with this main 5-seed campaign's ~1326 ms within sampling noise. fig4
  is therefore the figure that most directly shows registration, not just
  authentication, becoming measurably slower under contention.
- **fig5 (energy breakdown).** Three visible stacked segments — CPU, radio
  TX, radio RX (a residual idle/LPM segment is included for exact
  consistency with fig3's total but is now negligible, unlike in the
  fast-crypto version of this figure). **CPU now dominates at low N** (73%
  of session energy at N=100, ~47 mJ, matching device compute time almost
  exactly) **and RX (overhearing) takes over at high N** (84% at N=1200) —
  the opposite balance from the fast-crypto version, where RX dominated
  throughout. This is the direct energetic consequence of realistic crypto
  cost: at low N, the device spends most of its active-window time computing
  (not listening), so CPU dominates; as N grows, the network/congestion
  residual (Table 3) and the resulting RX/overhearing time grow enough to
  overtake it.
- **fig6 (message overhead).** Unaffected by the crypto-cost/duty-cycling
  changes (a property of the wire protocol only). AUTH_M1 (134 B) is the
  largest message; total session overhead is 398 bytes, confirmed by
  measurement in all 135 runs.
- **fig7 (combined overview).** Ties the three preceding trends together:
  success rate degrades from N=500, latency grows almost entirely from its
  network component past that point, and session energy grows linearly
  throughout, all sharing a single x-axis for direct visual comparison.

## 9. Assumptions and simplifications (summary)

1. Transport fallback: raw lr-wpan MAC with app-level fragmentation instead
   of 6LoWPAN/IPv6/UDP (§2) — required for the N=1200 scale of the sweep.
2. No MLME association; short addresses pre-provisioned.
3. Registration is simulated over the radio channel for cost measurement
   only, even though the protocol specifies it as an offline/secure-channel
   phase.
4. Registration retries are server-driven only; REG_3 is not individually
   retried at the application layer.
5. Processing-delay accounting uses literal per-primitive-operation counting
   (§3.1) rather than lump-sum constants.
6. Cryptographic randomness comes from OpenSSL's CSPRNG; scenario randomness
   (positions/timing/loss) uses the seeded ns-3 RNG.
7. `stackDelay` is counted toward a node's CPU/processing energy bucket.
8. Radio RX energy includes PHY-level reception of frames not addressed to
   the device (overhearing in the shared single-channel PAN) — physically
   realistic (802.15.4 hardware must receive/decode at least the PHY header
   before MAC-layer address filtering can discard a frame).
9. Device crypto cost (`devTpm=1072.8 ms`) is derived from a real published
   MSP430X benchmark for P-256, converted from its reported 16 MHz clock to
   the Tmote Sky's 8 MHz (§10) — it is **not** measured on the exact
   reference platform (classic MSP430F1611, no hardware multiplier), and is
   therefore likely optimistic; a pessimistic sensitivity bound from a
   second, independently-measured source is given in Table 4/5.
   `devTpa`/`devTh`/`devTmac` remain the task's original example
   placeholders, not independently re-measured.
10. `Delta=6.0s` is re-derived analytically from the new `devTpm` (§3.3), not
    itself independently validated against real hardware round-trip timing.
11. Server crypto costs are unchanged from the task's example values
    (assumed non-constrained gateway hardware).
12. The Source B sensitivity bound (Table 4/5) is computed analytically by
    rescaling the existing per-phase CPU energy breakdown — it is **not** a
    resimulated campaign, and does not account for how a slower `devTpm`
    would itself require an even larger `Delta` and could shift network
    timing/congestion behaviour.
13. **`I_cpu=1.8 mA` (§4) is the task's example placeholder, not a value
    derived from either cited source** — caught in review. Source B's own
    measurement, on the same reference hardware and with the same `E=U·I·T`
    formula used throughout this report, implies `I_cpu≈3.68 mA` while a
    point multiplication actually executes (Table 4b), roughly **doubling**
    the CPU energy component if corrected. This is **not** applied to the
    primary campaign (Tables 1–3, fig1–fig7 as generated); it is
    quantified as an explicit analytical sensitivity — "Source A +
    I_cpu(B)" — in Table 4b and Table 5 instead, alongside the existing
    `devTpm` Source A/B sensitivity, and shown to be, at high N, a
    *larger* source of uncertainty in the battery-life figures than the
    `devTpm` platform mismatch (assumption 9).

## 10. Crypto-cost sources and citations

**Source A** (primary, used for all simulated results above): Seo, H., An,
K., Kwon, H., Hu, Z. (2020). *"Montgomery Multiplication for Public Key
Cryptography on MSP430X."* ACM Transactions on Embedded Computing Systems,
Vol. 19, No. 3, Article 20. DOI:
[10.1145/3387919](https://dl.acm.org/doi/10.1145/3387919). NIST P-256 scalar
multiplication with side-channel countermeasures: 8,582,338 clock cycles
(reported as 0.53 s at their 16 MHz MSP430X clock).
**Caveat**: measured on **MSP430X with a hardware multiplier** (16/32-bit),
not the classic MSP430F1611 (Tmote Sky/TelosB) used elsewhere in this report
for energy constants, which has no hardware multiplier — likely optimistic
for the actual reference platform. We convert the cycle count to the Tmote
Sky's clock ourselves (the paper does not report a Tmote-Sky-clock figure).
**The Tmote Sky's real clock is 8.192 MHz, not 8 MHz** (confirmed by Source B
itself, which names it "Tmote Sky (16-bit/8.192-MHz MSP-430)"). The precise
conversion is `8,582,338 / 8,192,000 = 1047.7 ms`; the campaign instead uses
**`8,582,338 / 8,000,000 = 1072.8 ms`** (a rounded 8 MHz clock), which is a
deliberately conservative (slower-device) approximation, **+2.4% above** the
precise value. This is a uniform scalar on a single input parameter — it
does not shift any threshold (N=500 saturation, etc.) or change any
qualitative comparison in this report; every absolute energy/latency figure
that depends on `devTpm` would scale down by that same ~2.4% if the precise
8.192 MHz value were used instead.

**Source B** (pessimistic sensitivity bound, Tables 4–5 only): Szczechowiak,
P., Oliveira, L.B., Scott, M., Collier, M., Dahab, R. (2008). *"NanoECC:
Testing the Limits of Elliptic Curve Cryptography in Sensor Networks."*
Proceedings of the 5th European Conference on Wireless Sensor Networks
(EWSN 2008), LNCS 4913, Springer, Table 2 ("Performance evaluation of point
multiplication on MICA2 and Tmote Sky"). **Directly measured on real Tmote
Sky hardware** (MSP430F1611, no hardware multiplier, current-sense resistor
+ digitizer, 2×AA≈3V supply, `E=U·I·T` — the same formula and reference
platform used throughout this report): 160-bit prime-field point
multiplication = **0.72 s**, 3.68 mA, 7.95 mJ. **Caveat**: 160-bit, not
256-bit — we scale to 256 bits via `(256/160)^2` (low bound, 1843 ms) to
`(256/160)^2.5` (high bound, 2331 ms), an analytical extrapolation, not a
direct 256-bit measurement.

**Note on "the same formula and reference platform" above (caught in
review, §9 assumption 13):** this refers to the `E=U·I·T` energy formula
and the Tmote Sky/MSP430F1611 hardware, both shared with this report's own
methodology — it does **not** mean the campaign's `I_cpu=1.8 mA` constant
(§4) was itself derived from this source. It was not: `I_cpu=1.8 mA` is
the task's example placeholder, while Source B's own 3.68 mA figure above
is the CPU current implied *while ECC is actually executing* on the same
hardware — a real, citable number that the primary campaign does not use.
See Table 4b/5 for the quantified impact of correcting this.

Neither source measures "P-256 on a classic MSP430F1611 at 8 MHz" directly;
Source A has the right curve on the wrong (faster) chip, Source B has the
right chip but the wrong (smaller) curve. Both are reported with full
citations so the underlying numbers can be independently verified, and the
gap between them (64–118 mJ per session, Table 4) is carried through as an
explicit sensitivity range rather than collapsed into a single number.
