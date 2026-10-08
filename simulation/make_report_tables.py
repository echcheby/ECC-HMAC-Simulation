#!/usr/bin/env python3
"""Generates the markdown tables used in REPORT.md, from results/summary_all.csv
and results/loss_experiment_summary.csv. Prints markdown to stdout; run_all.sh
does not call this automatically -- it's a one-off report-authoring helper.

Assumes the "realistic MSP430" campaign: devTpm=1072.8 ms (Source A, see
REPORT.md), timeoutDelta=6.0 s, dutyCycle in {1 (primary), 0 (comparison)}.
"""
import os

import numpy as np
import pandas as pd
from scipy import stats

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(SCRIPT_DIR, "results")

# ---- Crypto cost constants (must match ecc-hmac-revised.cc defaults) ------
# Source A (Seo et al. 2020, P-256, 8,582,338 cycles at their reported 16 MHz
# MSP430X clock) converted to the Tmote Sky's clock. The campaign uses a
# rounded 8 MHz (1072.8 ms) -- NanoECC (Source B) documents the real Tmote
# Sky clock as 8.192 MHz, which would give 8,582,338/8,192,000 = 1047.7 ms.
# Using 8 MHz is therefore a conservative (slower-device) rounding, +2.4%
# above the precise value; this is a uniform scalar on one input parameter
# and does not change any threshold or qualitative comparison in this report.
DEV_TPM_A = 1072.8  # ms, as used throughout the campaign (8 MHz rounding)
DEV_TPM_A_PRECISE = 8582338 / 8192000 * 1000  # ms, 8.192 MHz (not used in the campaign)
DEV_TPA, DEV_TH, DEV_TMAC = 0.2, 0.1, 0.2  # ms, task EXAMPLE placeholders
STACK_DELAY = 2.0  # ms
# Source B (Szczechowiak et al. 2008, NanoECC, Table 2): 0.72 s measured for
# a REAL 160-bit prime-field point multiplication on actual Tmote Sky
# hardware. Scaled to a 256-bit curve via (256/160)^2 .. (256/160)^2.5 as a
# pessimistic sensitivity bound (NOT a direct measurement at 256 bits).
DEV_TPM_B_LOW = 0.72 * 1000 * (256 / 160) ** 2       # ms
DEV_TPM_B_HIGH = 0.72 * 1000 * (256 / 160) ** 2.5    # ms

# CPU current sensitivity: the campaign's --iCpu default (1.8 mA) is the
# task's EXAMPLE placeholder, carried over unmodified -- it is NOT sourced
# from Source B, even though Source B's own measurement, on the same
# reference hardware and using the same E=U.I.T formula this report uses
# throughout, implies a higher figure: 7.95 mJ / (0.72 s * 3 V) = 3.68 mA
# *while actually executing* a P-256 (scaled) point multiplication on a real
# Tmote Sky. Reported here as an explicit analytical sensitivity (Table 4b/5),
# not folded into the primary campaign (Table 1), matching how the Source B
# devTpm bound above is handled.
ICPU_A = 1.8   # mA, task example placeholder -- used throughout the primary campaign
ICPU_B = 3.68  # mA, Source B measured CPU current during ECC computation (Table 2)
ICPU_SCALE = ICPU_B / ICPU_A

T_COMPUTE_T_REG = 4 * DEV_TPM_A + DEV_TPA + DEV_TH + STACK_DELAY
T_COMPUTE_T_AUTH = 4 * DEV_TPM_A + DEV_TPA + 4 * DEV_TH + 2 * DEV_TMAC + STACK_DELAY


def agg(df, col, group="N"):
    g = df.groupby(group)[col]
    mean = g.mean()
    n = g.count()
    std = g.std(ddof=1).fillna(0.0)
    sem = std / np.sqrt(n.clip(lower=1))
    tcrit = pd.Series([stats.t.ppf(0.975, k - 1) if k > 1 else 0.0 for k in n], index=n.index)
    return mean, tcrit * sem


def main():
    df_all = pd.read_csv(os.path.join(RESULTS_DIR, "summary_all.csv"))
    df = df_all[df_all["dutyCycle"] == 1].copy()

    # ---- Table 1: main results (dutyCycle=1, primary scenario) -----------
    lat_m, lat_c = agg(df, "authLatencyMeanMs")
    sr_m, sr_c = agg(df, "successRatePct")
    e2e_m, e2e_c = agg(df, "e2eMeanMs")
    en_m, en_c = agg(df, "sessionEnergyMeanMJ")
    rs_m, rs_c = agg(df, "radioSharePct")
    drops = df.groupby("N")["totalMacDrops"].mean()
    regf = df.groupby("N")["regFailures"].sum()
    authf = df.groupby("N")["authFailures"].sum()
    desync = df.groupby("N")["desyncCount"].sum()

    print("## Table 1: Main results (dutyCycle=1, realistic MSP430 Tpm, Delta=6s)\n")
    print(
        "| N | Auth latency (ms) | Success rate (%) | E2E time (ms) | "
        "Session energy (mJ) | Radio share (%) | Mean MAC drops | "
        "Reg fail (Σ/5) | Auth fail (Σ/5) | Desync (Σ/5) |"
    )
    print("|---|---|---|---|---|---|---|---|---|---|")
    for n in sorted(df["N"].unique()):
        print(
            f"| {n} | {lat_m[n]:.1f} ± {lat_c[n]:.1f} | {sr_m[n]:.2f} ± {sr_c[n]:.2f} | "
            f"{e2e_m[n]:.1f} ± {e2e_c[n]:.1f} | {en_m[n]:.2f} ± {en_c[n]:.2f} | {rs_m[n]:.1f} | "
            f"{drops[n]:.1f} | {int(regf[n])} | {int(authf[n])} | {int(desync[n])} |"
        )

    # ---- Table 2: duty-cycle comparison (dutyCycle=1 vs 0) ----------------
    df0 = df_all[df_all["dutyCycle"] == 0].copy()
    if not df0.empty:
        sr0_m, _ = agg(df0, "successRatePct")
        sess0_m, _ = agg(df0, "sessionEnergyMeanMJ")
        full1_m, _ = agg(df, "fullEnergyMeanMJ")
        full0_m, _ = agg(df0, "fullEnergyMeanMJ")
        print("\n## Table 2: Duty-cycled (real sleep) vs always-on -- validation\n")
        print(
            "| N | Success dc=1 (%) | Success dc=0 (%) | Session energy dc=1 (mJ) | "
            "Session energy dc=0 (mJ) | Full-scenario energy dc=1 (mJ) | "
            "Full-scenario energy dc=0 (mJ) | Reduction (full, %) |"
        )
        print("|---|---|---|---|---|---|---|---|")
        for n in sorted(df["N"].unique()):
            if n not in full0_m.index:
                continue
            reduction = 100.0 * (1.0 - full1_m[n] / full0_m[n])
            print(
                f"| {n} | {sr_m[n]:.2f} | {sr0_m[n]:.2f} | {en_m[n]:.2f} | {sess0_m[n]:.2f} | "
                f"{full1_m[n]:.1f} | {full0_m[n]:.1f} | {reduction:.1f} |"
            )

    # ---- Table 3: latency decomposition (compute vs network) --------------
    total_attempts = df.groupby("N")["totalAttempts"].sum()
    n_seeds = df.groupby("N").size()
    success_devices = (sr_m / 100.0) * pd.Series(n_seeds.index, index=n_seeds.index) * n_seeds
    mean_attempts_per_success = total_attempts / success_devices.replace(0, np.nan)
    print("\n## Table 3: Authentication latency decomposition (compute vs network)\n")
    print(
        "| N | Mean attempts/success | Compute time (ms) = attempts × "
        f"{T_COMPUTE_T_AUTH:.1f}ms | Network/congestion residual (ms) | "
        "Network share of latency (%) |"
    )
    print("|---|---|---|---|---|")
    for n in sorted(df["N"].unique()):
        att = mean_attempts_per_success.get(n, np.nan)
        if np.isnan(att):
            continue
        compute_ms = att * T_COMPUTE_T_AUTH
        network_ms = lat_m[n] - compute_ms
        network_share = 100.0 * network_ms / lat_m[n] if lat_m[n] > 0 else 0.0
        print(f"| {n} | {att:.2f} | {compute_ms:.1f} | {network_ms:.1f} | {network_share:.1f} |")

    # ---- Table 4: Source B sensitivity (analytical only, no resimulation) -
    reg_cpu_m, _ = agg(df, "regCpuEnergyMeanMJ")
    auth_cpu_m, _ = agg(df, "authCpuEnergyMeanMJ")
    reg_tx_m, _ = agg(df, "regTxEnergyMeanMJ")
    reg_rx_m, _ = agg(df, "regRxEnergyMeanMJ")
    auth_tx_m, _ = agg(df, "authTxEnergyMeanMJ")
    auth_rx_m, _ = agg(df, "authRxEnergyMeanMJ")
    scale_low = DEV_TPM_B_LOW / DEV_TPM_A
    scale_high = DEV_TPM_B_HIGH / DEV_TPM_A
    print("\n## Table 4: Session energy sensitivity -- Source A vs Source B (pessimistic bound)\n")
    print(
        f"Source B scaling: devTpm scaled from {DEV_TPM_A:.1f} ms (Source A) to "
        f"{DEV_TPM_B_LOW:.0f}-{DEV_TPM_B_HIGH:.0f} ms (Source B, 160-bit real measurement "
        f"scaled to 256-bit via (256/160)^2..2.5). CPU energy scales linearly with devTpm; "
        f"TX/RX assumed unchanged (analytical only, not resimulated).\n"
    )
    print(
        "| N | Session energy, Source A (mJ) | Session energy, Source B low (mJ) | "
        "Session energy, Source B high (mJ) |"
    )
    print("|---|---|---|---|")
    for n in sorted(df["N"].unique()):
        cpu_a = reg_cpu_m[n] + auth_cpu_m[n]
        txrx = reg_tx_m[n] + reg_rx_m[n] + auth_tx_m[n] + auth_rx_m[n]
        session_a = cpu_a + txrx
        session_b_low = cpu_a * scale_low + txrx
        session_b_high = cpu_a * scale_high + txrx
        print(f"| {n} | {session_a:.2f} | {session_b_low:.2f} | {session_b_high:.2f} |")

    # ---- Table 4b: per-phase CPU/TX/RX breakdown at selected N -------------
    key_ns = [100, 500, 1000, 1200]
    print("\n## Table 4b: Per-phase CPU/TX/RX energy breakdown (Source A devTpm, mJ)\n")
    print(
        "| N | Reg CPU (I_cpu=1.8mA) | Reg TX | Reg RX | Reg total | "
        "Auth CPU (I_cpu=1.8mA) | Auth TX | Auth RX | Auth total | "
        "Reg CPU (I_cpu=3.68mA) | Reg total (I_cpu=3.68mA) | "
        "Auth CPU (I_cpu=3.68mA) | Auth total (I_cpu=3.68mA) |"
    )
    print("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for n in key_ns:
        reg_cpu_b = reg_cpu_m[n] * ICPU_SCALE
        auth_cpu_b = auth_cpu_m[n] * ICPU_SCALE
        print(
            f"| {n} | {reg_cpu_m[n]:.2f} | {reg_tx_m[n]:.2f} | {reg_rx_m[n]:.2f} | "
            f"{reg_cpu_m[n]+reg_tx_m[n]+reg_rx_m[n]:.2f} | {auth_cpu_m[n]:.2f} | {auth_tx_m[n]:.2f} | "
            f"{auth_rx_m[n]:.2f} | {auth_cpu_m[n]+auth_tx_m[n]+auth_rx_m[n]:.2f} | "
            f"{reg_cpu_b:.2f} | {reg_cpu_b+reg_tx_m[n]+reg_rx_m[n]:.2f} | "
            f"{auth_cpu_b:.2f} | {auth_cpu_b+auth_tx_m[n]+auth_rx_m[n]:.2f} |"
        )
    print(
        "\nCPU is essentially flat with N (23.2->25.3 mJ, +9%); RX (overhearing) "
        "dominates the growth in both phases (reg: 8.7->142.7 mJ, +16x; auth: "
        "8.4->114.4 mJ, +14x) -- **neither phase's total energy is independent of "
        "N**, only its CPU component is.\n"
        "\n**I_cpu inconsistency**: the campaign uses I_cpu=1.8 mA throughout "
        "(the task's example placeholder), but Source B's own measurement on the "
        "same reference hardware, with the same E=U.I.T formula used throughout "
        f"this report, implies I_cpu={ICPU_B:.2f} mA "
        "(7.95 mJ / (0.72 s x 3 V)) while actually executing a point "
        f"multiplication -- a {ICPU_SCALE:.2f}x higher current than the value "
        "used in the primary campaign. The last four columns above show the "
        "CPU-energy and per-phase-total impact of correcting only this constant "
        "(devTpm held at Source A): CPU energy is essentially doubled at every N, "
        "and because CPU is the dominant term at low N (Table 4b, 1.8 mA column), "
        "the correction has the largest *relative* impact there.\n"
    )

    # ---- Table 5: battery-life sensitivity ----------------------------------
    BATTERIES_J = {"CR2032 (~2.43 kJ)": 2430.0, "2xAA (~27 kJ)": 27000.0}
    rates_per_day = {"1 auth/hour": 24, "1 auth/6h": 4, "1 auth/day": 1}
    print("\n## Table 5: Battery-life sensitivity\n")
    print(
        "**These are upper-bound estimates for the protocol's cryptographic cost "
        "alone**: no application traffic, no standby/quiescent current between "
        "authentications, and no battery self-discharge are included. Real battery "
        "life will be shorter. Registration happens once per device lifetime (not "
        "repeated) -- treating it as a recurring cost would implicitly assume the "
        "device re-registers every hour, which is wrong -- so it is reported "
        "separately as a one-time cost. Only authentication recurs, so the "
        "recurring battery-life estimates below use **authentication-phase energy "
        "alone**, not the full session. **Neither phase's energy is independent of "
        "N** (Table 4b: RX/overhearing dominates and grows sharply with N), so "
        "both tables below are given at N=100, 500, 1000, and 1200 rather than a "
        "single representative value. A fourth basis, **'Source A + I_cpu(B)'**, "
        "isolates the I_cpu correction discussed under Table 4b: devTpm stays at "
        "Source A, but I_cpu is corrected from the campaign's 1.8 mA placeholder "
        f"to Source B's measured {ICPU_B:.2f} mA -- roughly doubling the CPU "
        "energy component alone, independent of the devTpm sensitivity captured "
        "by the Source B low/high rows.\n"
    )

    def energy_bases(cpu_m, tx_m, rx_m, n):
        return {
            "Source A": cpu_m[n] * 1.0 + tx_m[n] + rx_m[n],
            "Source A + I_cpu(B)": cpu_m[n] * ICPU_SCALE + tx_m[n] + rx_m[n],
            "Source B low": cpu_m[n] * scale_low + tx_m[n] + rx_m[n],
            "Source B high": cpu_m[n] * scale_high + tx_m[n] + rx_m[n],
        }

    print("### Registration (one-time cost per device)\n")
    header = "| N | Basis | Energy (mJ) | " + " | ".join(f"% of {k}" for k in BATTERIES_J) + " |"
    print(header)
    print("|---|---|---|" + "---|" * len(BATTERIES_J))
    for n in key_ns:
        reg_bases = energy_bases(reg_cpu_m, reg_tx_m, reg_rx_m, n)
        for label, mj in reg_bases.items():
            j = mj / 1000.0
            pct = {k: 100.0 * j / v for k, v in BATTERIES_J.items()}
            print(f"| {n} | {label} | {mj:.2f} | " + " | ".join(f"{pct[k]:.4f}%" for k in BATTERIES_J) + " |")

    print("\n### Authentication (repeating cost)\n")
    for batt_label, batt_j in BATTERIES_J.items():
        print(f"\n#### {batt_label}\n")
        print(
            "| N | Basis | Auth energy (mJ) | " +
            " | ".join(f"{k}: days" for k in rates_per_day) + " | " +
            " | ".join(f"{k}: %/year" for k in rates_per_day) + " |"
        )
        print("|---|---|---|" + "---|" * len(rates_per_day) + "---|" * len(rates_per_day))
        for n in key_ns:
            auth_bases = energy_bases(auth_cpu_m, auth_tx_m, auth_rx_m, n)
            for label, mj in auth_bases.items():
                j_per_auth = mj / 1000.0
                days = {k: batt_j / (j_per_auth * v) for k, v in rates_per_day.items()}
                pct_per_year = {k: 100.0 * j_per_auth * v * 365.0 / batt_j for k, v in rates_per_day.items()}
                print(
                    f"| {n} | {label} | {mj:.2f} | " +
                    " | ".join(f"{days[k]:.0f}" for k in rates_per_day) + " | " +
                    " | ".join(f"{pct_per_year[k]:.3f}%" for k in rates_per_day) + " |"
                )

    # ---- Loss experiment ----------------------------------------------------
    loss_path = os.path.join(RESULTS_DIR, "loss_experiment_summary.csv")
    if os.path.exists(loss_path):
        ldf = pd.read_csv(loss_path)
        lsr_m, lsr_c = agg(ldf, "successRatePct", group="lossProb")
        latt = ldf.groupby("lossProb")["totalAttempts"].mean()
        ldesync = ldf.groupby("lossProb")["desyncCount"].sum()
        lregf = ldf.groupby("lossProb")["regFailures"].sum()
        print("\n## Loss experiment (N=100, dutyCycle=1)\n")
        print(
            "| Loss probability (AUTH_M1/M2) | Success rate (%) | Mean total attempts (N=100) | "
            "Desync (Σ/5 seeds) | Reg failures (Σ/5 seeds) |"
        )
        print("|---|---|---|---|---|")
        for lp in sorted(ldf["lossProb"].unique()):
            print(
                f"| {lp*100:.0f}% | {lsr_m[lp]:.2f} ± {lsr_c[lp]:.2f} | {latt[lp]:.1f} | "
                f"{int(ldesync[lp])} | {int(lregf[lp])} |"
            )


if __name__ == "__main__":
    main()
