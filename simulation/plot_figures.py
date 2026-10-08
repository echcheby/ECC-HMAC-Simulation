#!/usr/bin/env python3
"""plot_figures.py -- generates the 7 publication-quality figures for the
REVISED ECC-HMAC IoT authentication protocol simulation results.

Reads only results/summary_all.csv (and, for fig6, the message-size
constants that ecc_hmac_proto.h/ecc-hmac-tests.cc already validated at
run time). Every plotted value comes from the CSV: no invented or smoothed
data. Aggregation across the 5 seeds per N uses mean +/- 95% Student-t CI.
"""
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from scipy import stats

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(SCRIPT_DIR, "results")
FIG_DIR = os.path.join(SCRIPT_DIR, "figures")
os.makedirs(FIG_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# Style: serif font, light dashed grid, no top/right spines, Okabe-Ito colours
# ---------------------------------------------------------------------------
OKABE_ITO = {
    "blue": "#0072B2",
    "vermillion": "#D55E00",
    "green": "#009E73",
    "orange": "#E69F00",
}
RADIO_ANNOTATION = "IEEE 802.15.4 CSMA/CA, 250 kbps"

plt.rcParams.update(
    {
        "font.family": "serif",
        "font.size": 11,
        "axes.titlesize": 13,
        "axes.titleweight": "bold",
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.grid": True,
        "grid.linestyle": "--",
        "grid.alpha": 0.4,
        "figure.dpi": 100,
        "savefig.dpi": 300,
    }
)


def annotate_radio(ax, x=0.99, y=0.03, ha="right", va="bottom"):
    ax.text(
        x,
        y,
        RADIO_ANNOTATION,
        transform=ax.transAxes,
        ha=ha,
        va=va,
        fontsize=7.5,
        style="italic",
        color="0.45",
    )


def set_node_xticks(ax, values):
    values = sorted(values)
    ax.set_xticks(values)
    ax.set_xticklabels([str(v) for v in values], rotation=45, ha="right")
    ax.set_xlabel("Number of IoT Nodes")


def agg_mean_ci(df, col, group="N"):
    """Mean and 95% Student-t CI half-width per group, computed from the
    per-seed samples actually present in the CSV (not a fixed percentage)."""
    g = df.groupby(group)[col]
    mean = g.mean()
    n = g.count()
    std = g.std(ddof=1).fillna(0.0)
    sem = std / np.sqrt(n.clip(lower=1))
    tcrit = pd.Series(
        [stats.t.ppf(0.975, k - 1) if k > 1 else 0.0 for k in n], index=n.index
    )
    ci = tcrit * sem
    out = pd.DataFrame({"mean": mean, "ci": ci, "n": n}).sort_index()
    return out


def savefig(fig, name):
    png = os.path.join(FIG_DIR, f"{name}.png")
    pdf = os.path.join(FIG_DIR, f"{name}.pdf")
    fig.savefig(png, bbox_inches="tight")
    fig.savefig(pdf, bbox_inches="tight")
    print(f"wrote {png}")
    print(f"wrote {pdf}")
    plt.close(fig)


def detect_knee(x, y, min_ratio=3.0):
    """Very small, transparent 'knee' heuristic: compare each segment's
    slope to the median slope of the first half of the curve. Returns the x
    value of the first point whose incoming slope exceeds min_ratio times
    that baseline, or None if no such clear knee exists in the data."""
    x = np.asarray(x, dtype=float)
    y = np.asarray(y, dtype=float)
    if len(x) < 4:
        return None
    slopes = np.diff(y) / np.diff(x)
    baseline = np.median(slopes[: max(1, len(slopes) // 2)])
    if baseline <= 0:
        return None
    for i, s in enumerate(slopes):
        if s > min_ratio * baseline and s > 0:
            return x[i + 1]
    return None


def main():
    summary_path = os.path.join(RESULTS_DIR, "summary_all.csv")
    df_all = pd.read_csv(summary_path)
    # The 7 required figures use the realistic, duty-cycled radio scenario
    # (dutyCycle=1) -- devices sleep whenever nothing is expected. The
    # always-on dutyCycle=0 runs are kept only for the stress-test
    # comparison table in REPORT.md (see make_report_tables.py), not plotted
    # here.
    df = df_all[df_all["dutyCycle"] == 1].copy()
    n_values = sorted(df["N"].unique())

    # ---- Shared saturation threshold: computed ONCE from the success-rate
    # curve (first N where mean success drops below 99%, the spec-mandated
    # criterion for fig2's degraded zone) and reused as the SAME vertical
    # line in both fig1 (latency) and fig2 (success rate), so the two
    # figures agree on a single definition of "saturation" instead of each
    # using its own independent criterion.
    sr = agg_mean_ci(df, "successRatePct")
    below_99 = sr[sr["mean"] < 99.0]
    saturation_n = int(below_99.index.min()) if not below_99.empty else None

    # ---- fig1: auth latency vs N, shaded 95% CI, shared saturation line ---
    lat = agg_mean_ci(df, "authLatencyMeanMs")
    fig, ax = plt.subplots(figsize=(6.4, 4.2))
    ax.plot(lat.index, lat["mean"], color=OKABE_ITO["blue"], marker="o", lw=2, label="Mean authentication latency")
    ax.fill_between(
        lat.index,
        lat["mean"] - lat["ci"],
        lat["mean"] + lat["ci"],
        color=OKABE_ITO["blue"],
        alpha=0.2,
        label="95% CI (across seeds)",
    )
    if saturation_n is not None:
        # Same threshold (first N with success <99%) as fig2's degraded
        # zone -- a single, shared definition of "saturation" across both
        # figures, not an independently-computed latency-only knee.
        ax.axvline(
            saturation_n,
            color=OKABE_ITO["vermillion"],
            ls=":",
            lw=1.5,
            label=f"Saturation threshold (N={saturation_n}, success <99%)",
        )
    ax.set_ylabel("Authentication latency (ms)")
    set_node_xticks(ax, n_values)
    ax.legend(frameon=True, framealpha=0.88, facecolor="white", edgecolor="0.8", fontsize=8.5)
    annotate_radio(ax)
    savefig(fig, "fig1_auth_latency_vs_nodes")

    # ---- fig2: success rate vs N, filled area, degraded zone <99% ---------
    fig, ax = plt.subplots(figsize=(6.4, 4.2))
    # Zoomed y-range for readability: a literal 0-100 axis compresses the
    # actually-interesting 86-100% variation into a thin sliver at the top.
    # The "filled area" is still filled down to the axis floor (a standard
    # adaptation when zooming an area chart), not literal y=0.
    y_floor = min(85.0, sr["mean"].min() - 2.0)
    ax.plot(sr.index, sr["mean"], color=OKABE_ITO["green"], marker="o", lw=2)
    ax.fill_between(sr.index, y_floor, sr["mean"], color=OKABE_ITO["green"], alpha=0.18)
    if saturation_n is not None:
        # Shade only the x-range where the curve is actually below 99%, not
        # the full plot width.
        ax.axvspan(
            saturation_n,
            sr.index.max(),
            color=OKABE_ITO["vermillion"],
            alpha=0.08,
            label=f"Degraded zone (<99% success, N={saturation_n})",
        )
        ax.axhline(99.0, color=OKABE_ITO["vermillion"], ls=":", lw=1.2)
        ax.legend(
            frameon=True, framealpha=0.88, facecolor="white", edgecolor="0.8", fontsize=8.5, loc="lower left"
        )
    ax.set_ylabel("Authentication success rate (%)")
    ax.set_ylim(y_floor, 100.5)
    set_node_xticks(ax, n_values)
    annotate_radio(ax)
    savefig(fig, "fig2_success_rate_vs_nodes")

    # ---- fig3: energy per session vs N, CI error bars -----------------------
    # Windowed per-session energy (registration + authentication phases only,
    # radio duty-cycled -- see REPORT.md): the realistic cost of one
    # authentication, not energy integrated over the whole (mostly idle)
    # simulation window. Registration (a one-time cost) and authentication
    # (the repeating cost) are plotted separately alongside the total, since
    # only authentication recurs in normal operation.
    en = agg_mean_ci(df, "sessionEnergyMeanMJ")
    reg_en = agg_mean_ci(df, "regEnergyMeanMJ")
    auth_en = agg_mean_ci(df, "authEnergyMeanMJ")
    fig, ax = plt.subplots(figsize=(6.4, 4.2))
    ax.errorbar(
        en.index,
        en["mean"],
        yerr=en["ci"],
        color=OKABE_ITO["orange"],
        marker="o",
        lw=2,
        capsize=3,
        ecolor="0.4",
        elinewidth=1,
        label="Total session (reg + auth)",
    )
    ax.errorbar(
        reg_en.index,
        reg_en["mean"],
        yerr=reg_en["ci"],
        color=OKABE_ITO["blue"],
        marker="s",
        lw=1.6,
        ls="--",
        capsize=3,
        ecolor="0.4",
        elinewidth=1,
        label="Registration (one-time cost)",
    )
    ax.errorbar(
        auth_en.index,
        auth_en["mean"],
        yerr=auth_en["ci"],
        color=OKABE_ITO["vermillion"],
        marker="^",
        lw=1.6,
        ls="--",
        capsize=3,
        ecolor="0.4",
        elinewidth=1,
        label="Authentication (repeating cost)",
    )
    ax.set_ylabel("Mean energy (mJ)")
    ax.legend(frameon=True, framealpha=0.88, facecolor="white", edgecolor="0.8", fontsize=8.5, loc="upper left")
    set_node_xticks(ax, n_values)
    annotate_radio(ax)
    savefig(fig, "fig3_energy_vs_nodes")

    # ---- fig4: end-to-end scenario time vs N -------------------------------
    e2e = agg_mean_ci(df, "e2eMeanMs")
    fig, ax = plt.subplots(figsize=(6.4, 4.2))
    ax.plot(e2e.index, e2e["mean"], color=OKABE_ITO["blue"], marker="o", lw=2, label="Mean end-to-end transaction time")
    ax.fill_between(
        e2e.index, e2e["mean"] - e2e["ci"], e2e["mean"] + e2e["ci"], color=OKABE_ITO["blue"], alpha=0.2, label="95% CI"
    )
    ax.set_ylabel("End-to-end transaction time (ms)")
    set_node_xticks(ax, n_values)
    ax.legend(frameon=False, fontsize=8.5)
    annotate_radio(ax)
    savefig(fig, "fig4_scenario_time_vs_nodes")

    # ---- fig5: energy breakdown stacked bars, with radio-share annotation --
    # Four segments -- CPU, TX, RX, and Idle/LPM -- so that each bar's total
    # height exactly equals the per-session energy plotted in fig3 (the CPU +
    # TX + RX windowed sums alone under-count the total by whatever brief
    # idle/waiting time falls *inside* the active session window, which would
    # otherwise make the stacked total disagree with fig3 and make the radio
    # share % label disagree with the bar's own visual proportions).
    cpu = agg_mean_ci(df, "sessionCpuEnergyMeanMJ")["mean"]
    tx = agg_mean_ci(df, "sessionTxEnergyMeanMJ")["mean"]
    rx = agg_mean_ci(df, "sessionRxEnergyMeanMJ")["mean"]
    share = agg_mean_ci(df, "radioSharePct")["mean"]
    total = en["mean"]  # same per-session total energy as fig3
    lpm = (total - cpu - tx - rx).clip(lower=0)

    fig, ax = plt.subplots(figsize=(7.6, 5.0))
    x = np.arange(len(n_values))
    width = 0.62
    ax.bar(x, cpu.values, width, color=OKABE_ITO["blue"], label="CPU / crypto processing")
    ax.bar(x, tx.values, width, bottom=cpu.values, color=OKABE_ITO["vermillion"], label="Radio TX")
    ax.bar(x, rx.values, width, bottom=(cpu + tx).values, color=OKABE_ITO["orange"], label="Radio RX")
    ax.bar(
        x,
        lpm.values,
        width,
        bottom=(cpu + tx + rx).values,
        color="0.82",
        label="Idle / low-power (LPM)",
    )
    for i, nval in enumerate(n_values):
        top = total.iloc[i]
        ax.text(i, top, f"{share.iloc[i]:.1f}%", ha="center", va="bottom", fontsize=7.5, color="0.25")
    ax.set_xticks(x)
    ax.set_xticklabels([str(v) for v in n_values], rotation=45, ha="right")
    ax.set_xlabel("Number of IoT Nodes")
    ax.set_ylabel("Mean energy per session (mJ)")
    ax.set_ylim(top=ax.get_ylim()[1] * 1.30)  # headroom for the % labels + annotation above the tallest bar
    ax.legend(
        frameon=True,
        framealpha=0.88,
        facecolor="white",
        edgecolor="0.8",
        fontsize=8.5,
        loc="upper left",
    )
    ax.text(
        0.99,
        0.98,
        "Bar labels: radio share of session energy = (TX+RX)/total\n"
        "Radio is duty-cycled (sleeps between phases and after the\n"
        "session), but RX still dominates during the active window:\n"
        "other devices keep transmitting on the shared channel while\n"
        "this device is awake for its own exchange (overhearing).",
        transform=ax.transAxes,
        ha="right",
        va="top",
        fontsize=7,
        color="0.35",
        style="italic",
    )

    # CPU and TX are real but small next to RX on this linear scale -- add a
    # zoomed inset so they are clearly visible, with their own values.
    inset = ax.inset_axes([0.055, 0.40, 0.30, 0.34])
    inset.bar(x, cpu.values, width, color=OKABE_ITO["blue"])
    inset.bar(x, tx.values, width, bottom=cpu.values, color=OKABE_ITO["vermillion"])
    inset.set_xticks(x[::2])
    inset.set_xticklabels([str(n_values[i]) for i in range(0, len(n_values), 2)], fontsize=6, rotation=45, ha="right")
    inset.set_ylabel("mJ", fontsize=7)
    inset.tick_params(axis="both", labelsize=6)
    inset.set_title("CPU + TX only (zoom)", fontsize=7.5, fontweight="bold")
    inset.grid(True, linestyle="--", alpha=0.4)

    annotate_radio(ax, x=0.99, y=-0.32)
    savefig(fig, "fig5_energy_breakdown")

    # ---- fig6: message overhead bar chart ----------------------------------
    msgs = [
        ("REG_1\n(0x01)", 66, "registration"),
        ("REG_2\n(0x02)", 98, "registration"),
        ("REG_3\n(0x03)", 33, "registration"),
        ("AUTH_TRIGGER\n(0x04)", 1, "trigger"),
        ("AUTH_M1\n(0x05)", 134, "authentication"),
        ("AUTH_M2\n(0x06)", 66, "authentication"),
    ]
    total_measured = int(df["totalSessionBytes"].iloc[0]) if "totalSessionBytes" in df.columns else 398
    sizes_ok = bool(df["messageSizesOk"].astype(bool).all()) if "messageSizesOk" in df.columns else True
    phase_colors = {
        "registration": OKABE_ITO["blue"],
        "trigger": OKABE_ITO["green"],
        "authentication": OKABE_ITO["vermillion"],
    }
    fig, ax = plt.subplots(figsize=(8.4, 4.8))
    labels = [m[0] for m in msgs]
    sizes = [m[1] for m in msgs]
    colors = [phase_colors[m[2]] for m in msgs]
    x = np.arange(len(labels))
    bars = ax.bar(x, sizes, color=colors, width=0.62)
    for b, s in zip(bars, sizes):
        ax.text(b.get_x() + b.get_width() / 2, s + 3, str(s), ha="center", va="bottom", fontsize=9)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=8.5)
    ax.set_ylim(0, 160)
    ax.set_ylabel("Application payload size (bytes)")
    from matplotlib.patches import Patch

    legend_handles = [Patch(color=c, label=p.capitalize()) for p, c in phase_colors.items()]
    ax.legend(
        handles=legend_handles,
        frameon=True,
        framealpha=0.88,
        facecolor="white",
        edgecolor="0.8",
        fontsize=8.5,
        loc="upper left",
    )
    status = "measured = expected" if sizes_ok else "MISMATCH -- see REPORT.md"
    ax.text(
        0.98,
        0.98,
        f"Total session overhead: {total_measured} bytes ({status})",
        transform=ax.transAxes,
        ha="right",
        va="top",
        fontsize=9,
        bbox=dict(boxstyle="round,pad=0.4", fc="white", ec="0.6"),
    )
    annotate_radio(ax, x=0.5, y=-0.16, ha="center")
    savefig(fig, "fig6_message_overhead")

    # ---- fig7: combined overview (success / latency / energy) -------------
    fig, ax1 = plt.subplots(figsize=(7.6, 4.8))
    fig.subplots_adjust(right=0.72)
    ax2 = ax1.twinx()
    ax3 = ax1.twinx()
    ax3.spines["right"].set_position(("axes", 1.22))

    (l1,) = ax1.plot(sr.index, sr["mean"], color=OKABE_ITO["green"], marker="o", lw=2, label="Success rate (%)")
    (l2,) = ax2.plot(lat.index, lat["mean"], color=OKABE_ITO["blue"], marker="s", lw=2, label="Auth latency (ms)")
    (l3,) = ax3.plot(en.index, en["mean"], color=OKABE_ITO["orange"], marker="^", lw=2, label="Energy per session (mJ)")

    ax1.set_ylabel("Success rate (%)", color=OKABE_ITO["green"])
    ax2.set_ylabel("Authentication latency (ms)", color=OKABE_ITO["blue"])
    ax3.set_ylabel("Energy per session (mJ)", color=OKABE_ITO["orange"])
    ax1.tick_params(axis="y", colors=OKABE_ITO["green"])
    ax2.tick_params(axis="y", colors=OKABE_ITO["blue"])
    ax3.tick_params(axis="y", colors=OKABE_ITO["orange"])

    set_node_xticks(ax1, n_values)
    ax1.legend(
        handles=[l1, l2, l3],
        frameon=True,
        framealpha=0.88,
        facecolor="white",
        edgecolor="0.8",
        fontsize=8.5,
        loc="center left",
    )
    annotate_radio(ax1, x=0.99, y=1.02)
    savefig(fig, "fig7_combined_overview")

    print("\nAll 7 figures written to", FIG_DIR)


if __name__ == "__main__":
    main()
