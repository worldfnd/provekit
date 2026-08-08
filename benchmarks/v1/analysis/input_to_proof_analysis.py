"""Marimo analysis for the V1 raw-input-to-proof campaign.

Run from the repository root:
    uv run --project benchmarks/v1/analysis marimo edit \
      benchmarks/v1/analysis/input_to_proof_analysis.py
"""

import marimo

__generated_with = "0.23.15"
app = marimo.App(width="full")


@app.cell
def _():
    import marimo as mo
    import matplotlib.pyplot as plt
    import pandas as pd
    import seaborn as sns
    from pathlib import Path

    return Path, mo, pd, plt, sns


@app.cell
def _(mo):
    mo.md(r"""
    # ProveKit V1 input-to-proof campaign

    ## tl;dr

    This notebook reads only the canonical sample CSV. It compares cold and
    warm raw-input-to-serialized-proof latency, including fresh witness
    generation. Passport P1 is a fourth, separately named workload; the
    historical Passport, OPRF, and WebAuthn counterparts remain explicitly
    non-equivalent across languages.
    """)
    return


@app.cell
def _(Path, pd):
    csv_path = Path(__file__).resolve().parents[1] / "input-to-proof-data" / "input-to-proof-samples.csv"
    samples = pd.read_csv(csv_path, keep_default_na=False)
    numeric_columns = [
        "sample_index",
        "initialization_time_ms",
        "witness_time_ms",
        "prover_time_ms",
        "verify_time_ms",
        "total_time_ms",
        "input_to_proof_time_ms",
        "peak_memory_mib",
        "proof_size_bytes",
        "circuit_size_bytes",
        "artifact_size_bytes",
        "bundle_size_bytes",
    ]
    for column in numeric_columns:
        samples[column] = pd.to_numeric(samples[column], errors="coerce")

    workload_labels = {
        "passport_complete_age_check": "Passport historical",
        "passport_age_integrity": "Passport P1",
        "oprf_nullifier": "OPRF O2",
        "webauthn": "WebAuthn analogue",
    }
    samples["workload"] = samples["circuit"].map(workload_labels).fillna(samples["circuit"])
    samples["target"] = samples["hardware"] + " · " + samples["runtime"]
    return csv_path, samples, workload_labels


@app.cell
def _(csv_path, mo):
    mo.md(f"""
    ## Context & Methods

    Source: `{csv_path}`

    ### Key Assumptions

    - Headline latency begins with raw structured input and ends when serialized
      proof bytes exist; verification is a correctness gate outside timing.
    - `cold_local` uses a fresh process/runtime for every attempt.
    - `warm_reuse` reuses initialization but regenerates witness and proof.
    - ProveKit native integrates witness construction and proving, so its native
      witness phase is intentionally blank rather than estimated.
    - Missing target/stack/workload/mode combinations remain visible as gaps.
    """)
    return


@app.cell
def _(pd, samples, workload_labels):
    expected = pd.MultiIndex.from_product(
        [
            ["macbook_m4", "iphone_se_2022", "motorola_e15"],
            list(workload_labels),
            ["provekit_v1", "noir_barretenberg", "circom_groth16"],
            ["cold_local", "warm_reuse"],
        ],
        names=["hardware", "circuit", "prover", "timing_mode"],
    ).to_frame(index=False)
    observed = (
        samples.groupby(["hardware", "circuit", "prover", "timing_mode"], as_index=False)
        .agg(
            warmups=("sample_kind", lambda values: int((values == "warmup").sum())),
            measured=("sample_kind", lambda values: int((values == "measured").sum())),
            status=("status", lambda values: "ok" if (values == "ok").all() else values.iloc[0]),
        )
    )
    coverage = expected.merge(observed, how="left")
    coverage["status"] = coverage["status"].replace("", pd.NA).fillna("missing")
    coverage[["warmups", "measured"]] = coverage[["warmups", "measured"]].fillna(0).astype(int)
    coverage["complete"] = (
        (coverage["status"] == "ok")
        & (coverage["warmups"] == 1)
        & (coverage["measured"] == 5)
    )
    measured = samples[(samples["status"] == "ok") & (samples["sample_kind"] == "measured")].copy()
    return coverage, measured


@app.cell
def _(coverage, measured, mo):
    mo.md(f"""
    ## Data

    - Complete cold/warm series: **{int(coverage['complete'].sum())} / 72**
    - Measured attempts retained: **{len(measured)}**
    - Missing or incomplete series: **{int((~coverage['complete']).sum())}**
    """)
    return


@app.cell
def _(coverage, plt, sns):
    coverage_plot = coverage.copy()
    coverage_plot["row"] = (
        coverage_plot["circuit"] + " · " + coverage_plot["prover"] + " · " + coverage_plot["timing_mode"]
    )
    coverage_plot["complete_code"] = coverage_plot["complete"].astype(int)
    matrix = coverage_plot.pivot(index="row", columns="hardware", values="complete_code")
    annotations = coverage_plot.pivot(index="row", columns="hardware", values="status")
    figure_coverage, axis_coverage = plt.subplots(figsize=(12, 14))
    sns.heatmap(
        matrix,
        annot=annotations,
        fmt="",
        cmap=sns.color_palette(["#eceff1", "#2e7d32"], as_cmap=True),
        vmin=0,
        vmax=1,
        cbar=False,
        linewidths=0.4,
        ax=axis_coverage,
    )
    axis_coverage.set_title("Coverage of 72 expected workload × stack × target × mode series")
    axis_coverage.set_xlabel("Target")
    axis_coverage.set_ylabel("Circuit · stack · timing mode")
    figure_coverage.tight_layout()
    figure_coverage
    return


@app.cell
def _(mo):
    mo.md(r"""
    ## Results

    Every figure below uses the five measured samples only. Medians summarize
    central performance; missing bars are absent evidence, never zeros.
    """)
    return


@app.cell
def _(measured, sns):
    latency_summary = measured.groupby(
        ["target", "workload", "prover", "timing_mode"], as_index=False
    ).agg(median_input_to_proof_ms=("input_to_proof_time_ms", "median"))
    figure_latency = sns.catplot(
        data=latency_summary,
        kind="bar",
        x="workload",
        y="median_input_to_proof_ms",
        hue="prover",
        row="target",
        col="timing_mode",
        sharey=False,
        height=3.2,
        aspect=1.6,
    ).figure
    figure_latency.suptitle("Median raw-input-to-proof latency", y=1.01)
    for axis in figure_latency.axes:
        axis.tick_params(axis="x", rotation=25)
        axis.set_ylabel("Milliseconds")
    figure_latency
    return


@app.cell
def _(measured, pd, plt, sns):
    phases = measured.melt(
        id_vars=["target", "workload", "prover", "timing_mode"],
        value_vars=["witness_time_ms", "prover_time_ms"],
        var_name="phase",
        value_name="milliseconds",
    ).dropna(subset=["milliseconds"])
    phase_summary = phases.groupby(
        ["target", "workload", "prover", "timing_mode", "phase"], as_index=False
    ).agg(median_ms=("milliseconds", "median"))
    figure_phases, axis_phases = plt.subplots(figsize=(14, 6))
    sns.barplot(
        data=phase_summary,
        x="workload",
        y="median_ms",
        hue="phase",
        errorbar=None,
        ax=axis_phases,
    )
    axis_phases.set_title("Witness and prover phase medians across completed series")
    axis_phases.set_ylabel("Milliseconds")
    axis_phases.tick_params(axis="x", rotation=25)
    figure_phases.tight_layout()
    figure_phases
    return


@app.cell
def _(measured, plt, sns):
    payload = measured.groupby(["target", "workload", "prover"], as_index=False).agg(
        proving_payload_bytes=("circuit_size_bytes", "median")
    )
    figure_payload, axis_payload = plt.subplots(figsize=(14, 6))
    sns.barplot(data=payload, x="workload", y="proving_payload_bytes", hue="prover", ax=axis_payload)
    axis_payload.set_yscale("log")
    axis_payload.set_title("Deduplicated proving payload (log scale)")
    axis_payload.set_ylabel("Bytes")
    axis_payload.tick_params(axis="x", rotation=25)
    figure_payload.tight_layout()
    figure_payload
    return


@app.cell
def _(measured, plt, sns):
    proof = measured.groupby(["target", "workload", "prover"], as_index=False).agg(
        serialized_proof_bytes=("proof_size_bytes", "median")
    )
    figure_proof, axis_proof = plt.subplots(figsize=(14, 6))
    sns.barplot(data=proof, x="workload", y="serialized_proof_bytes", hue="prover", ax=axis_proof)
    axis_proof.set_yscale("log")
    axis_proof.set_title("Serialized proof size (log scale)")
    axis_proof.set_ylabel("Bytes")
    axis_proof.tick_params(axis="x", rotation=25)
    figure_proof.tight_layout()
    figure_proof
    return


@app.cell
def _(measured, plt, sns):
    memory = measured.groupby(["target", "workload", "prover", "timing_mode"], as_index=False).agg(
        peak_process_rss_mib=("peak_memory_mib", "median")
    )
    figure_memory, axis_memory = plt.subplots(figsize=(14, 6))
    sns.barplot(data=memory, x="workload", y="peak_process_rss_mib", hue="prover", ax=axis_memory)
    axis_memory.set_title("Median peak benchmark-process RSS")
    axis_memory.set_ylabel("MiB")
    axis_memory.tick_params(axis="x", rotation=25)
    figure_memory.tight_layout()
    figure_memory
    return


@app.cell
def _(mo):
    mo.md(r"""
    ## Takeaways

    Read performance comparisons within one workload, target, and timing mode.
    Passport P1 is the exact additional source pair. Historical Passport and
    WebAuthn remain closest-analogue comparisons, and OPRF is the aligned O2
    nullifier statement. Do not turn cross-workload bar heights into a generic
    proof-system ranking.
    """)
    return


if __name__ == "__main__":
    app.run()
