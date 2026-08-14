"""Historical Marimo analysis for the proof-only semantic-parity export.

Run from the repository root:
    marimo edit benchmarks/v1/analysis/benchmark_analysis.py
or:
    marimo run benchmarks/v1/analysis/benchmark_analysis.py
"""

import marimo

__generated_with = "0.23.15"
app = marimo.App(width="medium")


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
    # Historical semantic-parity benchmark

    ## tl;dr

    This notebook reads only the legacy proof-only semantic-parity CSV.
    Completed charts use measured samples, never warmups or gaps. Missing and
    failed cells remain visible rather than being converted to zeros.
    """)
    return


@app.cell
def _(Path, pd):
    csv_path = Path(__file__).resolve().parents[1] / "legacy" / "semantic-parity" / "semantic-parity-samples.csv"
    samples = pd.read_csv(csv_path, keep_default_na=False)

    numeric_columns = [
        "sample_index",
        "witness_time_ms",
        "prover_time_ms",
        "verify_time_ms",
        "total_time_ms",
        "peak_memory_mib",
        "proof_size_bytes",
        "artifact_size_bytes",
    ]
    for numeric_column in numeric_columns:
        samples[numeric_column] = pd.to_numeric(samples[numeric_column], errors="coerce")

    expected_hardware = ["iphone_se_2022", "motorola_e15", "macbook_m4"]
    expected_circuits = ["oprf", "passport", "webauthn"]
    expected_provers = ["provekit_v1", "noir_barretenberg", "circom_groth16"]
    expected_cells = pd.MultiIndex.from_product(
        [expected_hardware, expected_circuits, expected_provers],
        names=["hardware", "circuit", "prover"],
    ).to_frame(index=False)
    return csv_path, expected_cells, expected_hardware, samples


@app.cell
def _(csv_path, mo):
    mo.md(
        f"""
        ## Context & Methods

        Source: `{csv_path}`

        ### Key Assumptions

        - The target surfaces are iPhone native, Motorola native, and M4 Mac browser/WASM.
        - OPRF, Passport, and WebAuthn counterparts are the closest available workloads,
          not statement-equivalent circuits.
        - Each successful cell requires one discarded warmup and five measured samples.
        - Blank metrics indicate missing evidence. A numeric zero is treated as a measurement.
        - Circom witness and Groth16 proving phases are reported separately.
        """
    )
    return


@app.cell
def _(expected_cells, pd, samples):
    if samples.empty:
        observed_cells = pd.DataFrame(
            columns=[
                "hardware",
                "circuit",
                "prover",
                "cell_status",
                "measured_samples",
                "coverage_ok",
            ]
        )
    else:
        observed_variants = (
            samples.groupby(["hardware", "circuit", "prover"], as_index=False)
            .agg(
                cell_status=("status", lambda values: "ok" if (values == "ok").all() else values.iloc[0]),
                measured_samples=("sample_kind", lambda values: int((values == "measured").sum())),
                warmups=("sample_kind", lambda values: int((values == "warmup").sum())),
            )
        )
        successful_variants = samples[samples["status"] == "ok"].groupby(
            ["hardware", "circuit", "prover", "circuit_variant"], as_index=False
        ).agg(
            measured_samples=("sample_kind", lambda values: int((values == "measured").sum())),
            warmups=("sample_kind", lambda values: int((values == "warmup").sum())),
        )
        successful_variants["variant_coverage_ok"] = (
            (successful_variants["measured_samples"] == 5)
            & (successful_variants["warmups"] == 1)
        )
        successful_cells = successful_variants.groupby(
            ["hardware", "circuit", "prover"], as_index=False
        ).agg(coverage_ok=("variant_coverage_ok", "all"))
        observed_cells = observed_variants.merge(
            successful_cells,
            on=["hardware", "circuit", "prover"],
            how="left",
        )
        observed_cells["coverage_ok"] = (
            observed_cells["coverage_ok"].map(lambda value: value is True)
            & (observed_cells["cell_status"] == "ok")
        )

    coverage = expected_cells.merge(
        observed_cells,
        on=["hardware", "circuit", "prover"],
        how="left",
    )
    coverage["cell_status"] = coverage["cell_status"].fillna("missing")
    coverage["measured_samples"] = coverage["measured_samples"].fillna(0).astype(int)
    coverage["coverage_ok"] = coverage["coverage_ok"].map(lambda value: value is True)
    return (coverage,)


@app.cell
def _(coverage, mo, samples):
    complete_cells = int(coverage["coverage_ok"].sum())
    gap_cells = int((coverage["cell_status"] != "ok").sum())
    measured_attempts = int((samples["sample_kind"] == "measured").sum()) if not samples.empty else 0
    mo.md(
        f"""
        ## Data

        - Complete cells: **{complete_cells} / 27**
        - Missing or failed cells: **{gap_cells}**
        - Measured attempts retained: **{measured_attempts}**
        """
    )
    return


@app.cell
def _(coverage, expected_hardware, plt, sns):
    status_order = [
        "ok",
        "unsupported",
        "build_failed",
        "crashed",
        "runtime_failed",
        "timed_out",
        "zero_samples",
        "not_run",
        "missing",
    ]
    status_codes = {status: index for index, status in enumerate(status_order)}
    coverage_plot = coverage.copy()
    coverage_plot["workload"] = coverage_plot["circuit"] + " · " + coverage_plot["prover"]
    coverage_plot["status_code"] = coverage_plot["cell_status"].map(status_codes)
    coverage_matrix = coverage_plot.pivot(
        index="workload", columns="hardware", values="status_code"
    ).reindex(columns=expected_hardware)

    coverage_annotations = coverage_plot.pivot(
        index="workload", columns="hardware", values="cell_status"
    ).reindex(columns=expected_hardware)

    figure_coverage, axis_coverage = plt.subplots(figsize=(10, 6))
    sns.heatmap(
        coverage_matrix,
        annot=coverage_annotations,
        fmt="",
        cmap=sns.color_palette(
            [
                "#2e7d32",
                "#f9a825",
                "#ef6c00",
                "#b71c1c",
                "#c62828",
                "#8e24aa",
                "#6a1b9a",
                "#607d8b",
                "#eceff1",
            ],
            as_cmap=True,
        ),
        vmin=0,
        vmax=len(status_order) - 1,
        cbar=False,
        linewidths=0.5,
        linecolor="white",
        ax=axis_coverage,
    )
    axis_coverage.set_title("Coverage status for all 27 expected cells")
    axis_coverage.set_xlabel("Target hardware/runtime")
    axis_coverage.set_ylabel("Closest circuit counterpart · prover")
    figure_coverage.tight_layout()
    figure_coverage
    return


@app.cell
def _(mo):
    mo.md(r"""
    ## Results

    The following views cover the four publication metrics: proving time, exact
    proving payload size, serialized proof size, and peak process memory.
    Completed bars use measured samples only. Absent bars are missing evidence,
    not zero-size or zero-time proofs.
    """)
    return


@app.cell
def _(plt, samples, sns):
    measured = samples[
        (samples["status"] == "ok") & (samples["sample_kind"] == "measured")
    ].copy()
    measured["workload_variant"] = (
        measured["circuit"] + " · " + measured["circuit_variant"]
    )
    if measured.empty:
        figure_latency, axis_latency = plt.subplots(figsize=(10, 4))
        axis_latency.text(
            0.5,
            0.5,
            "No measured samples yet",
            ha="center",
            va="center",
            transform=axis_latency.transAxes,
        )
        axis_latency.set_axis_off()
    else:
        latency_summary = (
            measured.groupby(
                ["hardware", "circuit", "circuit_variant", "workload_variant", "prover"],
                as_index=False,
            )
            .agg(
                median_prover_ms=("prover_time_ms", "median"),
                min_prover_ms=("prover_time_ms", "min"),
                max_prover_ms=("prover_time_ms", "max"),
                samples=("prover_time_ms", "count"),
            )
        )
        figure_latency = sns.catplot(
            data=latency_summary,
            kind="bar",
            x="workload_variant",
            y="median_prover_ms",
            hue="prover",
            col="hardware",
            col_wrap=1,
            height=3.1,
            aspect=2.8,
            sharey=False,
        ).figure
        figure_latency.suptitle("Median measured prover time by circuit and target", y=1.01)
        for axis in figure_latency.axes:
            axis.tick_params(axis="x", rotation=25)
        figure_latency.tight_layout()
    figure_latency
    return (measured,)


@app.cell
def _(mo):
    mo.md(r"""
    ### Proving payload, proof size, and peak process memory

    `artifact_size_bytes` is the exact deduplicated set of inputs needed by the
    prover for that lane; it is not an IPA, APK, or browser upload size. Proof
    size is the serialized proof emitted by the adapter. Peak memory is process
    RSS where the target exposes it.

    The coverage heatmap remains authoritative for missing and failed cells.
    An absent bar below means that no successful native/browser measurement
    exists. Workload variants are the closest available counterparts and are
    not apples-to-apples cryptographic statements.
    """)
    return


@app.cell
def _(measured, mo, pd, sns):
    footprint_frames = [
        measured.assign(
            metric="Exact proving payload (MiB)",
            metric_value=measured["artifact_size_bytes"] / (1024**2),
        ),
        measured.assign(
            metric="Serialized proof size (KiB)",
            metric_value=measured["proof_size_bytes"] / 1024,
        ),
        measured.assign(
            metric="Peak process memory (MiB)",
            metric_value=measured["peak_memory_mib"],
        ),
    ]
    footprint_long = pd.concat(footprint_frames, ignore_index=True).dropna(
        subset=["metric_value"]
    )
    metric_order = [
        "Exact proving payload (MiB)",
        "Serialized proof size (KiB)",
        "Peak process memory (MiB)",
    ]

    if footprint_long.empty:
        footprint_view = mo.md(
            "No proving-payload, proof-size, or peak-memory measurements are available."
        )
    else:
        footprint_grid = sns.catplot(
            data=footprint_long,
            kind="bar",
            x="workload_variant",
            y="metric_value",
            hue="prover",
            col="hardware",
            row="metric",
            row_order=metric_order,
            estimator="median",
            errorbar=("pi", 100),
            sharex=False,
            sharey=False,
            height=3.0,
            aspect=1.55,
        )
        footprint_grid.set_axis_labels("Closest circuit counterpart", "")
        footprint_grid.set_titles(row_template="{row_name}", col_template="{col_name}")
        footprint_grid.figure.suptitle(
            "Measured proof footprint by closest non-equivalent counterpart",
            y=1.01,
        )
        for footprint_axis in footprint_grid.axes.flat:
            footprint_axis.tick_params(axis="x", rotation=30)
        footprint_grid.figure.tight_layout()
        footprint_view = footprint_grid.figure
    footprint_view
    return


@app.cell
def _(mo):
    mo.md(r"""
    ### Circom phase separation

    This chart applies only to Circom rows. Witness generation and Groth16
    proving are separate phases. Browser `snarkjs.fullProve` observations must
    be instrumented around witness calculation and proving before they can
    populate both columns; a single combined duration must stay in
    `total_time_ms`.
    """)
    return


@app.cell
def _(measured, plt, sns):
    circom_measured = measured[measured["prover"] == "circom_groth16"].copy()
    phase_long = circom_measured.melt(
        id_vars=["hardware", "circuit", "circuit_variant", "workload_variant", "attempt_id"],
        value_vars=["witness_time_ms", "prover_time_ms"],
        var_name="phase",
        value_name="time_ms",
    ).dropna(subset=["time_ms"])

    figure_phases, axis_phases = plt.subplots(figsize=(10, 4))
    if phase_long.empty:
        axis_phases.text(
            0.5,
            0.5,
            "No separately timed Circom phases yet",
            ha="center",
            va="center",
            transform=axis_phases.transAxes,
        )
        axis_phases.set_axis_off()
    else:
        sns.barplot(
            data=phase_long,
            x="workload_variant",
            y="time_ms",
            hue="phase",
            estimator="median",
            errorbar=("pi", 100),
            ax=axis_phases,
        )
    axis_phases.set_title("Circom witness and Groth16 prover time")
    axis_phases.set_ylabel("Median time (ms), with observed range")
    axis_phases.set_xlabel("Closest circuit counterpart")
    axis_phases.tick_params(axis="x", rotation=25)
    figure_phases.tight_layout()
    figure_phases
    return


@app.cell
def _(mo, samples):
    notes = (
        samples.loc[samples["non_equivalence_note"] != "", ["circuit", "prover", "non_equivalence_note"]]
        .drop_duplicates()
        .sort_values(["circuit", "prover"])
    )
    mo.md("## Takeaways\n\n### Non-equivalence notes")
    return (notes,)


@app.cell
def _(mo, notes):
    mo.ui.table(notes, selection=None, pagination=True, page_size=12)
    return


@app.cell
def _(coverage, mo):
    missing_table = coverage.loc[
        coverage["cell_status"] != "ok",
        ["hardware", "circuit", "prover", "cell_status", "measured_samples"],
    ]
    mo.md(
        """
        ### Missing and failed cells

        These cells stay in the analysis and must be explained before publication.
        """
    )
    return (missing_table,)


@app.cell
def _(missing_table, mo):
    mo.ui.table(missing_table, selection=None, pagination=True, page_size=15)
    return


if __name__ == "__main__":
    app.run()
