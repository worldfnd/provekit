import statistics
import unittest
from pathlib import Path

import pandas as pd


class BenchmarkAnalysisTest(unittest.TestCase):
    def test_fixture_medians_match_independent_statistics(self):
        fixture = pd.DataFrame(
            [
                {"variant": "a", "sample_kind": "warmup", "prover_time_ms": 99},
                {"variant": "a", "sample_kind": "measured", "prover_time_ms": 1},
                {"variant": "a", "sample_kind": "measured", "prover_time_ms": 9},
                {"variant": "a", "sample_kind": "measured", "prover_time_ms": 3},
                {"variant": "a", "sample_kind": "measured", "prover_time_ms": 7},
                {"variant": "a", "sample_kind": "measured", "prover_time_ms": 5},
            ]
        )
        measured = fixture[fixture["sample_kind"] == "measured"]
        notebook_median = measured.groupby("variant")["prover_time_ms"].median().loc["a"]
        independent_median = statistics.median(
            measured.loc[measured["variant"] == "a", "prover_time_ms"].tolist()
        )
        self.assertEqual(notebook_median, independent_median)
        self.assertEqual(notebook_median, 5)

    def test_canonical_csv_has_27_cells_and_complete_successful_variants(self):
        csv_path = Path(__file__).resolve().parents[1] / "semantic-parity-data" / "semantic-parity-samples.csv"
        samples = pd.read_csv(csv_path, keep_default_na=False)
        cells = samples[["hardware", "circuit", "prover"]].drop_duplicates()
        self.assertEqual(len(cells), 27)

        successful = samples[samples["status"] == "ok"]
        variants = successful.groupby(
            ["hardware", "circuit", "prover", "circuit_variant"]
        )
        for identity, records in variants:
            with self.subTest(identity=identity):
                self.assertEqual((records["sample_kind"] == "warmup").sum(), 1)
                self.assertEqual((records["sample_kind"] == "measured").sum(), 5)

    def test_successful_measured_rows_have_all_four_publication_metrics(self):
        csv_path = Path(__file__).resolve().parents[1] / "semantic-parity-data" / "semantic-parity-samples.csv"
        samples = pd.read_csv(csv_path, keep_default_na=False)
        measured = samples[
            (samples["status"] == "ok") & (samples["sample_kind"] == "measured")
        ]
        metric_columns = [
            "prover_time_ms",
            "artifact_size_bytes",
            "proof_size_bytes",
            "peak_memory_mib",
        ]
        numeric_metrics = measured[metric_columns].apply(pd.to_numeric, errors="coerce")
        self.assertFalse(numeric_metrics.isna().any().any())
        self.assertTrue((numeric_metrics > 0).all().all())

    def test_notebook_names_all_four_publication_metrics(self):
        notebook_path = Path(__file__).with_name("benchmark_analysis.py")
        notebook_source = notebook_path.read_text()
        for metric in [
            "prover_time_ms",
            "artifact_size_bytes",
            "proof_size_bytes",
            "peak_memory_mib",
        ]:
            with self.subTest(metric=metric):
                self.assertIn(metric, notebook_source)


if __name__ == "__main__":
    unittest.main()
