import statistics
import unittest
from pathlib import Path

import pandas as pd


class InputToProofAnalysisTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.csv_path = (
            Path(__file__).resolve().parents[1]
            / "input-to-proof-data"
            / "input-to-proof-samples.csv"
        )
        cls.samples = pd.read_csv(cls.csv_path, keep_default_na=False)

    def test_mac_has_four_workloads_three_stacks_and_both_modes(self):
        mac = self.samples[self.samples["hardware"] == "macbook_m4"]
        series = mac[["circuit", "prover", "timing_mode"]].drop_duplicates()
        self.assertEqual(len(series), 24)
        self.assertEqual(mac["circuit"].nunique(), 4)
        self.assertEqual(mac["prover"].nunique(), 3)
        self.assertEqual(set(mac["timing_mode"]), {"cold_local", "warm_reuse"})

    def test_each_completed_series_has_one_warmup_and_five_measurements(self):
        for identity, records in self.samples[self.samples["status"] == "ok"].groupby(
            ["hardware", "circuit", "prover", "timing_mode"]
        ):
            with self.subTest(identity=identity):
                self.assertEqual((records["sample_kind"] == "warmup").sum(), 1)
                self.assertEqual((records["sample_kind"] == "measured").sum(), 5)

    def test_measured_headline_medians_match_independent_statistics(self):
        measured = self.samples[
            (self.samples["status"] == "ok")
            & (self.samples["sample_kind"] == "measured")
        ].copy()
        measured["input_to_proof_time_ms"] = pd.to_numeric(
            measured["input_to_proof_time_ms"], errors="raise"
        )
        identity, records = next(
            iter(measured.groupby(["hardware", "circuit", "prover", "timing_mode"]))
        )
        values = records["input_to_proof_time_ms"].tolist()
        self.assertEqual(records["input_to_proof_time_ms"].median(), statistics.median(values), identity)

    def test_notebook_names_headline_and_four_payload_metrics(self):
        source = Path(__file__).with_name("input_to_proof_analysis.py").read_text()
        for metric in [
            "input_to_proof_time_ms",
            "circuit_size_bytes",
            "proof_size_bytes",
            "peak_memory_mib",
        ]:
            with self.subTest(metric=metric):
                self.assertIn(metric, source)


if __name__ == "__main__":
    unittest.main()
