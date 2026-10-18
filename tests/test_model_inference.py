import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from python_core.model_inference import analyze_feature_json, infer_threat


def feature_document(file_path: str) -> dict[str, object]:
    return {
        "schema_version": 1,
        "file_path": file_path,
        "architecture": "PE32+",
        "sections": [{"name": ".text", "entropy": 5.0}],
        "imports": [],
    }


class InferThreatTests(unittest.TestCase):
    def test_returns_zero_for_unremarkable_features(self):
        self.assertEqual(infer_threat([".text"], [], [5.0]), 0.0)

    def test_scores_known_import_and_high_entropy(self):
        score = infer_threat(
            [".text", ".upx"], ["KERNEL32.dll", "CreateRemoteThread"], [7.8, 7.5]
        )
        self.assertGreater(score, 0.0)
        self.assertLessEqual(score, 1.0)

    def test_rejects_mismatched_feature_counts(self):
        with self.assertRaises(ValueError):
            infer_threat([".text"], [], [])

    def test_rejects_invalid_entropy(self):
        with self.assertRaises(ValueError):
            infer_threat([".text"], [], [float("nan")])

    def test_validates_and_analyzes_json_contract(self):
        with TemporaryDirectory() as directory:
            sample = Path(directory) / "sample.exe"
            sample.write_bytes(b"MZsample")
            response = json.loads(
                analyze_feature_json(json.dumps(feature_document(str(sample))))
            )
            self.assertEqual(response["risk_score"], 0.0)
            self.assertEqual(response["yara_matches"], [])

    def test_rejects_invalid_json_contract(self):
        document = feature_document("sample.exe")
        document["unexpected"] = True
        with self.assertRaises(ValueError):
            analyze_feature_json(json.dumps(document))

    def test_uses_explicit_yara_rules_file(self):
        with TemporaryDirectory() as directory:
            sample = Path(directory) / "sample.exe"
            rules = Path(directory) / "test.yar"
            sample.write_bytes(b"MZsample")
            rules.write_text(
                'rule ChimeraTest { strings: $mz = "MZ" condition: $mz at 0 }',
                encoding="utf-8",
            )
            response = json.loads(
                analyze_feature_json(
                    json.dumps(feature_document(str(sample))), str(rules)
                )
            )
            self.assertEqual(response["yara_matches"][0]["rule"], "ChimeraTest")


if __name__ == "__main__":
    unittest.main()
