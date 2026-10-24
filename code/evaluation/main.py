"""Evaluation CLI entry point for Ghost Data Still Exists deletion audit agent.

Calculates:
- Case-level deletion_status accuracy.
- Step-level field matching accuracy (phase, system_id, resource_id, operation, state, evidence_id).
- Step sequence and ordering accuracy.
- Generates Markdown reports conforming to official submission guidelines.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from code.config import AppConfig
from code.output import validate_output_file


@dataclass
class EvaluationMetrics:
    """Summary metrics of evaluation comparing predictions to ground truth."""
    total_cases: int = 0
    correct_status_cases: int = 0
    total_expected_steps: int = 0
    total_predicted_steps: int = 0
    exact_match_cases: int = 0
    step_field_matches: Dict[str, int] = field(default_factory=lambda: {
        "phase": 0,
        "system_id": 0,
        "resource_id": 0,
        "operation": 0,
        "state": 0,
        "evidence_id": 0,
    })

    @property
    def status_accuracy(self) -> float:
        return (self.correct_status_cases / self.total_cases * 100.0) if self.total_cases > 0 else 0.0

    @property
    def exact_case_accuracy(self) -> float:
        return (self.exact_match_cases / self.total_cases * 100.0) if self.total_cases > 0 else 0.0


def load_csv_cases(file_path: Path) -> Dict[str, Tuple[str, List[Dict[str, Any]]]]:
    """Load case rows from a CSV file into a mapping of case_id -> (status, steps)."""
    cases: Dict[str, Tuple[str, List[Dict[str, Any]]]] = {}
    with open(file_path, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader, None)
        for row in reader:
            if len(row) < 3:
                continue
            case_id, status, steps_raw = row[0], row[1], row[2]
            try:
                steps = json.loads(steps_raw)
            except Exception:
                steps = []
            cases[case_id] = (status, steps)
    return cases


def evaluate_predictions(
    predictions_path: Path,
    ground_truth_path: Path,
    case_filter: Optional[str] = None,
) -> Tuple[EvaluationMetrics, List[str]]:
    """Compare prediction CSV against ground truth CSV."""
    details: List[str] = []
    metrics = EvaluationMetrics()

    pred_cases = load_csv_cases(predictions_path)
    truth_cases = load_csv_cases(ground_truth_path)

    case_ids = [case_filter] if case_filter else sorted(truth_cases.keys())

    for cid in case_ids:
        if cid not in truth_cases:
            details.append(f"Case '{cid}' not found in ground truth.")
            continue
        if cid not in pred_cases:
            details.append(f"Case '{cid}' missing in predictions.")
            metrics.total_cases += 1
            continue

        metrics.total_cases += 1
        t_status, t_steps = truth_cases[cid]
        p_status, p_steps = pred_cases[cid]

        status_ok = (t_status == p_status)
        if status_ok:
            metrics.correct_status_cases += 1
        else:
            details.append(f"Case '{cid}': status mismatch. Expected '{t_status}', got '{p_status}'.")

        metrics.total_expected_steps += len(t_steps)
        metrics.total_predicted_steps += len(p_steps)

        # Step comparison
        steps_match = True
        if len(t_steps) != len(p_steps):
            steps_match = False
            details.append(f"Case '{cid}': step count mismatch. Expected {len(t_steps)}, got {len(p_steps)}.")

        # Check matched steps up to minimum length
        for i in range(min(len(t_steps), len(p_steps))):
            ts = t_steps[i]
            ps = p_steps[i]

            for key in ["phase", "system_id", "resource_id", "operation", "state", "evidence_id"]:
                if ts.get(key) == ps.get(key):
                    metrics.step_field_matches[key] += 1
                else:
                    steps_match = False

        if status_ok and steps_match and len(t_steps) == len(p_steps):
            metrics.exact_match_cases += 1

    return metrics, details


def generate_markdown_report(metrics: EvaluationMetrics, details: List[str], output_path: Path) -> None:
    """Generate a clean Markdown evaluation report."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    report_content = [
        "# Evaluation Report — Ghost Data Still Exists",
        "",
        "## Summary Metrics",
        "",
        f"- **Total Cases Evaluated:** {metrics.total_cases}",
        f"- **Status Accuracy:** {metrics.status_accuracy:.2f}% ({metrics.correct_status_cases}/{metrics.total_cases})",
        f"- **Exact Case Match Accuracy:** {metrics.exact_case_accuracy:.2f}% ({metrics.exact_match_cases}/{metrics.total_cases})",
        f"- **Expected Total Steps:** {metrics.total_expected_steps}",
        f"- **Predicted Total Steps:** {metrics.total_predicted_steps}",
        "",
        "## Field-Level Accuracy",
        "",
        "| Field | Correct Matches | Total Expected | Accuracy |",
        "| --- | --- | --- | --- |",
    ]

    total_exp = max(metrics.total_expected_steps, 1)
    for field_name, count in metrics.step_field_matches.items():
        acc = (count / total_exp) * 100.0
        report_content.append(f"| `{field_name}` | {count} | {total_exp} | {acc:.2f}% |")

    report_content.extend([
        "",
        "## Discrepancies and Findings",
        "",
    ])

    if not details:
        report_content.append("No discrepancies found. 100% agreement with ground truth.")
    else:
        for d in details[:50]:
            report_content.append(f"- {d}")
        if len(details) > 50:
            report_content.append(f"- ... and {len(details) - 50} more discrepancies.")

    output_path.write_text("\n".join(report_content), encoding="utf-8")


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse CLI options for evaluation."""
    parser = argparse.ArgumentParser(
        prog="python -m code.evaluation.main",
        description="Ghost Data Still Exists — Evaluation and Metrics CLI",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "--predictions",
        type=Path,
        required=True,
        help="Path to prediction CSV file to evaluate",
    )
    parser.add_argument(
        "--truth",
        type=Path,
        default=None,
        help="Path to ground truth CSV (defaults to dataset/sample_output.csv)",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=None,
        help="Path to output Markdown report (e.g. code/evaluation/evaluation_report.md)",
    )
    parser.add_argument(
        "--case-id",
        type=str,
        default=None,
        help="Optional case ID filter to evaluate a single case",
    )

    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    """Evaluation CLI orchestrator."""
    args = parse_args(argv)

    pred_path = args.predictions.resolve()
    if not pred_path.is_file():
        print(f"[ERROR] Predictions file not found: '{pred_path}'", file=sys.stderr)
        return 1

    # First validate schema of predictions
    is_valid_schema, schema_issues = validate_output_file(pred_path)
    if not is_valid_schema:
        print(f"[ERROR] Predictions file failed schema validation ({len(schema_issues)} issues):", file=sys.stderr)
        for issue in schema_issues[:10]:
            print(f"  - {issue}", file=sys.stderr)
        return 1

    cfg = AppConfig()
    truth_path = args.truth.resolve() if args.truth else cfg.sample_output_path

    if not truth_path.is_file():
        print(f"[ERROR] Ground truth file not found: '{truth_path}'", file=sys.stderr)
        return 1

    print(f"[*] Evaluating predictions: '{pred_path}'")
    print(f"[*] Using ground truth:   '{truth_path}'")

    metrics, details = evaluate_predictions(pred_path, truth_path, case_filter=args.case_id)

    print("\n--- Evaluation Results ---")
    print(f"Cases Evaluated:      {metrics.total_cases}")
    print(f"Status Accuracy:      {metrics.status_accuracy:.2f}% ({metrics.correct_status_cases}/{metrics.total_cases})")
    print(f"Exact Case Matches:   {metrics.exact_case_accuracy:.2f}% ({metrics.exact_match_cases}/{metrics.total_cases})")

    if args.report:
        report_path = args.report.resolve()
        generate_markdown_report(metrics, details, report_path)
        print(f"\n[SUCCESS] Markdown evaluation report saved to: '{report_path}'")

    return 0


if __name__ == "__main__":
    sys.exit(main())
