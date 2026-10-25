"""Application entry point and CLI orchestration for Ghost Data Still Exists.

Entry point for running deletion audits, verifying inputs, or validating
generated output files against the official competition specification.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import List, Optional, Tuple

import pandas as pd

from code.config import AppConfig
from code.evidence import EvidenceCorpus
from code.identity import IdentityGraph
from code.models import CaseAuditResult
from code.output import validate_output_file, write_output_csv
from code.planner import plan_case
from code.policy import PolicyEngine


def parse_args(args: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        prog="python -m code.main",
        description="Ghost Data Still Exists — AI-Powered Deletion Audit Agent CLI",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "--dataset-dir",
        type=Path,
        default=None,
        help="Path to dataset directory (defaults to repository root 'dataset/')",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Path for final output.csv (defaults to repository root 'output.csv')",
    )
    parser.add_argument(
        "--sample",
        action="store_true",
        help="Run audit against sample requests (sample_deletion_requests.csv) instead of full dataset",
    )
    parser.add_argument(
        "--validate-only",
        type=Path,
        metavar="PATH",
        help="Validate an existing output CSV file against the official specification schema and exit",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Verify configuration and dataset input files without performing audit execution",
    )

    return parser.parse_args(args)


def run_validate_only(output_path: Path, expected_cases: Optional[int] = None) -> int:
    """Validate an existing output CSV and print detailed report."""
    print(f"[*] Validating output file: {output_path}")
    is_valid, issues = validate_output_file(output_path, expected_case_count=expected_cases)

    if is_valid:
        print("[SUCCESS] Output file is fully compliant with the official competition schema!")
        return 0

    print(f"[FAIL] Found {len(issues)} validation issues:")
    for issue in issues[:25]:  # Display first 25 issues
        print(f"  - {issue}")
    if len(issues) > 25:
        print(f"  ... and {len(issues) - 25} more issues.")
    return 1


def run_audit_pipeline(
    cfg: AppConfig,
    use_sample: bool = False,
    output_path: Optional[Path] = None,
) -> Tuple[Path, float, int]:
    """Execute end-to-end deletion audit pipeline."""
    start_time = time.time()
    target_output = output_path or cfg.output_path

    print("[*] Ingesting identity graph...")
    u_df = pd.read_csv(cfg.user_identities_path)
    a_df = pd.read_csv(cfg.user_audit_log_path)
    graph = IdentityGraph(u_df, a_df)

    print("[*] Ingesting and indexing evidence corpus...")
    corpus = EvidenceCorpus(
        cfg.evidence_dir,
        cfg.evidence_files_path,
        cfg.system_activity_path,
        cfg.user_audit_log_path,
    ).build_index()

    print("[*] Initializing statutory policy engine...")
    engine = PolicyEngine(cfg.deletion_rules_path)

    req_path = cfg.sample_deletion_requests_path if use_sample else cfg.deletion_requests_path
    print(f"[*] Loading deletion requests from: {req_path}")
    req_df = pd.read_csv(req_path)

    total_cases = len(req_df)
    print(f"[*] Processing {total_cases} deletion audit cases...")

    results: List[CaseAuditResult] = []
    for _, row in req_df.iterrows():
        cid = str(row["case_id"])
        email = str(row["email"]) if pd.notna(row["email"]) else None
        audit_at = str(row["audit_at"]) if pd.notna(row["audit_at"]) else None
        req_text = str(row["request_text"]) if pd.notna(row["request_text"]) else None

        subj = graph.resolve(cid, email, audit_at)
        items = corpus.get_subject_evidence(subj, audit_at)
        eval_res = engine.evaluate_case(cid, req_text, subj, items)
        planned = plan_case(eval_res)
        results.append(planned)

    print(f"[*] Serializing and writing output to: {target_output}")
    write_output_csv(results, target_output)

    duration = time.time() - start_time
    per_case_ms = (duration / total_cases * 1000) if total_cases > 0 else 0
    print(f"[SUCCESS] Audit pipeline completed in {duration:.2f}s ({per_case_ms:.1f}ms/case)")
    return target_output, duration, total_cases


def main(argv: Optional[List[str]] = None) -> int:
    """CLI execution orchestrator."""
    args = parse_args(argv)

    # Initialize configuration
    cfg = AppConfig()
    if args.dataset_dir:
        cfg.dataset_dir = args.dataset_dir.resolve()
    if args.output:
        cfg.output_path = args.output.resolve()

    # Mode 1: Validation only
    if args.validate_only:
        expected = 32 if args.sample else (518 if not args.sample else None)
        return run_validate_only(args.validate_only, expected_cases=None)

    # Mode 2: Verify inputs and environment
    is_valid, missing_errors = cfg.validate_inputs(use_sample=args.sample)
    if not is_valid:
        print("[ERROR] Input verification failed with actionable errors:", file=sys.stderr)
        for err in missing_errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print("[*] Configuration verified.")
    print(f"    Dataset path: {cfg.dataset_dir}")
    print(f"    Target output: {cfg.output_path}")
    print(f"    Mode: {'Sample (32 requests)' if args.sample else 'Full Evaluation (518 requests)'}")

    if args.dry_run:
        print("[*] Dry run complete. All required input files are present and verified.")
        return 0

    # Mode 3: Execute audit pipeline
    target_output, duration, count = run_audit_pipeline(
        cfg,
        use_sample=args.sample,
        output_path=args.output,
    )

    # Mode 4: Validate generated output against competition rules
    expected_count = 32 if args.sample else 518
    return run_validate_only(target_output, expected_cases=expected_count)


if __name__ == "__main__":
    sys.exit(main())
