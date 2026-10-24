"""Application entry point and CLI orchestration for Ghost Data Still Exists.

Entry point for running deletion audits, verifying inputs, or validating
generated output files against the official competition specification.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from code.config import AppConfig
from code.output import validate_output_file


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

    print(f"[*] Configuration verified.")
    print(f"    Dataset path: {cfg.dataset_dir}")
    print(f"    Target output: {cfg.output_path}")
    print(f"    Mode: {'Sample (32 requests)' if args.sample else 'Full Evaluation (518 requests)'}")

    if args.dry_run:
        print("[*] Dry run complete. All required input files are present and verified.")
        return 0

    # Note: Full agent orchestration pipeline will be connected in Phase 2
    print("[INFO] Foundation initialized. Complete agent pipeline implementation will occur in the next phase.")
    print("       To validate existing files, run: python -m code.main --validate-only <path>")
    return 0


if __name__ == "__main__":
    sys.exit(main())
