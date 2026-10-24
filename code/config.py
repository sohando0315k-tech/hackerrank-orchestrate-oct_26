"""Project configuration and path resolution for Ghost Data Still Exists.

Ensures dynamic, portable path resolution across Windows, macOS, and Linux
without relying on hardcoded absolute paths.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple


@dataclass
class AppConfig:
    """Application configuration and path registry."""
    # Root directory is two levels up from this file (repo root)
    base_dir: Path = field(default_factory=lambda: Path(__file__).resolve().parent.parent)
    dataset_dir: Path = field(init=False)
    output_path: Path = field(init=False)
    reports_dir: Path = field(init=False)
    evaluation_dir: Path = field(init=False)

    def __post_init__(self) -> None:
        # Allow environment variable override, defaulting to standard locations
        env_dataset = os.getenv("DATASET_DIR")
        self.dataset_dir = Path(env_dataset).resolve() if env_dataset else self.base_dir / "dataset"

        env_output = os.getenv("OUTPUT_PATH")
        self.output_path = Path(env_output).resolve() if env_output else self.base_dir / "output.csv"

        self.reports_dir = self.base_dir / "reports"
        self.evaluation_dir = self.base_dir / "code" / "evaluation"

    # Specific dataset file paths
    @property
    def deletion_requests_path(self) -> Path:
        return self.dataset_dir / "deletion_requests.csv"

    @property
    def sample_deletion_requests_path(self) -> Path:
        return self.dataset_dir / "sample_deletion_requests.csv"

    @property
    def sample_output_path(self) -> Path:
        return self.dataset_dir / "sample_output.csv"

    @property
    def deletion_rules_path(self) -> Path:
        return self.dataset_dir / "deletion_rules.csv"

    @property
    def evidence_files_path(self) -> Path:
        return self.dataset_dir / "evidence_files.csv"

    @property
    def user_identities_path(self) -> Path:
        return self.dataset_dir / "user_identities.csv"

    @property
    def user_audit_log_path(self) -> Path:
        return self.dataset_dir / "user_audit_log.csv"

    @property
    def system_activity_path(self) -> Path:
        return self.dataset_dir / "system_activity.csv"

    @property
    def evidence_dir(self) -> Path:
        return self.dataset_dir / "evidence"

    def validate_inputs(self, use_sample: bool = False) -> Tuple[bool, List[str]]:
        """Validate presence of all required input files.

        Returns:
            Tuple of (all_present, list_of_error_messages)
        """
        errors: List[str] = []

        if not self.dataset_dir.exists():
            errors.append(
                f"Dataset directory not found at '{self.dataset_dir}'. "
                "Ensure dataset files are located at repository root 'dataset/' or configure DATASET_DIR."
            )
            return False, errors

        # Core required files for any run
        required_files = [
            ("Deletion rules", self.deletion_rules_path),
            ("User identities", self.user_identities_path),
            ("User audit log", self.user_audit_log_path),
            ("System activity log", self.system_activity_path),
            ("Evidence files manifest", self.evidence_files_path),
        ]

        if use_sample:
            required_files.append(("Sample deletion requests", self.sample_deletion_requests_path))
        else:
            required_files.append(("Deletion requests", self.deletion_requests_path))

        for name, path in required_files:
            if not path.is_file():
                errors.append(f"Missing required input file [{name}]: expected at '{path}'.")

        if not self.evidence_dir.is_dir():
            errors.append(f"Evidence corpus directory missing: expected at '{self.evidence_dir}'.")

        return (len(errors) == 0, errors)


# Global default configuration instance
config = AppConfig()
