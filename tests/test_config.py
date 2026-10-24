"""Unit tests for configuration and path resolution."""

import os
from pathlib import Path
import pytest

from code.config import AppConfig


def test_default_config_resolution():
    """Verify that default paths resolve relative to repository root."""
    cfg = AppConfig()
    assert cfg.base_dir.is_dir()
    assert (cfg.base_dir / "code").is_dir()
    assert cfg.dataset_dir == cfg.base_dir / "dataset"
    assert cfg.output_path == cfg.base_dir / "output.csv"
    assert cfg.reports_dir == cfg.base_dir / "reports"
    assert cfg.evaluation_dir == cfg.base_dir / "code" / "evaluation"


def test_env_var_override(monkeypatch, tmp_path):
    """Verify that environment variables override default dataset and output paths."""
    custom_dataset = tmp_path / "custom_data"
    custom_output = tmp_path / "custom_out.csv"

    monkeypatch.setenv("DATASET_DIR", str(custom_dataset))
    monkeypatch.setenv("OUTPUT_PATH", str(custom_output))

    cfg = AppConfig()
    assert cfg.dataset_dir == custom_dataset.resolve()
    assert cfg.output_path == custom_output.resolve()


def test_validate_inputs_missing_directory(tmp_path):
    """Verify actionable error when dataset directory does not exist."""
    cfg = AppConfig()
    cfg.dataset_dir = tmp_path / "non_existent_dir"

    is_valid, errors = cfg.validate_inputs()
    assert not is_valid
    assert len(errors) == 1
    assert "Dataset directory not found" in errors[0]


def test_validate_inputs_missing_required_file(tmp_path):
    """Verify actionable error when a specific required dataset file is missing."""
    dataset_dir = tmp_path / "dataset"
    dataset_dir.mkdir()
    evidence_dir = dataset_dir / "evidence"
    evidence_dir.mkdir()

    cfg = AppConfig()
    cfg.dataset_dir = dataset_dir

    is_valid, errors = cfg.validate_inputs(use_sample=True)
    assert not is_valid
    # Multiple required files are missing
    assert any("Deletion rules" in err for err in errors)
    assert any("Sample deletion requests" in err for err in errors)


def test_validate_inputs_sample_success():
    """Verify input validation succeeds on existing dataset."""
    cfg = AppConfig()
    if cfg.dataset_dir.is_dir() and (cfg.dataset_dir / "sample_deletion_requests.csv").is_file():
        is_valid, errors = cfg.validate_inputs(use_sample=True)
        assert is_valid
        assert len(errors) == 0
