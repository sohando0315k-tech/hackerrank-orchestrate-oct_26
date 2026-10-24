"""Unit tests for output serialization, schema enforcement, and validation."""

import csv
import json
from pathlib import Path
import pytest

from code.models import (
    AuditStep,
    CaseAuditResult,
    DeletionStatus,
    Operation,
    Phase,
    State,
)
from code.output import (
    serialize_steps,
    validate_output_file,
    write_output_csv,
)


def test_serialize_steps_empty_and_not_applicable():
    """Verify serialization of empty steps returns '[]'."""
    assert serialize_steps([]) == "[]"


def test_serialize_steps_valid():
    """Verify valid serialization of AuditStep instances."""
    step = AuditStep(
        step_no=1,
        phase=Phase.VERIFICATION,
        system_id="account_service",
        resource_id="account_001",
        operation=Operation.VERIFY_RECORD_ABSENT,
        state=State.ABSENT,
        evidence_id="evidence_54",
    )
    serialized = serialize_steps([step])
    parsed = json.loads(serialized)
    assert len(parsed) == 1
    assert parsed[0]["step_no"] == 1
    assert parsed[0]["phase"] == "VERIFICATION"
    assert parsed[0]["operation"] == "VERIFY_RECORD_ABSENT"
    assert parsed[0]["state"] == "ABSENT"
    assert parsed[0]["evidence_id"] == "evidence_54"


def test_write_and_validate_output_csv(tmp_path):
    """Verify writing CaseAuditResult instances and validating generated CSV."""
    out_file = tmp_path / "test_output.csv"

    results = [
        CaseAuditResult(
            case_id="case_001",
            deletion_status=DeletionStatus.COMPLETE,
            steps=[
                AuditStep(
                    step_no=1,
                    phase=Phase.VERIFICATION,
                    system_id="account_service",
                    resource_id="account_01",
                    operation=Operation.VERIFY_RECORD_ABSENT,
                    state=State.ABSENT,
                    evidence_id="evidence_01",
                )
            ],
        ),
        CaseAuditResult(
            case_id="case_002",
            deletion_status=DeletionStatus.NOT_APPLICABLE,
            steps=[],
        ),
    ]

    write_output_csv(results, out_file)
    assert out_file.is_file()

    is_valid, issues = validate_output_file(out_file, expected_case_count=2)
    assert is_valid
    assert len(issues) == 0


def test_validate_official_sample_output():
    """Verify that dataset/sample_output.csv passes official schema validation."""
    sample_path = Path("dataset/sample_output.csv")
    if sample_path.is_file():
        is_valid, issues = validate_output_file(sample_path, expected_case_count=32)
        assert is_valid, f"Sample output failed validation: {issues}"


def test_validate_not_applicable_non_empty(tmp_path):
    """Verify error when NOT_APPLICABLE has non-empty steps_json."""
    bad_file = tmp_path / "bad_not_applicable.csv"
    with open(bad_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["case_id", "deletion_status", "steps_json"])
        writer.writerow(["case_001", "NOT_APPLICABLE", '[{"step_no": 1}]'])

    is_valid, issues = validate_output_file(bad_file)
    assert not is_valid
    assert any("NOT_APPLICABLE must have empty steps_json" in i for i in issues)


def test_validate_step_number_discontinuity(tmp_path):
    """Verify error when step numbers are not consecutive starting at 1."""
    bad_file = tmp_path / "bad_steps.csv"
    steps = [
        {
            "step_no": 2,  # Should start at 1
            "phase": "VERIFICATION",
            "system_id": "account_service",
            "resource_id": "acc_01",
            "operation": "VERIFY_RECORD_ABSENT",
            "state": "ABSENT",
            "evidence_id": "evidence_01",
        }
    ]
    with open(bad_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["case_id", "deletion_status", "steps_json"])
        writer.writerow(["case_001", "COMPLETE", json.dumps(steps)])

    is_valid, issues = validate_output_file(bad_file)
    assert not is_valid
    assert any("Step number discontinuity" in i for i in issues)


def test_validate_invalid_operation_state_pairing(tmp_path):
    """Verify error when an operation is paired with an incompatible state."""
    bad_file = tmp_path / "bad_pairing.csv"
    steps = [
        {
            "step_no": 1,
            "phase": "FINDING",
            "system_id": "account_service",
            "resource_id": "acc_01",
            "operation": "REPORT_REMAINING_RECORD",
            "state": "ABSENT",  # Invalid! REPORT_REMAINING_RECORD requires PRESENT
            "evidence_id": "evidence_01",
        }
    ]
    with open(bad_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["case_id", "deletion_status", "steps_json"])
        writer.writerow(["case_001", "INCOMPLETE", json.dumps(steps)])

    is_valid, issues = validate_output_file(bad_file)
    assert not is_valid
    assert any("requires state 'PRESENT', but found state 'ABSENT'" in i for i in issues)


def test_validate_case_sorting(tmp_path):
    """Verify error when case_ids are not in ascending sorted order."""
    bad_file = tmp_path / "unsorted.csv"
    with open(bad_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["case_id", "deletion_status", "steps_json"])
        writer.writerow(["case_002", "NOT_APPLICABLE", "[]"])
        writer.writerow(["case_001", "NOT_APPLICABLE", "[]"])

    is_valid, issues = validate_output_file(bad_file)
    assert not is_valid
    assert any("Rows are not sorted by case_id" in i for i in issues)
