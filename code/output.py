"""Output serialization, schema enforcement, and validation for Ghost Data Still Exists.

Enforces the exact CSV header `case_id,deletion_status,steps_json`, valid JSON encoding,
permitted operations/states, step number continuity, and sorting rules according
to the official challenge specification.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from code.models import (
    OPERATION_CONTRACT,
    OPERATION_ORDER,
    AuditStep,
    CaseAuditResult,
    DeletionStatus,
    Operation,
    Phase,
    State,
)

OUTPUT_COLUMNS = ["case_id", "deletion_status", "steps_json"]

PHASE_ORDER = [Phase.FINDING, Phase.REMEDIATION, Phase.VERIFICATION]


def serialize_steps(steps: Sequence[Union[AuditStep, Dict[str, Any]]]) -> str:
    """Serialize a list of AuditStep objects or dictionaries into a JSON string.

    For NOT_APPLICABLE or empty step lists, returns '[]'.
    """
    if not steps:
        return "[]"

    raw_list = [s.to_dict() if isinstance(s, AuditStep) else s for s in steps]
    # Compact, deterministic JSON serialization
    return json.dumps(raw_list, separators=(",", ":"))


def write_output_csv(
    results: Sequence[Union[CaseAuditResult, Dict[str, Any]]],
    output_path: Union[Path, str],
) -> None:
    """Write audit results to a CSV file matching the competition output specification."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, lineterminator="\n")
        writer.writerow(OUTPUT_COLUMNS)

        for item in results:
            if isinstance(item, CaseAuditResult):
                case_id = item.case_id
                status = item.deletion_status.value
                steps_json = serialize_steps(item.steps)
            else:
                case_id = item["case_id"]
                raw_status = item["deletion_status"]
                status = raw_status.value if isinstance(raw_status, DeletionStatus) else str(raw_status)
                steps_json = serialize_steps(item.get("steps", []))

            writer.writerow([case_id, status, steps_json])


def validate_step(step: Dict[str, Any], expected_step_no: int, status: str) -> List[str]:
    """Validate a single step dictionary against specification rules."""
    errors: List[str] = []

    required_keys = {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}
    missing_keys = required_keys - set(step.keys())
    if missing_keys:
        errors.append(f"Step {expected_step_no} is missing required fields: {sorted(missing_keys)}")
        return errors

    step_no = step.get("step_no")
    if step_no != expected_step_no:
        errors.append(f"Step number discontinuity: expected {expected_step_no}, got {step_no}")

    # Validate phase
    phase_str = step.get("phase", "")
    try:
        phase = Phase(phase_str)
    except ValueError:
        errors.append(f"Step {expected_step_no}: invalid phase '{phase_str}'")
        return errors

    # Validate operation
    op_str = step.get("operation", "")
    try:
        op = Operation(op_str)
    except ValueError:
        errors.append(f"Step {expected_step_no}: invalid operation '{op_str}'")
        return errors

    # Validate state
    state_str = step.get("state", "")
    try:
        state = State(state_str)
    except ValueError:
        errors.append(f"Step {expected_step_no}: invalid state '{state_str}'")
        return errors

    # Validate operation contract (phase & state pairing)
    expected_phase, expected_state = OPERATION_CONTRACT[op]
    if phase != expected_phase:
        errors.append(
            f"Step {expected_step_no}: operation '{op.value}' belongs to phase "
            f"'{expected_phase.value}', but found in phase '{phase.value}'"
        )
    if state != expected_state:
        errors.append(
            f"Step {expected_step_no}: operation '{op.value}' requires state "
            f"'{expected_state.value}', but found state '{state.value}'"
        )

    # Validate evidence citations
    evidence_id = str(step.get("evidence_id", "")).strip()
    if status == DeletionStatus.COMPLETE.value:
        if phase != Phase.VERIFICATION:
            errors.append(f"Step {expected_step_no}: COMPLETE case must only contain VERIFICATION steps")
        if not evidence_id:
            errors.append(
                f"Step {expected_step_no}: VERIFICATION step in COMPLETE case must cite evidence proving state"
            )
    elif status == DeletionStatus.INCOMPLETE.value:
        if phase in (Phase.REMEDIATION, Phase.VERIFICATION):
            if evidence_id != "":
                errors.append(
                    f"Step {expected_step_no}: proposed {phase.value} in INCOMPLETE case must use empty evidence_id, "
                    f"got '{evidence_id}'"
                )
        elif phase == Phase.FINDING:
            if not evidence_id:
                errors.append(f"Step {expected_step_no}: FINDING in INCOMPLETE case must cite evidence ID")

    return errors


def validate_step_ordering(steps: List[Dict[str, Any]]) -> List[str]:
    """Validate that steps obey the official ordering:
    1. Phase order: FINDING, then REMEDIATION, then VERIFICATION.
    2. Operation order within phase (as defined in table).
    3. Ascending order by system_id, then resource_id.
    """
    errors: List[str] = []
    if len(steps) <= 1:
        return errors

    phase_index_map = {phase: i for i, phase in enumerate(PHASE_ORDER)}

    def step_sort_key(s: Dict[str, Any]) -> Tuple[int, int, str, str]:
        p = Phase(s["phase"])
        op = Operation(s["operation"])
        p_idx = phase_index_map[p]
        op_list = OPERATION_ORDER[p]
        op_idx = op_list.index(op) if op in op_list else 999
        return (p_idx, op_idx, s.get("system_id", ""), s.get("resource_id", ""))

    for i in range(len(steps) - 1):
        key_curr = step_sort_key(steps[i])
        key_next = step_sort_key(steps[i + 1])
        if key_curr > key_next:
            errors.append(
                f"Steps out of order between step {steps[i].get('step_no')} and step {steps[i+1].get('step_no')}. "
                "Steps must be ordered by phase (FINDING -> REMEDIATION -> VERIFICATION), "
                "then operation table order, then system_id, then resource_id."
            )
            break

    return errors


def validate_output_file(
    file_path: Union[Path, str],
    expected_case_count: Optional[int] = None,
) -> Tuple[bool, List[str]]:
    """Validate an output CSV file against all official competition rules.

    Returns:
        Tuple of (is_valid: bool, issues: list of error descriptions)
    """
    file_path = Path(file_path)
    issues: List[str] = []

    if not file_path.is_file():
        return False, [f"Output file does not exist: '{file_path}'"]

    with open(file_path, "r", encoding="utf-8", newline="") as f:
        reader = csv.reader(f)
        try:
            header = next(reader)
        except StopIteration:
            return False, ["Output file is completely empty (no header row found)."]

        if header != OUTPUT_COLUMNS:
            issues.append(f"Header mismatch. Expected {OUTPUT_COLUMNS}, got {header}")

        rows = list(reader)

    if expected_case_count is not None and len(rows) != expected_case_count:
        issues.append(f"Row count mismatch: expected {expected_case_count} data rows, got {len(rows)}")

    seen_case_ids: List[str] = []

    for row_idx, row in enumerate(rows, start=2):
        if len(row) != 3:
            issues.append(f"Line {row_idx}: expected 3 columns, found {len(row)}")
            continue

        case_id, status_str, steps_json_str = row
        seen_case_ids.append(case_id)

        # Validate status
        try:
            status = DeletionStatus(status_str)
        except ValueError:
            issues.append(f"Line {row_idx} ({case_id}): invalid deletion_status '{status_str}'")
            continue

        # Parse JSON
        try:
            steps_data = json.loads(steps_json_str)
        except json.JSONDecodeError as e:
            issues.append(f"Line {row_idx} ({case_id}): malformed JSON in steps_json: {e}")
            continue

        if not isinstance(steps_data, list):
            issues.append(f"Line {row_idx} ({case_id}): steps_json must be a JSON array, got {type(steps_data).__name__}")
            continue

        # Validate NOT_APPLICABLE rule
        if status == DeletionStatus.NOT_APPLICABLE:
            if len(steps_data) != 0:
                issues.append(f"Line {row_idx} ({case_id}): NOT_APPLICABLE must have empty steps_json '[]', found {len(steps_data)} items")
            continue

        # Validate step list for COMPLETE and INCOMPLETE
        if len(steps_data) == 0:
            issues.append(f"Line {row_idx} ({case_id}): {status.value} case must have at least one step in steps_json")
            continue

        for expected_step_no, step in enumerate(steps_data, start=1):
            if not isinstance(step, dict):
                issues.append(f"Line {row_idx} ({case_id}): step {expected_step_no} is not a JSON object")
                continue
            step_issues = validate_step(step, expected_step_no, status.value)
            for si in step_issues:
                issues.append(f"Line {row_idx} ({case_id}): {si}")

        # Check step ordering
        order_issues = validate_step_ordering(steps_data)
        for oi in order_issues:
            issues.append(f"Line {row_idx} ({case_id}): {oi}")

    # Check case_id sorting
    if seen_case_ids != sorted(seen_case_ids):
        issues.append("Rows are not sorted by case_id in ascending order.")

    return (len(issues) == 0, issues)
