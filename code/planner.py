"""Deterministic Remediation and Verification Planner module.

Synthesizes policy findings and compliance checks into correctly ordered,
schema-valid audit steps according to the official competition specification:
1. Strict Phase Order: FINDING -> REMEDIATION -> VERIFICATION.
2. Official Operation Precedence within each phase:
   - FINDING:
     REPORT_REMAINING_RECORD -> REPORT_EXPOSED_PII -> REPORT_ACTIVE_DATA_FLOW -> REPORT_RESTORE_RISK
   - REMEDIATION:
     DISABLE_DATA_FLOW -> BLOCK_RESTORE -> DELETE_RECORD -> REDACT_RECORD -> ANONYMIZE_RECORD
   - VERIFICATION:
     VERIFY_RECORD_ABSENT -> VERIFY_RECORD_PRESENT -> VERIFY_RECORD_REDACTED ->
     VERIFY_RECORD_ANONYMIZED -> VERIFY_DATA_FLOW_DISABLED -> VERIFY_RESTORE_BLOCKED
3. Ascending sort by system_id, then resource_id.
4. Consecutively numbered starting at 1.
5. Strict evidence citation rules:
   - COMPLETE cases: only VERIFICATION steps, all citing authentic evidence IDs.
   - INCOMPLETE cases: FINDING steps cite authentic evidence IDs; proposed
     REMEDIATION and future VERIFICATION steps strictly use empty string "".
   - NOT_APPLICABLE cases: steps_json must be strictly empty [].
6. Preserves cross-subject isolation, statutory retention, and tombstones.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple, Union

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
from code.policy import DataCategory, PolicyEvaluationResult

# Official Phase Execution Precedence
PHASE_PRIORITY: Dict[Phase, int] = {
    Phase.FINDING: 0,
    Phase.REMEDIATION: 1,
    Phase.VERIFICATION: 2,
}


def get_remediation_operation(
    finding_op: Union[Operation, str],
    category: Optional[Union[DataCategory, str]] = None,
) -> Tuple[Operation, State]:
    """Map a policy finding operation to its required statutory remediation operation and state.

    Remediation Precedence / Contracts:
    - REPORT_ACTIVE_DATA_FLOW -> (DISABLE_DATA_FLOW, DISABLED)
    - REPORT_RESTORE_RISK     -> (BLOCK_RESTORE, BLOCKED)
    - REPORT_REMAINING_RECORD -> (DELETE_RECORD, ABSENT)
    - REPORT_EXPOSED_PII:
      - If category is ANALYTICS_PROFILE or PRODUCT_TELEMETRY -> (ANONYMIZE_RECORD, ANONYMIZED)
      - If category is SUPPORT_MESSAGE, EMAIL_DELIVERY_LOG, or ACCOUNT_TOMBSTONE -> (REDACT_RECORD, REDACTED)
    """
    f_op = Operation(finding_op) if not isinstance(finding_op, Operation) else finding_op
    cat_str = (category.value if isinstance(category, DataCategory) else str(category or "")).upper()

    if f_op == Operation.REPORT_ACTIVE_DATA_FLOW:
        return (Operation.DISABLE_DATA_FLOW, State.DISABLED)

    if f_op == Operation.REPORT_RESTORE_RISK:
        return (Operation.BLOCK_RESTORE, State.BLOCKED)

    if f_op == Operation.REPORT_REMAINING_RECORD:
        return (Operation.DELETE_RECORD, State.ABSENT)

    if f_op == Operation.REPORT_EXPOSED_PII:
        if "ANALYTICS" in cat_str or "TELEMETRY" in cat_str:
            return (Operation.ANONYMIZE_RECORD, State.ANONYMIZED)
        return (Operation.REDACT_RECORD, State.REDACTED)

    # Fallback to DELETE_RECORD if unrecognized
    return (Operation.DELETE_RECORD, State.ABSENT)


def get_verification_operation(
    remediation_op: Union[Operation, str],
) -> Tuple[Operation, State]:
    """Map a proposed remediation operation to its post-remediation verification check.

    Post-Remediation Verification Contracts:
    - DISABLE_DATA_FLOW -> (VERIFY_DATA_FLOW_DISABLED, DISABLED)
    - BLOCK_RESTORE     -> (VERIFY_RESTORE_BLOCKED, BLOCKED)
    - DELETE_RECORD     -> (VERIFY_RECORD_ABSENT, ABSENT)
    - REDACT_RECORD     -> (VERIFY_RECORD_REDACTED, REDACTED)
    - ANONYMIZE_RECORD  -> (VERIFY_RECORD_ANONYMIZED, ANONYMIZED)
    """
    r_op = Operation(remediation_op) if not isinstance(remediation_op, Operation) else remediation_op

    if r_op == Operation.DISABLE_DATA_FLOW:
        return (Operation.VERIFY_DATA_FLOW_DISABLED, State.DISABLED)
    if r_op == Operation.BLOCK_RESTORE:
        return (Operation.VERIFY_RESTORE_BLOCKED, State.BLOCKED)
    if r_op == Operation.DELETE_RECORD:
        return (Operation.VERIFY_RECORD_ABSENT, State.ABSENT)
    if r_op == Operation.REDACT_RECORD:
        return (Operation.VERIFY_RECORD_REDACTED, State.REDACTED)
    if r_op == Operation.ANONYMIZE_RECORD:
        return (Operation.VERIFY_RECORD_ANONYMIZED, State.ANONYMIZED)

    return (Operation.VERIFY_RECORD_ABSENT, State.ABSENT)


def deduplicate_steps(steps: List[AuditStep]) -> List[AuditStep]:
    """Deduplicate audit steps within each phase deterministically.

    Deduplication rules:
    - Unique step identity is defined by (phase, operation, system_id, resource_id).
    - If multiple identical steps exist within a phase:
      - Prefer a step with a non-empty, authentic evidence_id over an empty one.
      - Break any remaining ties by sorted evidence_id string.
    """
    if not steps:
        return []

    # Map (phase, operation, system_id, resource_id) -> best AuditStep
    seen: Dict[Tuple[Phase, Operation, str, str], AuditStep] = {}

    for step in steps:
        p = Phase(step.phase) if not isinstance(step.phase, Phase) else step.phase
        op = Operation(step.operation) if not isinstance(step.operation, Operation) else step.operation
        sys_clean = str(step.system_id).strip()
        res_clean = str(step.resource_id).strip()
        key = (p, op, sys_clean, res_clean)

        if key not in seen:
            seen[key] = step
        else:
            existing = seen[key]
            # If current step has an authentic evidence_id and existing does not, prefer current
            if step.evidence_id and not existing.evidence_id:
                seen[key] = step
            elif step.evidence_id and existing.evidence_id:
                # Deterministic tie-break
                if str(step.evidence_id) < str(existing.evidence_id):
                    seen[key] = step

    return list(seen.values())


def sort_and_number_steps(steps: List[AuditStep]) -> List[AuditStep]:
    """Sort audit steps according to the official competition specification and renumber consecutively.

    Official Ordering Rules:
    1. Phase order: FINDING (0) -> REMEDIATION (1) -> VERIFICATION (2).
    2. Operation precedence within phase (defined by OPERATION_ORDER).
    3. Ascending order by system_id (case-insensitive).
    4. Ascending order by resource_id (case-insensitive).
    5. Step numbers consecutively starting at 1.
    """
    def sort_key(step: AuditStep) -> Tuple[int, int, str, str]:
        p = Phase(step.phase) if not isinstance(step.phase, Phase) else step.phase
        op = Operation(step.operation) if not isinstance(step.operation, Operation) else step.operation
        phase_rank = PHASE_PRIORITY.get(p, 99)
        op_list = OPERATION_ORDER.get(p, [])
        op_rank = op_list.index(op) if op in op_list else 99
        sys_sort = str(step.system_id).strip().lower()
        res_sort = str(step.resource_id).strip().lower()
        return (phase_rank, op_rank, sys_sort, res_sort)

    # First deduplicate steps
    deduped = deduplicate_steps(steps)

    # Sort deterministically
    sorted_steps = sorted(deduped, key=sort_key)

    # Renumber consecutively starting at 1
    numbered_steps: List[AuditStep] = []
    for idx, s in enumerate(sorted_steps, start=1):
        numbered_steps.append(
            AuditStep(
                step_no=idx,
                phase=Phase(s.phase) if not isinstance(s.phase, Phase) else s.phase,
                system_id=str(s.system_id).strip(),
                resource_id=str(s.resource_id).strip(),
                operation=Operation(s.operation) if not isinstance(s.operation, Operation) else s.operation,
                state=State(s.state) if not isinstance(s.state, State) else s.state,
                evidence_id=str(s.evidence_id or "").strip(),
            )
        )

    return numbered_steps


def _extract_field(obj: Any, key: str, default: Any = None) -> Any:
    """Extract attribute or dict key gracefully."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def build_audit_steps(
    evaluation: Union[PolicyEvaluationResult, Dict[str, Any]],
) -> List[AuditStep]:
    """Build, order, and number the complete audit steps for an evaluated case.

    Enforces the challenge contract:
    - NOT_APPLICABLE: returns []
    - COMPLETE: only VERIFICATION steps, all citing authentic evidence_id
    - INCOMPLETE:
      - FINDING steps citing authentic evidence_id
      - REMEDIATION steps with evidence_id = ""
      - VERIFICATION steps with evidence_id = ""
    """
    # Extract fields supporting both PolicyEvaluationResult and dict
    if isinstance(evaluation, PolicyEvaluationResult):
        case_id = evaluation.case_id
        status = evaluation.deletion_status
        findings = evaluation.findings
        verifications = evaluation.verifications
    else:
        case_id = str(evaluation.get("case_id", ""))
        raw_status = evaluation.get("deletion_status")
        status = DeletionStatus(raw_status) if raw_status else DeletionStatus.NOT_APPLICABLE
        findings = evaluation.get("findings", [])
        verifications = evaluation.get("verifications", [])

    # Case 1: NOT_APPLICABLE
    if status == DeletionStatus.NOT_APPLICABLE:
        return []

    raw_steps: List[AuditStep] = []

    # Case 2: COMPLETE
    if status == DeletionStatus.COMPLETE:
        for v in verifications:
            raw_op = _extract_field(v, "operation")
            v_op = Operation(raw_op) if not isinstance(raw_op, Operation) else raw_op
            expected_phase, expected_state = OPERATION_CONTRACT[v_op]
            ev_id = str(_extract_field(v, "evidence_id", "") or "").strip()
            sys_id = str(_extract_field(v, "system_id", "")).strip()
            res_id = str(_extract_field(v, "resource_id", "")).strip()
            raw_steps.append(
                AuditStep(
                    step_no=0,
                    phase=Phase.VERIFICATION,
                    system_id=sys_id,
                    resource_id=res_id,
                    operation=v_op,
                    state=expected_state,
                    evidence_id=ev_id,
                )
            )
        return sort_and_number_steps(raw_steps)

    # Case 3: INCOMPLETE
    # A. Findings
    remediated_resources: Set[str] = set()
    for f in findings:
        raw_op = _extract_field(f, "operation")
        f_op = Operation(raw_op) if not isinstance(raw_op, Operation) else raw_op
        expected_phase, expected_state = OPERATION_CONTRACT[f_op]
        ev_id = str(_extract_field(f, "evidence_id", "") or "").strip()
        sys_id = str(_extract_field(f, "system_id", "")).strip()
        res_id = str(_extract_field(f, "resource_id", "")).strip()
        raw_steps.append(
            AuditStep(
                step_no=0,
                phase=Phase.FINDING,
                system_id=sys_id,
                resource_id=res_id,
                operation=f_op,
                state=expected_state,
                evidence_id=ev_id,
            )
        )

        # B. Remediation (proposed action -> evidence_id must be "")
        cat = _extract_field(f, "data_category", None)
        rem_op_attr = _extract_field(f, "remediation_operation", None)
        if rem_op_attr:
            rem_op = Operation(rem_op_attr) if not isinstance(rem_op_attr, Operation) else rem_op_attr
            _, rem_state = OPERATION_CONTRACT[rem_op]
        else:
            rem_op, rem_state = get_remediation_operation(f_op, cat)

        raw_steps.append(
            AuditStep(
                step_no=0,
                phase=Phase.REMEDIATION,
                system_id=sys_id,
                resource_id=res_id,
                operation=rem_op,
                state=rem_state,
                evidence_id="",
            )
        )
        remediated_resources.add(res_id)

    # C. Verifications (future verification checks -> evidence_id must be "")
    # Add pre-existing / policy-provided verifications
    verified_resources: Set[Tuple[Operation, str]] = set()
    for v in verifications:
        raw_op = _extract_field(v, "operation")
        v_op = Operation(raw_op) if not isinstance(raw_op, Operation) else raw_op
        expected_phase, expected_state = OPERATION_CONTRACT[v_op]
        sys_id = str(_extract_field(v, "system_id", "")).strip()
        res_id = str(_extract_field(v, "resource_id", "")).strip()
        raw_steps.append(
            AuditStep(
                step_no=0,
                phase=Phase.VERIFICATION,
                system_id=sys_id,
                resource_id=res_id,
                operation=v_op,
                state=expected_state,
                evidence_id="",
            )
        )
        verified_resources.add((v_op, res_id))

    # Ensure every remediated resource has a corresponding post-remediation verification
    for f in findings:
        res_id = str(_extract_field(f, "resource_id", "")).strip()
        sys_id = str(_extract_field(f, "system_id", "")).strip()
        raw_op = _extract_field(f, "operation")
        f_op = Operation(raw_op) if not isinstance(raw_op, Operation) else raw_op
        cat = _extract_field(f, "data_category", None)
        rem_op_attr = _extract_field(f, "remediation_operation", None)
        if rem_op_attr:
            rem_op = Operation(rem_op_attr) if not isinstance(rem_op_attr, Operation) else rem_op_attr
        else:
            rem_op, _ = get_remediation_operation(f_op, cat)

        verif_op, verif_state = get_verification_operation(rem_op)
        if (verif_op, res_id) not in verified_resources:
            raw_steps.append(
                AuditStep(
                    step_no=0,
                    phase=Phase.VERIFICATION,
                    system_id=sys_id,
                    resource_id=res_id,
                    operation=verif_op,
                    state=verif_state,
                    evidence_id="",
                )
            )
            verified_resources.add((verif_op, res_id))

    return sort_and_number_steps(raw_steps)


class DeletionAuditPlanner:
    """Deterministic audit step synthesis planner for deletion compliance."""

    def plan(
        self,
        evaluation: Union[PolicyEvaluationResult, Dict[str, Any]],
    ) -> CaseAuditResult:
        """Synthesize CaseAuditResult with ordered, schema-valid steps."""
        if isinstance(evaluation, PolicyEvaluationResult):
            case_id = evaluation.case_id
            status = evaluation.deletion_status
        else:
            case_id = str(evaluation.get("case_id", ""))
            raw_status = evaluation.get("deletion_status")
            status = DeletionStatus(raw_status) if raw_status else DeletionStatus.NOT_APPLICABLE

        steps = build_audit_steps(evaluation)
        return CaseAuditResult(
            case_id=case_id,
            deletion_status=status,
            steps=steps,
        )


def plan_case(
    evaluation: Union[PolicyEvaluationResult, Dict[str, Any]],
) -> CaseAuditResult:
    """Convenience function to synthesize CaseAuditResult from a policy evaluation."""
    planner = DeletionAuditPlanner()
    return planner.plan(evaluation)
