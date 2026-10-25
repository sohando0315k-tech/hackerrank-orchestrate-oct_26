"""Unit tests for deterministic remediation and verification planner (Sprint 3B).

Verifies:
1. Strict Phase Order: FINDING -> REMEDIATION -> VERIFICATION.
2. Official Operation Precedence within each phase.
3. System ID and Resource ID ascending sort.
4. Schema validation and step number continuity via code.output.validate_step.
5. Strict evidence citation rules (COMPLETE vs INCOMPLETE).
6. NOT_APPLICABLE requests producing exactly empty steps [].
7. Retention preservation (security audit logs, legal holds, user retention exceptions).
8. Active data flows and restore risk remediation.
9. Deterministic output and deduplication of redundant findings.
10. Robustness with dictionary inputs and duck typing.
"""

import pytest

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
from code.output import validate_step, validate_step_ordering
from code.planner import (
    DeletionAuditPlanner,
    build_audit_steps,
    deduplicate_steps,
    get_remediation_operation,
    get_verification_operation,
    plan_case,
    sort_and_number_steps,
)
from code.policy import (
    DataCategory,
    PolicyEvaluationResult,
    PolicyFinding,
    PolicyVerification,
)


# --- 1. NOT_APPLICABLE Contract ---

def test_not_applicable_produces_empty_steps():
    """Verify NOT_APPLICABLE case produces strictly empty steps []."""
    eval_res = PolicyEvaluationResult(
        case_id="case_optout_01",
        deletion_status=DeletionStatus.NOT_APPLICABLE,
        findings=[],
        verifications=[],
    )
    result = plan_case(eval_res)
    assert result.case_id == "case_optout_01"
    assert result.deletion_status == DeletionStatus.NOT_APPLICABLE
    assert result.steps == []

    # Row tuple serialization check
    cid, status, steps_dict = result.to_row()
    assert cid == "case_optout_01"
    assert status == "NOT_APPLICABLE"
    assert steps_dict == []


# --- 2. COMPLETE Cases Contract ---

def test_complete_case_only_verifications_with_authentic_evidence():
    """Verify COMPLETE cases only contain VERIFICATION steps, all citing authentic evidence IDs."""
    verifs = [
        PolicyVerification(
            operation=Operation.VERIFY_RECORD_ABSENT,
            state=State.ABSENT,
            system_id="account_service",
            resource_id="account_001",
            evidence_id="evidence_54",
        ),
        PolicyVerification(
            operation=Operation.VERIFY_RECORD_PRESENT,
            state=State.PRESENT,
            system_id="security_service",
            resource_id="audit_record_200",
            evidence_id="evidence_94",
        ),
        PolicyVerification(
            operation=Operation.VERIFY_RECORD_ANONYMIZED,
            state=State.ANONYMIZED,
            system_id="analytics_platform",
            resource_id="analytics_901",
            evidence_id="evidence_56",
        ),
    ]
    eval_res = PolicyEvaluationResult(
        case_id="case_complete_01",
        deletion_status=DeletionStatus.COMPLETE,
        findings=[],
        verifications=verifs,
    )

    result = plan_case(eval_res)
    assert result.deletion_status == DeletionStatus.COMPLETE
    assert len(result.steps) == 3

    # Every step must be VERIFICATION and have non-empty evidence_id
    for idx, s in enumerate(result.steps, start=1):
        assert s.step_no == idx
        assert s.phase == Phase.VERIFICATION
        assert s.evidence_id != ""
        # Schema validation
        errs = validate_step(s.to_dict(), idx, DeletionStatus.COMPLETE.value)
        assert errs == []

    # Ordering validation
    step_dicts = [s.to_dict() for s in result.steps]
    order_errs = validate_step_ordering(step_dicts)
    assert order_errs == []


# --- 3. INCOMPLETE Cases & Phase Order ---

def test_incomplete_phase_ordering_and_precedence():
    """Verify strict phase order: FINDING -> REMEDIATION -> VERIFICATION and operation precedence."""
    findings = [
        PolicyFinding(
            operation=Operation.REPORT_ACTIVE_DATA_FLOW,
            state=State.ACTIVE,
            system_id="integration_service",
            resource_id="data_flow_9522",
            evidence_id="evidence_92",
            data_category=DataCategory.DATA_FLOW,
            remediation_operation=Operation.DISABLE_DATA_FLOW,
            verification_operation=Operation.VERIFY_DATA_FLOW_DISABLED,
        ),
        PolicyFinding(
            operation=Operation.REPORT_REMAINING_RECORD,
            state=State.PRESENT,
            system_id="search_service",
            resource_id="search_052",
            evidence_id="evidence_03",
            data_category=DataCategory.SEARCH_INDEX_ENTRY,
            remediation_operation=Operation.DELETE_RECORD,
            verification_operation=Operation.VERIFY_RECORD_ABSENT,
        ),
        PolicyFinding(
            operation=Operation.REPORT_EXPOSED_PII,
            state=State.PRESENT,
            system_id="analytics_platform",
            resource_id="analytics_2034",
            evidence_id="evidence_03",
            data_category=DataCategory.ANALYTICS_PROFILE,
            remediation_operation=Operation.ANONYMIZE_RECORD,
            verification_operation=Operation.VERIFY_RECORD_ANONYMIZED,
        ),
        PolicyFinding(
            operation=Operation.REPORT_EXPOSED_PII,
            state=State.PRESENT,
            system_id="support_platform",
            resource_id="support_864",
            evidence_id="evidence_03",
            data_category=DataCategory.SUPPORT_MESSAGE,
            remediation_operation=Operation.REDACT_RECORD,
            verification_operation=Operation.VERIFY_RECORD_REDACTED,
        ),
    ]
    verifs = [
        # Pre-existing compliant verification
        PolicyVerification(
            operation=Operation.VERIFY_RECORD_ABSENT,
            state=State.ABSENT,
            system_id="account_service",
            resource_id="account_4248",
            evidence_id="",
        ),
        PolicyVerification(
            operation=Operation.VERIFY_RECORD_PRESENT,
            state=State.PRESENT,
            system_id="security_service",
            resource_id="audit_record_9394",
            evidence_id="",
        ),
    ]
    eval_res = PolicyEvaluationResult(
        case_id="case_complex_incomplete",
        deletion_status=DeletionStatus.INCOMPLETE,
        findings=findings,
        verifications=verifs,
    )

    result = plan_case(eval_res)
    assert result.deletion_status == DeletionStatus.INCOMPLETE

    step_dicts = [s.to_dict() for s in result.steps]
    phases = [s["phase"] for s in step_dicts]

    # 1. Phase grouping: FINDINGS come first, then REMEDIATION, then VERIFICATION
    last_phase = "FINDING"
    phase_transitions = {"FINDING": ["FINDING", "REMEDIATION"], "REMEDIATION": ["REMEDIATION", "VERIFICATION"], "VERIFICATION": ["VERIFICATION"]}
    for p in phases:
        assert p in phase_transitions[last_phase], f"Invalid phase transition from {last_phase} to {p}"
        last_phase = p

    # 2. Findings operations precedence check
    f_ops = [s["operation"] for s in step_dicts if s["phase"] == "FINDING"]
    assert f_ops == [
        "REPORT_REMAINING_RECORD",  # search_052
        "REPORT_EXPOSED_PII",       # analytics_2034
        "REPORT_EXPOSED_PII",       # support_864
        "REPORT_ACTIVE_DATA_FLOW",   # data_flow_9522
    ]

    # 3. Remediation operations precedence check
    r_ops = [s["operation"] for s in step_dicts if s["phase"] == "REMEDIATION"]
    assert r_ops == [
        "DISABLE_DATA_FLOW",  # data_flow_9522
        "DELETE_RECORD",      # search_052
        "REDACT_RECORD",      # support_864
        "ANONYMIZE_RECORD",   # analytics_2034
    ]

    # 4. Verification operations precedence check
    v_ops = [s["operation"] for s in step_dicts if s["phase"] == "VERIFICATION"]
    assert v_ops == [
        "VERIFY_RECORD_ABSENT",      # account_4248
        "VERIFY_RECORD_ABSENT",      # search_052
        "VERIFY_RECORD_PRESENT",     # audit_record_9394
        "VERIFY_RECORD_REDACTED",    # support_864
        "VERIFY_RECORD_ANONYMIZED",  # analytics_2034
        "VERIFY_DATA_FLOW_DISABLED", # data_flow_9522
    ]

    # 5. Schema and ordering validation
    order_errs = validate_step_ordering(step_dicts)
    assert order_errs == []

    for idx, s in enumerate(step_dicts, 1):
        errs = validate_step(s, idx, DeletionStatus.INCOMPLETE.value)
        assert errs == [], f"Step {idx} failed validation: {errs}"


# --- 4. Evidence Citation Rules for INCOMPLETE Cases ---

def test_incomplete_evidence_citation_rules():
    """Verify INCOMPLETE cases enforce authentic evidence_id for findings, empty string for remediation/verifications."""
    findings = [
        PolicyFinding(
            operation=Operation.REPORT_REMAINING_RECORD,
            state=State.PRESENT,
            system_id="export_service",
            resource_id="export_001",
            evidence_id="evidence_59",
            remediation_operation=Operation.DELETE_RECORD,
        ),
    ]
    verifs = [
        PolicyVerification(
            operation=Operation.VERIFY_RECORD_ABSENT,
            state=State.ABSENT,
            system_id="account_service",
            resource_id="account_008",
            evidence_id="",
        )
    ]
    eval_res = PolicyEvaluationResult(
        case_id="case_08_test",
        deletion_status=DeletionStatus.INCOMPLETE,
        findings=findings,
        verifications=verifs,
    )
    result = plan_case(eval_res)

    for s in result.steps:
        if s.phase == Phase.FINDING:
            assert s.evidence_id == "evidence_59"
        elif s.phase in (Phase.REMEDIATION, Phase.VERIFICATION):
            assert s.evidence_id == ""


# --- 5. Active Data Flow and Restore Risk Planning ---

def test_active_data_flow_planning():
    """Verify active data flow produces REPORT_ACTIVE_DATA_FLOW -> DISABLE_DATA_FLOW -> VERIFY_DATA_FLOW_DISABLED."""
    finding = PolicyFinding(
        operation=Operation.REPORT_ACTIVE_DATA_FLOW,
        state=State.ACTIVE,
        system_id="integration_service",
        resource_id="data_flow_100",
        evidence_id="activity_01",
        remediation_operation=Operation.DISABLE_DATA_FLOW,
    )
    eval_res = PolicyEvaluationResult(
        case_id="case_flow",
        deletion_status=DeletionStatus.INCOMPLETE,
        findings=[finding],
    )
    result = plan_case(eval_res)
    assert len(result.steps) == 3

    assert result.steps[0].operation == Operation.REPORT_ACTIVE_DATA_FLOW
    assert result.steps[0].phase == Phase.FINDING
    assert result.steps[0].state == State.ACTIVE
    assert result.steps[0].evidence_id == "activity_01"

    assert result.steps[1].operation == Operation.DISABLE_DATA_FLOW
    assert result.steps[1].phase == Phase.REMEDIATION
    assert result.steps[1].state == State.DISABLED
    assert result.steps[1].evidence_id == ""

    assert result.steps[2].operation == Operation.VERIFY_DATA_FLOW_DISABLED
    assert result.steps[2].phase == Phase.VERIFICATION
    assert result.steps[2].state == State.DISABLED
    assert result.steps[2].evidence_id == ""


def test_restore_risk_planning():
    """Verify restore risk produces REPORT_RESTORE_RISK -> BLOCK_RESTORE -> VERIFY_RESTORE_BLOCKED."""
    finding = PolicyFinding(
        operation=Operation.REPORT_RESTORE_RISK,
        state=State.ACTIVE,
        system_id="backup_service",
        resource_id="backup_555",
        evidence_id="evidence_93",
        remediation_operation=Operation.BLOCK_RESTORE,
    )
    eval_res = PolicyEvaluationResult(
        case_id="case_backup",
        deletion_status=DeletionStatus.INCOMPLETE,
        findings=[finding],
    )
    result = plan_case(eval_res)
    assert len(result.steps) == 3

    assert result.steps[0].operation == Operation.REPORT_RESTORE_RISK
    assert result.steps[0].phase == Phase.FINDING
    assert result.steps[0].state == State.ACTIVE
    assert result.steps[0].evidence_id == "evidence_93"

    assert result.steps[1].operation == Operation.BLOCK_RESTORE
    assert result.steps[1].phase == Phase.REMEDIATION
    assert result.steps[1].state == State.BLOCKED
    assert result.steps[1].evidence_id == ""

    assert result.steps[2].operation == Operation.VERIFY_RESTORE_BLOCKED
    assert result.steps[2].phase == Phase.VERIFICATION
    assert result.steps[2].state == State.BLOCKED
    assert result.steps[2].evidence_id == ""


# --- 6. Retention Preservation (No Deletion of Retained Records) ---

def test_retained_records_never_generate_deletion():
    """Verify retained audit logs and legal holds produce VERIFY_RECORD_PRESENT and never DELETE_RECORD."""
    verifs = [
        PolicyVerification(
            operation=Operation.VERIFY_RECORD_PRESENT,
            state=State.PRESENT,
            system_id="security_service",
            resource_id="audit_record_999",
            evidence_id="evidence_94",
        ),
        PolicyVerification(
            operation=Operation.VERIFY_RECORD_PRESENT,
            state=State.PRESENT,
            system_id="legal_service",
            resource_id="legal_hold_001",
            evidence_id="evidence_94",
        ),
    ]
    eval_res = PolicyEvaluationResult(
        case_id="case_retained",
        deletion_status=DeletionStatus.COMPLETE,
        findings=[],
        verifications=verifs,
    )
    result = plan_case(eval_res)
    assert len(result.steps) == 2
    for s in result.steps:
        assert s.operation == Operation.VERIFY_RECORD_PRESENT
        assert s.phase == Phase.VERIFICATION
        assert s.state == State.PRESENT


# --- 7. Deduplication of Findings and Verifications ---

def test_deduplicate_identical_steps():
    """Verify duplicate findings or verifications on the same resource are cleanly deduplicated."""
    step1 = AuditStep(
        step_no=1,
        phase=Phase.FINDING,
        system_id="search_service",
        resource_id="search_001",
        operation=Operation.REPORT_REMAINING_RECORD,
        state=State.PRESENT,
        evidence_id="evidence_57",
    )
    step2 = AuditStep(
        step_no=2,
        phase=Phase.FINDING,
        system_id="search_service",
        resource_id="search_001",
        operation=Operation.REPORT_REMAINING_RECORD,
        state=State.PRESENT,
        evidence_id="evidence_57",
    )
    step3 = AuditStep(
        step_no=3,
        phase=Phase.FINDING,
        system_id="search_service",
        resource_id="search_002",
        operation=Operation.REPORT_REMAINING_RECORD,
        state=State.PRESENT,
        evidence_id="evidence_58",
    )
    deduped = deduplicate_steps([step1, step2, step3])
    assert len(deduped) == 2
    res_ids = [s.resource_id for s in deduped]
    assert "search_001" in res_ids
    assert "search_002" in res_ids


# --- 8. Step Sorting & Continuity ---

def test_consecutive_numbering_and_tie_breaking():
    """Verify step numbering starts at 1, has no gaps, and sorts lexicographically by system then resource."""
    steps = [
        AuditStep(0, Phase.FINDING, "support_platform", "support_99", Operation.REPORT_REMAINING_RECORD, State.PRESENT, "ev1"),
        AuditStep(0, Phase.FINDING, "account_service", "account_55", Operation.REPORT_REMAINING_RECORD, State.PRESENT, "ev2"),
        AuditStep(0, Phase.FINDING, "account_service", "account_10", Operation.REPORT_REMAINING_RECORD, State.PRESENT, "ev3"),
    ]
    sorted_steps = sort_and_number_steps(steps)
    assert len(sorted_steps) == 3
    assert [s.step_no for s in sorted_steps] == [1, 2, 3]
    # Sorted by system_id, then resource_id
    assert sorted_steps[0].system_id == "account_service"
    assert sorted_steps[0].resource_id == "account_10"
    assert sorted_steps[1].system_id == "account_service"
    assert sorted_steps[1].resource_id == "account_55"
    assert sorted_steps[2].system_id == "support_platform"
    assert sorted_steps[2].resource_id == "support_99"


# --- 9. Deterministic Output Across Repeated Runs ---

def test_deterministic_output_across_permutations():
    """Verify that permuting input findings and verifications yields identical ordered output."""
    f1 = PolicyFinding(Operation.REPORT_REMAINING_RECORD, State.PRESENT, "search_service", "search_001", "ev_a")
    f2 = PolicyFinding(Operation.REPORT_ACTIVE_DATA_FLOW, State.ACTIVE, "integration_service", "data_flow_001", "ev_b")
    v1 = PolicyVerification(Operation.VERIFY_RECORD_ABSENT, State.ABSENT, "account_service", "account_001", "")

    eval_a = PolicyEvaluationResult("case_det", DeletionStatus.INCOMPLETE, findings=[f1, f2], verifications=[v1])
    eval_b = PolicyEvaluationResult("case_det", DeletionStatus.INCOMPLETE, findings=[f2, f1], verifications=[v1])

    res_a = plan_case(eval_a)
    res_b = plan_case(eval_b)

    assert [s.to_dict() for s in res_a.steps] == [s.to_dict() for s in res_b.steps]


# --- 10. Dictionary Input Compatibility ---

def test_planner_accepts_dict_input():
    """Verify planner accepts dict representations of evaluation results."""
    dict_input = {
        "case_id": "case_dict_01",
        "deletion_status": "COMPLETE",
        "findings": [],
        "verifications": [
            {
                "operation": "VERIFY_RECORD_ABSENT",
                "state": "ABSENT",
                "system_id": "account_service",
                "resource_id": "account_001",
                "evidence_id": "evidence_54",
            }
        ],
    }
    result = plan_case(dict_input)
    assert result.case_id == "case_dict_01"
    assert result.deletion_status == DeletionStatus.COMPLETE
    assert len(result.steps) == 1
    assert result.steps[0].operation == Operation.VERIFY_RECORD_ABSENT
    assert result.steps[0].evidence_id == "evidence_54"
