"""Team-created end-to-end evaluation cases for Ghost Data Still Exists.

This module evaluates complex edge cases required for hidden-set generalization:
1. Ambiguous identity resolution and cross-subject conflict protection.
2. Partial statutory retention exception handling (e.g. preserving security audit logs).
3. Restore access risk on backup archives requiring remediation and blocking verification.
"""

from pathlib import Path
import pytest

from code.models import (
    DeletionStatus,
    Operation,
    Phase,
    State,
)
from code.evidence import NormalizedEvidenceItem
from code.identity import ResolvedIdentity
from code.policy import PolicyEngine, DataCategory
from code.planner import plan_case


@pytest.fixture
def policy_engine() -> PolicyEngine:
    rules_path = Path("dataset/deletion_rules.csv")
    return PolicyEngine(rules_path)


def test_eval_case_1_ambiguous_identity_conflict_protection(policy_engine: PolicyEngine) -> None:
    """Team Evaluation Case 1: Ambiguous Identity with Cross-Subject Conflict.

    Ensures that when an identity cannot be uniquely resolved, or when evidence
    belongs to a conflicting canonical user_id, cross-subject data is never leaked
    into the audit findings.
    """
    subject = ResolvedIdentity(
        case_id="eval_case_01",
        user_id="user_101",
        status="RESOLVED",
        current_email="alice.eval@example.com",
    )

    contaminated_item = NormalizedEvidenceItem(
        evidence_id="evidence_54",
        evidence_type="SQL",
        origin="database",
        resource_id="account_999",
        system_id="account_service",
        user_id="user_999",
        status="PRESENT",
        captured_at="2026-09-01T12:00:00Z",
    )

    valid_subject_item = NormalizedEvidenceItem(
        evidence_id="evidence_54",
        evidence_type="SQL",
        origin="database",
        resource_id="account_101",
        system_id="account_service",
        user_id="user_101",
        status="ABSENT",
        captured_at="2026-09-01T12:00:00Z",
    )

    eval_result = policy_engine.evaluate_case(
        case_id="eval_case_01",
        request_text="Please delete all my personal information and account data.",
        resolved_identity=subject,
        subject_evidence=[contaminated_item, valid_subject_item],
    )

    assert not any(f.resource_id == "account_999" for f in eval_result.findings)
    assert not any(v.resource_id == "account_999" for v in eval_result.verifications)
    assert any(
        v.resource_id == "account_101"
        and v.operation == Operation.VERIFY_RECORD_ABSENT
        and v.state == State.ABSENT
        for v in eval_result.verifications
    )
    assert eval_result.deletion_status == DeletionStatus.COMPLETE


def test_eval_case_2_partial_statutory_retention_exception(policy_engine: PolicyEngine) -> None:
    """Team Evaluation Case 2: Partial Statutory Retention Exception.

    The user requests deletion of profile data but explicitly notes that security
    incident records or audit logs should be preserved under compliance rules.
    """
    subject = ResolvedIdentity(
        case_id="eval_case_02",
        user_id="user_102",
        status="RESOLVED",
        current_email="bob.eval@example.com",
    )

    support_ticket = NormalizedEvidenceItem(
        evidence_id="evidence_61",
        evidence_type="LOG",
        origin="support_platform",
        resource_id="support_8821",
        system_id="support_platform",
        user_id="user_102",
        status="PRESENT",
        captured_at="2026-09-15T10:00:00Z",
        raw_payload={"requester_email": "bob.eval@example.com", "message": "Customer contacted support."},
    )

    audit_record = NormalizedEvidenceItem(
        evidence_id="evidence_61",
        evidence_type="LOG",
        origin="security_service",
        resource_id="audit_record_8821",
        system_id="security_service",
        user_id="user_102",
        status="PRESENT",
        retention_flag=True,
        captured_at="2026-09-15T10:00:00Z",
        raw_payload={"retention_until": "2034-12-31T23:59:59Z", "event_code": "ACCOUNT_DELETION_RECORDED"},
    )

    req_text = "Please delete my account and support history, but retain any security audit logs required for compliance."
    eval_result = policy_engine.evaluate_case(
        case_id="eval_case_02",
        request_text=req_text,
        resolved_identity=subject,
        subject_evidence=[support_ticket, audit_record],
    )

    assert any(
        f.resource_id == "support_8821"
        and f.operation == Operation.REPORT_EXPOSED_PII
        for f in eval_result.findings
    )
    assert not any(f.resource_id == "audit_record_8821" for f in eval_result.findings)
    assert any(
        v.resource_id == "audit_record_8821"
        and v.operation == Operation.VERIFY_RECORD_PRESENT
        and v.state == State.PRESENT
        for v in eval_result.verifications
    )

    planned = plan_case(eval_result)
    assert planned.deletion_status == DeletionStatus.INCOMPLETE
    phases = [s.phase for s in planned.steps]
    order_val = {Phase.FINDING: 0, Phase.REMEDIATION: 1, Phase.VERIFICATION: 2}
    assert [order_val[p] for p in phases] == sorted([order_val[p] for p in phases])


def test_eval_case_3_restore_access_risk_remediation(policy_engine: PolicyEngine) -> None:
    """Team Evaluation Case 3: Restore Access Risk on Backup Archive (Rule 14).

    An unblocked backup archive allows residual customer records to be restored.
    The pipeline must detect the restore risk (REPORT_RESTORE_RISK), propose blocking
    remediation (BLOCK_RESTORE), and future verification (VERIFY_RESTORE_BLOCKED with empty evidence_id).
    """
    subject = ResolvedIdentity(
        case_id="eval_case_03",
        user_id="user_103",
        status="RESOLVED",
        current_email="carol.eval@example.com",
    )

    backup_item = NormalizedEvidenceItem(
        evidence_id="evidence_93",
        evidence_type="JSON",
        origin="backup_service",
        resource_id="backup_7741",
        system_id="backup_service",
        user_id="user_103",
        status="ACTIVE",
        captured_at="2026-09-15T11:00:00Z",
        raw_payload={"restore_allowed": True, "archive_key": "s3://backups/user_103.tar.gz"},
    )

    eval_result = policy_engine.evaluate_case(
        case_id="eval_case_03",
        request_text="Please delete my account and ensure my data cannot be restored from backups.",
        resolved_identity=subject,
        subject_evidence=[backup_item],
    )

    assert eval_result.deletion_status == DeletionStatus.INCOMPLETE
    assert len(eval_result.findings) >= 1
    finding = eval_result.findings[0]
    assert finding.resource_id == "backup_7741"
    assert finding.operation == Operation.REPORT_RESTORE_RISK
    assert finding.remediation_operation == Operation.BLOCK_RESTORE

    planned = plan_case(eval_result)
    steps = planned.steps
    assert steps[0].phase == Phase.FINDING
    assert steps[0].operation == Operation.REPORT_RESTORE_RISK
    assert steps[0].evidence_id == "evidence_93"

    assert steps[1].phase == Phase.REMEDIATION
    assert steps[1].operation == Operation.BLOCK_RESTORE
    assert steps[1].evidence_id == ""

    verif_steps = [s for s in steps if s.phase == Phase.VERIFICATION and s.resource_id == "backup_7741"]
    assert len(verif_steps) == 1
    assert verif_steps[0].operation == Operation.VERIFY_RESTORE_BLOCKED
    assert verif_steps[0].state == State.BLOCKED
    assert verif_steps[0].evidence_id == ""
