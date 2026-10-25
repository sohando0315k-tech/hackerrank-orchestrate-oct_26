"""Unit tests for statutory policy engine (Sprint 3A).

Verifies:
1. Dynamic loading of 15 statutory deletion rules from deletion_rules.csv.
2. Resource classification and data category mapping across all rules.
3. Policy violations producing exact findings and operation contracts.
4. Compliant records producing exact verification checks.
5. Scoped retention exceptions preserving requested records.
6. Account tombstones distinguishing compliant vs PII-exposing states.
7. Active data flow and backup restore risk detection.
8. Case-level status determination (COMPLETE, INCOMPLETE, NOT_APPLICABLE).
9. Strict evidence citation rules (empty string for INCOMPLETE verifications).
10. Cross-subject canonical user-ID isolation.
"""

from pathlib import Path
import pytest

from code.models import DeletionStatus, Operation, Phase, State
from code.identity import ResolvedIdentity
from code.evidence import NormalizedEvidenceItem
from code.rules import IntentResult, RequestIntent
from code.policy import (
    DataCategory,
    PolicyEngine,
    PolicyFinding,
    PolicyRule,
    PolicyVerification,
    RequiredAction,
    classify_resource_category,
    infer_system_id,
    is_analytics_compliant,
    is_backup_compliant,
    is_data_flow_compliant,
    is_support_message_compliant,
    is_tombstone_compliant,
)


@pytest.fixture
def rules_path():
    return Path("dataset/deletion_rules.csv")


@pytest.fixture
def policy_engine(rules_path):
    return PolicyEngine(rules_path)


@pytest.fixture
def resolved_subject():
    return ResolvedIdentity(
        case_id="case_test_01",
        user_id="user_100",
        status="RESOLVED",
        current_email="test.user@example.com",
        current_name="Test User",
        current_phone="+1234567890",
        historical_emails={"test.user@example.com"},
        historical_phones={"+1234567890"},
        historical_names={"Test User"},
        email_hashes=set(),
    )


@pytest.fixture
def deletion_intent():
    return IntentResult(
        intent=RequestIntent.DELETION,
        is_deletion_authorized=True,
        confidence=1.0,
        detected_language="English",
        reasons=["Explicit deletion requested"],
    )


# --- 1. Rules Loading & Dynamic Validation ---

def test_load_statutory_rules(policy_engine):
    """Verify all 15 statutory deletion rules are dynamically loaded."""
    assert len(policy_engine.rules) == 15
    expected_rules = [f"rule_{i:02d}" for i in range(1, 16)]
    for r_id in expected_rules:
        assert r_id in policy_engine.rules
        rule = policy_engine.rules[r_id]
        assert isinstance(rule, PolicyRule)
        assert rule.rule_id == r_id
        assert rule.data_category != DataCategory.UNKNOWN
        assert isinstance(rule.required_action, RequiredAction)

    # Specific rule expectations
    assert policy_engine.rules["rule_01"].data_category == DataCategory.USER_PROFILE
    assert policy_engine.rules["rule_01"].required_action == RequiredAction.DELETE

    assert policy_engine.rules["rule_05"].data_category == DataCategory.SUPPORT_MESSAGE
    assert policy_engine.rules["rule_05"].required_action == RequiredAction.REDACT

    assert policy_engine.rules["rule_07"].data_category == DataCategory.ANALYTICS_PROFILE
    assert policy_engine.rules["rule_07"].required_action == RequiredAction.ANONYMIZE

    assert policy_engine.rules["rule_12"].data_category == DataCategory.SECURITY_AUDIT_LOG
    assert policy_engine.rules["rule_12"].required_action == RequiredAction.RETAIN

    assert policy_engine.rules["rule_14"].data_category == DataCategory.BACKUP_ARCHIVE
    assert policy_engine.rules["rule_14"].required_action == RequiredAction.RETAIN

    assert policy_engine.rules["rule_15"].data_category == DataCategory.ACCOUNT_TOMBSTONE
    assert policy_engine.rules["rule_15"].required_action == RequiredAction.REDACT


# --- 2. Resource Category Classification ---

def test_classify_resource_category():
    """Verify resource classification across prefixes and payload hints."""
    cat, sys = classify_resource_category("account_001")
    assert cat == DataCategory.USER_PROFILE
    assert sys == "account_service"

    cat, sys = classify_resource_category("search_450")
    assert cat == DataCategory.SEARCH_INDEX_ENTRY
    assert sys == "search_service"

    cat, sys = classify_resource_category("support_101", raw_payload={"attachment": "id_card.png"})
    assert cat == DataCategory.SUPPORT_ATTACHMENT
    assert sys == "support_platform"

    cat, sys = classify_resource_category("support_101", raw_payload={"message_excerpt": "Hello"})
    assert cat == DataCategory.SUPPORT_MESSAGE
    assert sys == "support_platform"

    cat, sys = classify_resource_category("analytics_505")
    assert cat == DataCategory.ANALYTICS_PROFILE
    assert sys == "analytics_platform"

    cat, sys = classify_resource_category("audit_record_99")
    assert cat == DataCategory.SECURITY_AUDIT_LOG
    assert sys == "security_service"

    cat, sys = classify_resource_category("backup_1234")
    assert cat == DataCategory.BACKUP_ARCHIVE
    assert sys == "backup_service"

    cat, sys = classify_resource_category("data_flow_881")
    assert cat == DataCategory.DATA_FLOW
    assert sys == "integration_service"

    cat, sys = classify_resource_category("tombstone_777")
    assert cat == DataCategory.ACCOUNT_TOMBSTONE
    assert sys == "identity_service"

    cat, sys = classify_resource_category("export_333")
    assert cat == DataCategory.USER_EXPORT
    assert sys == "export_service"


# --- 3. Violation Findings Across Rules ---

def test_remaining_user_profile_finding(policy_engine, resolved_subject, deletion_intent):
    """Verify active user profile generates REPORT_REMAINING_RECORD finding."""
    item = NormalizedEvidenceItem(
        evidence_id="evidence_54",
        evidence_type="SQL",
        origin="failover_replica",
        resource_id="account_100",
        system_id="account_service",
        user_id="user_100",
        status="ACTIVE",
        raw_payload={"email": "test.user@example.com"},
    )
    finding, verif = policy_engine.evaluate_resource("account_100", [item], resolved_subject, deletion_intent)
    assert finding is not None
    assert finding.operation == Operation.REPORT_REMAINING_RECORD
    assert finding.state == State.PRESENT
    assert finding.remediation_operation == Operation.DELETE_RECORD
    assert finding.verification_operation == Operation.VERIFY_RECORD_ABSENT
    assert finding.evidence_id == "evidence_54"


def test_support_message_pii_finding(policy_engine, resolved_subject, deletion_intent):
    """Verify unredacted support message generates REPORT_EXPOSED_PII finding."""
    item = NormalizedEvidenceItem(
        evidence_id="evidence_60",
        evidence_type="JSON",
        origin="support_platform",
        resource_id="support_200",
        system_id="support_platform",
        user_id="user_100",
        status="PRESENT",
        raw_payload={"requester_email": "test.user@example.com", "message": "My order is delayed"},
    )
    finding, verif = policy_engine.evaluate_resource("support_200", [item], resolved_subject, deletion_intent)
    assert finding is not None
    assert finding.operation == Operation.REPORT_EXPOSED_PII
    assert finding.state == State.PRESENT
    assert finding.remediation_operation == Operation.REDACT_RECORD
    assert finding.verification_operation == Operation.VERIFY_RECORD_REDACTED
    assert finding.evidence_id == "evidence_60"


def test_attributable_analytics_finding(policy_engine, resolved_subject, deletion_intent):
    """Verify attributable analytics generates REPORT_EXPOSED_PII finding."""
    item = NormalizedEvidenceItem(
        evidence_id="evidence_56",
        evidence_type="JSON",
        origin="analytics_platform",
        resource_id="analytics_300",
        system_id="analytics_platform",
        user_id="user_100",
        status="ACTIVE",
        raw_payload={"attributable": True, "customer_reference": "user_100"},
    )
    finding, verif = policy_engine.evaluate_resource("analytics_300", [item], resolved_subject, deletion_intent)
    assert finding is not None
    assert finding.operation == Operation.REPORT_EXPOSED_PII
    assert finding.state == State.PRESENT
    assert finding.remediation_operation == Operation.ANONYMIZE_RECORD
    assert finding.verification_operation == Operation.VERIFY_RECORD_ANONYMIZED
    assert finding.evidence_id == "evidence_56"


def test_tombstone_pii_finding(policy_engine, resolved_subject, deletion_intent):
    """Verify tombstone containing personal data generates REPORT_EXPOSED_PII finding."""
    item = NormalizedEvidenceItem(
        evidence_id="evidence_51",
        evidence_type="JSON",
        origin="identity_service",
        resource_id="tombstone_400",
        system_id="identity_service",
        user_id="user_100",
        status="PRESENT",
        raw_payload={"user_id": "user_100", "email": "test.user@example.com"},
    )
    finding, verif = policy_engine.evaluate_resource("tombstone_400", [item], resolved_subject, deletion_intent)
    assert finding is not None
    assert finding.operation == Operation.REPORT_EXPOSED_PII
    assert finding.remediation_operation == Operation.REDACT_RECORD
    assert finding.verification_operation == Operation.VERIFY_RECORD_REDACTED


def test_active_data_flow_finding(policy_engine, resolved_subject, deletion_intent):
    """Verify active data flow generates REPORT_ACTIVE_DATA_FLOW finding."""
    item = NormalizedEvidenceItem(
        evidence_id="evidence_92",
        evidence_type="JSON",
        origin="integration_service",
        resource_id="data_flow_500",
        system_id="integration_service",
        user_id="user_100",
        status="ACTIVE",
        raw_payload={"enabled": True, "connector_name": "profile_replicator"},
    )
    finding, verif = policy_engine.evaluate_resource("data_flow_500", [item], resolved_subject, deletion_intent)
    assert finding is not None
    assert finding.operation == Operation.REPORT_ACTIVE_DATA_FLOW
    assert finding.state == State.ACTIVE
    assert finding.remediation_operation == Operation.DISABLE_DATA_FLOW
    assert finding.verification_operation == Operation.VERIFY_DATA_FLOW_DISABLED


def test_unblocked_backup_restore_risk_finding(policy_engine, resolved_subject, deletion_intent):
    """Verify unblocked backup generates REPORT_RESTORE_RISK finding."""
    item = NormalizedEvidenceItem(
        evidence_id="evidence_93",
        evidence_type="JSON",
        origin="backup_service",
        resource_id="backup_600",
        system_id="backup_service",
        user_id="user_100",
        status="PRESENT",
        raw_payload={"restore_allowed": True},
    )
    finding, verif = policy_engine.evaluate_resource("backup_600", [item], resolved_subject, deletion_intent)
    assert finding is not None
    assert finding.operation == Operation.REPORT_RESTORE_RISK
    assert finding.state == State.ACTIVE
    assert finding.remediation_operation == Operation.BLOCK_RESTORE
    assert finding.verification_operation == Operation.VERIFY_RESTORE_BLOCKED


# --- 4. Compliant States & Verifications ---

def test_absent_record_verification(policy_engine, resolved_subject, deletion_intent):
    """Verify absent record produces VERIFY_RECORD_ABSENT without finding."""
    item = NormalizedEvidenceItem(
        evidence_id="evidence_54",
        evidence_type="SQL",
        origin="failover_replica",
        resource_id="account_100",
        system_id="account_service",
        user_id="user_100",
        status="ABSENT",
    )
    finding, verif = policy_engine.evaluate_resource("account_100", [item], resolved_subject, deletion_intent)
    assert finding is None
    assert verif is not None
    assert verif.operation == Operation.VERIFY_RECORD_ABSENT
    assert verif.state == State.ABSENT
    assert verif.evidence_id == "evidence_54"


def test_statutory_security_audit_preservation(policy_engine, resolved_subject, deletion_intent):
    """Verify security audit log is preserved per Rule 12 with VERIFY_RECORD_PRESENT."""
    item = NormalizedEvidenceItem(
        evidence_id="evidence_94",
        evidence_type="LOG",
        origin="security_service",
        resource_id="audit_record_700",
        system_id="security_service",
        user_id="user_100",
        status="PRESENT",
        retention_flag=True,
    )
    finding, verif = policy_engine.evaluate_resource("audit_record_700", [item], resolved_subject, deletion_intent)
    assert finding is None
    assert verif is not None
    assert verif.operation == Operation.VERIFY_RECORD_PRESENT
    assert verif.state == State.PRESENT
    assert verif.evidence_id == "evidence_94"


def test_compliant_tombstone_redacted(policy_engine, resolved_subject, deletion_intent):
    """Verify tombstone with only user_id preserved is compliant (Rule 15)."""
    item = NormalizedEvidenceItem(
        evidence_id="evidence_51",
        evidence_type="JSON",
        origin="identity_service",
        resource_id="tombstone_800",
        system_id="identity_service",
        user_id="user_100",
        status="PRESENT",
        raw_payload={"user_id": "user_100", "email": None, "full_name": None},
    )
    finding, verif = policy_engine.evaluate_resource("tombstone_800", [item], resolved_subject, deletion_intent)
    assert finding is None
    assert verif is not None
    assert verif.operation == Operation.VERIFY_RECORD_REDACTED
    assert verif.state == State.REDACTED
    assert verif.evidence_id == "evidence_51"


def test_compliant_anonymized_analytics(policy_engine, resolved_subject, deletion_intent):
    """Verify anonymized analytics is compliant (Rule 07)."""
    item = NormalizedEvidenceItem(
        evidence_id="evidence_56",
        evidence_type="JSON",
        origin="analytics_platform",
        resource_id="analytics_900",
        system_id="analytics_platform",
        user_id="user_100",
        status="ANONYMIZED",
        raw_payload={"attributable": False},
    )
    finding, verif = policy_engine.evaluate_resource("analytics_900", [item], resolved_subject, deletion_intent)
    assert finding is None
    assert verif is not None
    assert verif.operation == Operation.VERIFY_RECORD_ANONYMIZED
    assert verif.state == State.ANONYMIZED


def test_compliant_disabled_data_flow(policy_engine, resolved_subject, deletion_intent):
    """Verify disabled connector is compliant with VERIFY_DATA_FLOW_DISABLED."""
    item = NormalizedEvidenceItem(
        evidence_id="evidence_92",
        evidence_type="JSON",
        origin="integration_service",
        resource_id="data_flow_1000",
        system_id="integration_service",
        user_id="user_100",
        status="DISABLED",
        raw_payload={"enabled": False},
    )
    finding, verif = policy_engine.evaluate_resource("data_flow_1000", [item], resolved_subject, deletion_intent)
    assert finding is None
    assert verif is not None
    assert verif.operation == Operation.VERIFY_DATA_FLOW_DISABLED
    assert verif.state == State.DISABLED


def test_compliant_blocked_backup(policy_engine, resolved_subject, deletion_intent):
    """Verify blocked backup archive is compliant with VERIFY_RESTORE_BLOCKED."""
    item = NormalizedEvidenceItem(
        evidence_id="evidence_92",
        evidence_type="JSON",
        origin="backup_service",
        resource_id="backup_1100",
        system_id="backup_service",
        user_id="user_100",
        status="BLOCKED",
        raw_payload={"restore_allowed": False},
    )
    finding, verif = policy_engine.evaluate_resource("backup_1100", [item], resolved_subject, deletion_intent)
    assert finding is None
    assert verif is not None
    assert verif.operation == Operation.VERIFY_RESTORE_BLOCKED
    assert verif.state == State.BLOCKED


# --- 5. Scoped Retention Exception Preservation ---

def test_scoped_retention_exception_preservation(policy_engine, resolved_subject):
    """Verify that scoped retention exceptions (e.g. tax records) preserve records as VERIFY_RECORD_PRESENT."""
    intent_with_exc = IntentResult(
        intent=RequestIntent.DELETION,
        is_deletion_authorized=True,
        confidence=1.0,
        detected_language="English",
        retention_exceptions=["tax records and billing invoices"],
    )
    tax_item = NormalizedEvidenceItem(
        evidence_id="evidence_80",
        evidence_type="JSON",
        origin="billing_service",
        resource_id="billing_invoice_99",
        system_id="billing_service",
        user_id="user_100",
        status="PRESENT",
    )
    finding, verif = policy_engine.evaluate_resource("billing_invoice_99", [tax_item], resolved_subject, intent_with_exc)
    assert finding is None
    assert verif is not None
    assert verif.operation == Operation.VERIFY_RECORD_PRESENT
    assert verif.state == State.PRESENT
    assert "tax records" in verif.reason


# --- 6. Cross-Subject Canonical User-ID Isolation ---

def test_cross_subject_isolation_in_resource_evaluation(policy_engine, resolved_subject, deletion_intent):
    """Verify evidence items with conflicting canonical user IDs are ignored."""
    alien_item = NormalizedEvidenceItem(
        evidence_id="evidence_99",
        evidence_type="SQL",
        origin="failover_replica",
        resource_id="account_999",
        system_id="account_service",
        user_id="user_999",  # Conflicting canonical user ID
        status="ACTIVE",
    )
    finding, verif = policy_engine.evaluate_resource("account_999", [alien_item], resolved_subject, deletion_intent)
    assert finding is None
    assert verif is None


# --- 7. Case-Level Policy Decision & Evidence Citation Contract ---

def test_case_evaluation_not_applicable(policy_engine, resolved_subject):
    """Verify non-deletion request results in NOT_APPLICABLE with zero steps."""
    res = policy_engine.evaluate_case(
        case_id="case_optout",
        request_text="Please stop promotional emails. I am not asking for deletion.",
        resolved_identity=resolved_subject,
        subject_evidence=[],
    )
    assert res.deletion_status == DeletionStatus.NOT_APPLICABLE
    assert len(res.findings) == 0
    assert len(res.verifications) == 0


def test_case_evaluation_complete(policy_engine, resolved_subject, deletion_intent):
    """Verify fully compliant case results in COMPLETE with verified evidence IDs."""
    items = [
        NormalizedEvidenceItem(
            evidence_id="evidence_54",
            evidence_type="SQL",
            origin="failover_replica",
            resource_id="account_100",
            system_id="account_service",
            user_id="user_100",
            status="ABSENT",
        ),
        NormalizedEvidenceItem(
            evidence_id="evidence_94",
            evidence_type="LOG",
            origin="security_service",
            resource_id="audit_record_200",
            system_id="security_service",
            user_id="user_100",
            status="PRESENT",
            retention_flag=True,
        ),
    ]
    res = policy_engine.evaluate_case(
        case_id="case_comp",
        request_text="Delete my account permanently.",
        resolved_identity=resolved_subject,
        subject_evidence=items,
        intent_result=deletion_intent,
    )
    assert res.deletion_status == DeletionStatus.COMPLETE
    assert len(res.findings) == 0
    assert len(res.verifications) == 2
    # In COMPLETE cases, all verifications MUST cite non-empty authentic evidence IDs
    for v in res.verifications:
        assert v.evidence_id != ""


def test_case_evaluation_incomplete_enforces_empty_verification_evidence_id(
    policy_engine, resolved_subject, deletion_intent
):
    """Verify INCOMPLETE case enforces non-empty finding evidence_id, but empty verification evidence_id."""
    items = [
        # Non-compliant user profile
        NormalizedEvidenceItem(
            evidence_id="evidence_54",
            evidence_type="SQL",
            origin="failover_replica",
            resource_id="account_100",
            system_id="account_service",
            user_id="user_100",
            status="ACTIVE",
        ),
        # Retained security audit log
        NormalizedEvidenceItem(
            evidence_id="evidence_94",
            evidence_type="LOG",
            origin="security_service",
            resource_id="audit_record_200",
            system_id="security_service",
            user_id="user_100",
            status="PRESENT",
            retention_flag=True,
        ),
    ]
    res = policy_engine.evaluate_case(
        case_id="case_incomp",
        request_text="Delete my account permanently.",
        resolved_identity=resolved_subject,
        subject_evidence=items,
        intent_result=deletion_intent,
    )
    assert res.deletion_status == DeletionStatus.INCOMPLETE
    assert len(res.findings) == 1
    assert res.findings[0].evidence_id == "evidence_54"
    assert len(res.verifications) == 2
    # In INCOMPLETE cases, all proposed future verifications MUST have evidence_id == ""
    for v in res.verifications:
        assert v.evidence_id == ""

# -----------------------------------------------------------------------------
# Sprint 3C Tests: Primary Account Absence Verification
# -----------------------------------------------------------------------------

def test_case_evaluation_primary_account_absence_in_complete_case(
    policy_engine, deletion_intent
) -> None:
    """Verify that a COMPLETE case with absent primary profile verifies account absence citing snapshot."""
    user = ResolvedIdentity(
        case_id="case_01",
        user_id="user_01",
        current_name="Maria Silva",
        current_email="maria.silva@example.com",
    )
    items = [
        NormalizedEvidenceItem(
            evidence_id="evidence_92",
            evidence_type="JSON",
            origin="service_resource_export",
            resource_id="audit_record_10",
            system_id="security_service",
            user_id="user_01",
            status="PRESENT",
            retention_flag=True,
        )
    ]
    res = policy_engine.evaluate_case(
        case_id="case_01",
        request_text="Please delete my account and verify that profile is gone.",
        resolved_identity=user,
        subject_evidence=items,
        intent_result=deletion_intent,
    )
    assert res.deletion_status == DeletionStatus.COMPLETE
    acc_verifs = [v for v in res.verifications if v.resource_id == "account_001"]
    assert len(acc_verifs) == 1
    assert acc_verifs[0].operation == Operation.VERIFY_RECORD_ABSENT
    assert acc_verifs[0].state == State.ABSENT
    assert acc_verifs[0].evidence_id == "evidence_92"


def test_case_evaluation_primary_account_absence_in_incomplete_case(
    policy_engine, deletion_intent
) -> None:
    """Verify that an INCOMPLETE case with primary account absence uses empty evidence_id."""
    user = ResolvedIdentity(
        case_id="case_06",
        user_id="user_06",
        current_name="Alex Wang",
        current_email="alex.wang@example.com",
    )
    items = [
        NormalizedEvidenceItem(
            evidence_id="evidence_57",
            evidence_type="SQL",
            origin="search_service",
            resource_id="search_001",
            system_id="search_service",
            user_id="user_06",
            status="PRESENT",
        )
    ]
    res = policy_engine.evaluate_case(
        case_id="case_06",
        request_text="Delete my profile and search entries.",
        resolved_identity=user,
        subject_evidence=items,
        intent_result=deletion_intent,
    )
    assert res.deletion_status == DeletionStatus.INCOMPLETE
    assert len(res.findings) == 1
    acc_verifs = [v for v in res.verifications if v.resource_id == "account_006"]
    assert len(acc_verifs) == 1
    assert acc_verifs[0].operation == Operation.VERIFY_RECORD_ABSENT
    assert acc_verifs[0].evidence_id == ""

