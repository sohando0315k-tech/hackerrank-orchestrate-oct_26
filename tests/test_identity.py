"""Unit tests for multi-hop identity resolution."""

import pandas as pd
import pytest

from code.identity import IdentityGraph, ResolvedIdentity, resolve_subject_identity


@pytest.fixture
def sample_identities():
    """Synthetic identities DataFrame."""
    return pd.DataFrame([
        {
            "user_id": "user_01",
            "name": "Alice Smith",
            "email": "alice.active@example.com",
            "phone": "+1-555-0101",
            "email_hash": "hash_alice_active",
            "updated_at": "2026-05-01T12:00:00Z",
        },
        {
            "user_id": "user_02",
            "name": "Bob Jones",
            "email": "bob.current@example.com",
            "phone": "+1-555-0202",
            "email_hash": "hash_bob_current",
            "updated_at": "2026-04-15T10:00:00Z",
        },
        {
            "user_id": "user_03",
            "name": "Carol White",
            "email": "carol.c@example.com",
            "phone": "+1-555-0303",
            "email_hash": "hash_carol_c",
            "updated_at": "2026-06-01T08:00:00Z",
        },
    ])


@pytest.fixture
def sample_audit_log():
    """Synthetic audit log DataFrame covering multiple mutations and chains."""
    return pd.DataFrame([
        # Bob Jones: historical email change bob.old@example.com -> bob.current@example.com
        {
            "audit_id": "aud_01",
            "user_id": "user_02",
            "event_time": "2025-06-01T09:00:00Z",
            "field_name": "email",
            "old_value": "bob.old@example.com",
            "new_value": "bob.current@example.com",
        },
        {
            "audit_id": "aud_02",
            "user_id": "user_02",
            "event_time": "2025-06-01T09:00:00Z",
            "field_name": "email_hash",
            "old_value": "hash_bob_old",
            "new_value": "hash_bob_current",
        },
        {
            "audit_id": "aud_03",
            "user_id": "user_02",
            "event_time": "2025-07-01T10:00:00Z",
            "field_name": "phone",
            "old_value": "+1-555-0201",
            "new_value": "+1-555-0202",
        },
        # Carol White: multi-hop email chain carol.first@example.com -> carol.second@example.com -> carol.c@example.com
        {
            "audit_id": "aud_04",
            "user_id": "user_03",
            "event_time": "2025-01-10T12:00:00Z",
            "field_name": "email",
            "old_value": "carol.first@example.com",
            "new_value": "carol.second@example.com",
        },
        {
            "audit_id": "aud_05",
            "user_id": "user_03",
            "event_time": "2025-08-20T14:00:00Z",
            "field_name": "email",
            "old_value": "carol.second@example.com",
            "new_value": "carol.c@example.com",
        },
        # Carol White: future change that happened on 2026-09-01
        {
            "audit_id": "aud_06",
            "user_id": "user_03",
            "event_time": "2026-09-01T15:00:00Z",
            "field_name": "email",
            "old_value": "carol.c@example.com",
            "new_value": "carol.future@example.com",
        },
    ])


def test_exact_current_email_match(sample_identities, sample_audit_log):
    """Verify direct resolution of an active email in user_identities."""
    res = resolve_subject_identity(
        case_id="case_101",
        request_email="alice.active@example.com",
        identities_df=sample_identities,
        audit_log_df=sample_audit_log,
    )
    assert res.is_resolved
    assert res.status == "RESOLVED"
    assert res.user_id == "user_01"
    assert res.current_name == "Alice Smith"
    assert res.current_email == "alice.active@example.com"
    assert res.current_phone == "+1-555-0101"
    assert "hash_alice_active" in res.email_hashes
    assert res.provenance.get("user_01") == "user_identities.user_id"


def test_historical_email_match(sample_identities, sample_audit_log):
    """Verify resolution of an old email alias recorded in user_audit_log."""
    res = resolve_subject_identity(
        case_id="case_102",
        request_email="bob.old@example.com",
        identities_df=sample_identities,
        audit_log_df=sample_audit_log,
    )
    assert res.is_resolved
    assert res.status == "RESOLVED"
    assert res.user_id == "user_02"
    assert res.current_email == "bob.current@example.com"
    assert "bob.old@example.com" in res.historical_emails
    assert "bob.current@example.com" in res.all_emails
    assert "+1-555-0201" in res.historical_phones
    assert "+1-555-0202" in res.all_phones
    assert "hash_bob_old" in res.email_hashes
    assert "hash_bob_current" in res.email_hashes
    assert "user_audit_log.old_value:aud_01" in res.provenance.get("bob.old@example.com", "")


def test_multi_hop_email_chain(sample_identities, sample_audit_log):
    """Verify resolution through a multi-step rename chain (carol.first -> carol.second -> carol.c)."""
    res = resolve_subject_identity(
        case_id="case_103",
        request_email="carol.first@example.com",
        identities_df=sample_identities,
        audit_log_df=sample_audit_log,
        audit_at="2026-06-15T00:00:00Z",
    )
    assert res.is_resolved
    assert res.user_id == "user_03"
    assert res.current_email == "carol.c@example.com"
    assert "carol.first@example.com" in res.historical_emails
    assert "carol.second@example.com" in res.historical_emails


def test_temporal_cutoff_isolation(sample_identities, sample_audit_log):
    """Verify that an email change occurring AFTER audit_at is strictly ignored."""
    # carol.future@example.com happened on 2026-09-01.
    # At cutoff 2026-07-01, carol.future did not exist!
    res = resolve_subject_identity(
        case_id="case_104",
        request_email="carol.future@example.com",
        identities_df=sample_identities,
        audit_log_df=sample_audit_log,
        audit_at="2026-07-01T00:00:00Z",
    )
    assert not res.is_resolved
    assert res.status == "UNRESOLVED"
    assert "carol.future@example.com" in (res.ambiguity_reason or "")


def test_case_and_whitespace_normalization(sample_identities, sample_audit_log):
    """Verify resolution succeeds regardless of email casing or extraneous whitespace."""
    res = resolve_subject_identity(
        case_id="case_105",
        request_email="  ALICE.ACTIVE@EXAMPLE.COM  ",
        identities_df=sample_identities,
        audit_log_df=sample_audit_log,
    )
    assert res.is_resolved
    assert res.user_id == "user_01"


def test_unknown_email_returns_unresolved(sample_identities, sample_audit_log):
    """Verify unlinked email safely returns UNRESOLVED with zero hallucinated user_id."""
    res = resolve_subject_identity(
        case_id="case_106",
        request_email="unknown.stranger@example.com",
        identities_df=sample_identities,
        audit_log_df=sample_audit_log,
    )
    assert not res.is_resolved
    assert res.status == "UNRESOLVED"
    assert res.user_id is None
    assert res.confidence == 0.0


def test_empty_or_malformed_email(sample_identities, sample_audit_log):
    """Verify empty or None email inputs are handled safely."""
    res1 = resolve_subject_identity("c1", "", sample_identities, sample_audit_log)
    assert not res1.is_resolved
    assert res1.status == "UNRESOLVED"

    res2 = resolve_subject_identity("c2", None, sample_identities, sample_audit_log)
    assert not res2.is_resolved
    assert res2.status == "UNRESOLVED"


def test_ambiguous_identity_mapping():
    """Verify that if an email maps to multiple distinct user_ids, it returns AMBIGUOUS."""
    identities = pd.DataFrame([
        {"user_id": "u1", "email": "shared@example.com", "name": "User 1", "phone": "1", "email_hash": "h1"},
        {"user_id": "u2", "email": "other@example.com", "name": "User 2", "phone": "2", "email_hash": "h2"},
    ])
    # Audit log maps shared@example.com to u2 as well
    audit_log = pd.DataFrame([
        {"audit_id": "a1", "user_id": "u2", "event_time": "2025-01-01T00:00:00Z", "field_name": "email", "old_value": "shared@example.com", "new_value": "other@example.com"},
    ])

    res = resolve_subject_identity("case_ambig", "shared@example.com", identities, audit_log)
    assert not res.is_resolved
    assert res.status == "AMBIGUOUS"
    assert "conflicting users" in res.ambiguity_reason


def test_deterministic_regardless_of_row_ordering(sample_identities, sample_audit_log):
    """Verify identity resolution output is strictly deterministic when inputs are shuffled."""
    shuffled_identities = sample_identities.sample(frac=1.0, random_state=42)
    shuffled_audit = sample_audit_log.sample(frac=1.0, random_state=42)

    res1 = resolve_subject_identity("c1", "bob.old@example.com", sample_identities, sample_audit_log)
    res2 = resolve_subject_identity("c1", "bob.old@example.com", shuffled_identities, shuffled_audit)

    assert res1.user_id == res2.user_id
    assert res1.status == res2.status
    assert res1.all_emails == res2.all_emails
    assert res1.all_phones == res2.all_phones
    assert res1.email_hashes == res2.email_hashes


def test_no_cross_user_merges(sample_identities, sample_audit_log):
    """Verify that identifiers from distinct subjects are never merged."""
    alice = resolve_subject_identity("c_alice", "alice.active@example.com", sample_identities, sample_audit_log)
    bob = resolve_subject_identity("c_bob", "bob.current@example.com", sample_identities, sample_audit_log)

    assert alice.user_id != bob.user_id
    assert len(alice.all_emails.intersection(bob.all_emails)) == 0
    assert len(alice.all_phones.intersection(bob.all_phones)) == 0


def test_timezone_offsets_and_instant_comparisons():
    """Verify that audit log timestamps with +01:00, -05:00, and Z are compared by actual UTC instant."""
    identities = pd.DataFrame([
        {"user_id": "u_tz", "email": "current.tz@example.com", "name": "TZ User", "phone": "123", "email_hash": "h_tz"},
    ])

    # Audit event happened at 12:00:00+01:00 (which is 11:00:00 UTC)
    audit_log = pd.DataFrame([
        {
            "audit_id": "aud_tz_1",
            "user_id": "u_tz",
            "event_time": "2026-05-01T12:00:00+01:00",
            "field_name": "email",
            "old_value": "old.tz1@example.com",
            "new_value": "current.tz@example.com",
        },
        {
            "audit_id": "aud_tz_2",
            "user_id": "u_tz",
            "event_time": "2026-05-01T06:00:00-05:00",  # Also 11:00:00 UTC
            "field_name": "email",
            "old_value": "old.tz2@example.com",
            "new_value": "old.tz1@example.com",
        },
        {
            "audit_id": "aud_tz_3",
            "user_id": "u_tz",
            "event_time": "2026-05-01T11:30:01Z",  # 1 second AFTER cutoff (future event)
            "field_name": "email",
            "old_value": "future.alias@example.com",
            "new_value": "old.tz2@example.com",
        },
    ])

    # Cutoff at 11:30:00 UTC
    audit_at_cutoff = "2026-05-01T11:30:00Z"

    # Both tz1 and tz2 occurred at 11:00:00 UTC, which is BEFORE 11:30:00 UTC cutoff
    res1 = resolve_subject_identity("c_tz1", "old.tz1@example.com", identities, audit_log, audit_at=audit_at_cutoff)
    assert res1.is_resolved
    assert res1.user_id == "u_tz"

    res2 = resolve_subject_identity("c_tz2", "old.tz2@example.com", identities, audit_log, audit_at=audit_at_cutoff)
    assert res2.is_resolved
    assert res2.user_id == "u_tz"

    # Future alias occurred at 11:30:01 UTC, which is AFTER 11:30:00 UTC cutoff -> must not resolve
    res_fut = resolve_subject_identity("c_fut", "future.alias@example.com", identities, audit_log, audit_at=audit_at_cutoff)
    assert not res_fut.is_resolved
    assert res_fut.status == "UNRESOLVED"


def test_unparseable_and_naive_timestamps_handling():
    """Verify conservative rejection of unparseable, malformed, or timezone-naive timestamps."""
    identities = pd.DataFrame([
        {"user_id": "u_bad", "email": "curr.bad@example.com", "name": "Bad TS", "phone": "456", "email_hash": "h_bad"},
    ])
    audit_log = pd.DataFrame([
        # Timezone-naive timestamp
        {"audit_id": "a_naive", "user_id": "u_bad", "event_time": "2026-05-01 11:00:00", "field_name": "email", "old_value": "naive@example.com", "new_value": "curr.bad@example.com"},
        # Malformed timestamp
        {"audit_id": "a_malformed", "user_id": "u_bad", "event_time": "not-a-timestamp", "field_name": "email", "old_value": "malformed@example.com", "new_value": "curr.bad@example.com"},
    ])

    # With cutoff enforced: naive and malformed timestamps cannot be verified as prior to cutoff
    res_naive = resolve_subject_identity("c_n", "naive@example.com", identities, audit_log, audit_at="2026-05-01T12:00:00Z")
    assert not res_naive.is_resolved

    res_mal = resolve_subject_identity("c_m", "malformed@example.com", identities, audit_log, audit_at="2026-05-01T12:00:00Z")
    assert not res_mal.is_resolved

    # Malformed audit_at cutoff
    res_bad_cutoff = resolve_subject_identity("c_cut", "curr.bad@example.com", identities, audit_log, audit_at="invalid-cutoff")
    assert not res_bad_cutoff.is_resolved
    assert "invalid, malformed, or timezone-naive" in res_bad_cutoff.ambiguity_reason
