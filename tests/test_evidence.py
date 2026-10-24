"""Comprehensive unit and integration test suite for Evidence Corpus Pre-Indexer (Sprint 2).

Tests adhere strictly to:
- Offline determinism (0 network calls, standard library and project modules only).
- Official citations only (never generate synthetic evidence IDs for real records).
- Temporal cutoff enforcement (before, at, after audit_at, timezone conversions).
- Multi-format ingestion (SQL, JSON, LOG, PDF, PNG, TEXT, SYSTEM_ACTIVITY, AUDIT_LOG).
- Replica drift handling.
- Deterministic ordering and zero cross-subject leakage.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
import sqlite3
import tempfile
from typing import List
import zlib

import pandas as pd
import pytest

from code.config import AppConfig
from code.evidence import (
    EvidenceCorpus,
    EvidenceCorpusIndex,
    EvidenceReference,
    NormalizedEvidenceItem,
    infer_system_id,
    parse_handover_txt,
    parse_json_bundle,
    parse_log_file,
    parse_pdf_document,
    parse_png_metadata,
    parse_sql_dump,
    parse_system_activity,
    parse_user_audit_log,
)
from code.identity import IdentityGraph, ResolvedIdentity, parse_iso_timestamp


# -----------------------------------------------------------------------------
# 1. SQL Schema Parsing & Replica Drift
# -----------------------------------------------------------------------------

def test_sql_parser_primary_and_replica_drift(tmp_path: Path) -> None:
    """Test SQL ingestion across primary and failover replica tables with state drift."""
    sql_file = tmp_path / "test_replica.sql"
    sql_content = """
    CREATE TABLE customer_profiles_primary (
        resource_id TEXT PRIMARY KEY,
        user_id TEXT,
        email TEXT,
        account_status TEXT,
        updated_at TEXT
    );
    CREATE TABLE customer_profiles_failover_replica (
        resource_id TEXT PRIMARY KEY,
        user_id TEXT,
        email TEXT,
        account_status TEXT,
        updated_at TEXT
    );
    -- Subject is DELETED in primary but still ACTIVE in failover replica (replica drift!)
    INSERT INTO customer_profiles_primary VALUES ('account_101', 'user_101', 'alice@example.com', 'DELETED', '2026-09-01T10:00:00Z');
    INSERT INTO customer_profiles_failover_replica VALUES ('account_101', 'user_101', 'alice@example.com', 'ACTIVE', '2026-08-15T12:00:00Z');
    """
    sql_file.write_text(sql_content, encoding="utf-8")

    items = parse_sql_dump(
        file_path=sql_file,
        file_id="evidence_54",
        captured_at="2026-09-02T00:00:00Z",
        origin="customer_accounts_snapshot",
    )

    assert len(items) == 2
    # Verify primary table item shows ABSENT
    primary_items = [i for i in items if i.raw_payload["table"] == "customer_profiles_primary"]
    assert len(primary_items) == 1
    assert primary_items[0].status == "ABSENT"
    assert primary_items[0].resource_id == "account_101"
    assert primary_items[0].user_id == "user_101"

    # Verify replica table item captures drift: status is ACTIVE
    replica_items = [i for i in items if i.raw_payload["table"] == "customer_profiles_failover_replica"]
    assert len(replica_items) == 1
    assert replica_items[0].status == "ACTIVE"
    assert replica_items[0].evidence_id == "evidence_54"


def test_sql_parser_embedded_json_and_specialized_tables(tmp_path: Path) -> None:
    """Test SQL tables with embedded JSON payloads, connector subscriptions, and backup restores."""
    sql_file = tmp_path / "test_embedded.sql"
    sql_content = """
    CREATE TABLE backup_restore_entries (
        resource_id TEXT,
        customer_reference TEXT,
        customer_email TEXT,
        restore_allowed INTEGER,
        updated_at TEXT
    );
    CREATE TABLE connector_subscriptions (
        resource_id TEXT,
        customer_reference TEXT,
        customer_email TEXT,
        enabled INTEGER,
        updated_at TEXT
    );
    CREATE TABLE customer_data_primary (
        resource_id TEXT,
        origin_system TEXT,
        collection_name TEXT,
        record_json TEXT,
        updated_at TEXT
    );
    INSERT INTO backup_restore_entries VALUES ('backup_999', 'user_50', 'bob@example.com', 1, '2026-08-01T10:00:00Z');
    INSERT INTO connector_subscriptions VALUES ('data_flow_888', 'user_50', 'bob@example.com', 0, '2026-08-01T10:00:00Z');
    INSERT INTO customer_data_primary VALUES (
        'audit_record_777',
        'security_service',
        'audit_events',
        '{"resource_id":"audit_record_777","subject_reference":"user_50","retention_until":"2029-12-31T00:00:00Z"}',
        '2026-08-01T10:00:00Z'
    );
    """
    sql_file.write_text(sql_content, encoding="utf-8")

    items = parse_sql_dump(
        file_path=sql_file,
        file_id="evidence_93",
        captured_at="2026-09-01T00:00:00Z",
        origin="database_dump",
    )

    assert len(items) == 3
    # backup_999 with restore_allowed=1 must be ACTIVE
    backup_item = next(i for i in items if i.resource_id == "backup_999")
    assert backup_item.status == "ACTIVE"
    assert backup_item.system_id == "backup_service"

    # data_flow_888 with enabled=0 must be DISABLED
    flow_item = next(i for i in items if i.resource_id == "data_flow_888")
    assert flow_item.status == "DISABLED"
    assert flow_item.system_id == "integration_service"

    # audit_record_777 with retention_until must flag retention
    audit_item = next(i for i in items if i.resource_id == "audit_record_777")
    assert audit_item.retention_flag is True
    assert audit_item.system_id == "security_service"
    assert audit_item.user_id == "user_50"


# -----------------------------------------------------------------------------
# 2. JSON Bundle Parser & Schema Tolerances
# -----------------------------------------------------------------------------

def test_json_bundle_parser_list_and_dict_envelopes(tmp_path: Path) -> None:
    """Test JSON ingestion across both top-level list envelopes and dict envelopes."""
    # List envelope
    list_file = tmp_path / "bundle_list.json"
    list_file.write_text(
        json.dumps([
            {
                "resource_id": "account_201",
                "record_type": "USER_PROFILE",
                "user_id": "user_201",
                "email": "charlie@example.com",
                "result": "NOT_FOUND",
                "recorded_at": "2026-09-10T12:00:00Z",
            },
            {
                "resource_id": "analytics_301",
                "record_type": "ANALYTICS_PROFILE",
                "subject_reference": "user_201",
                "result": "ANONYMIZED",
                "recorded_at": "2026-09-10T12:05:00Z",
            },
        ]),
        encoding="utf-8",
    )

    # Dict envelope with 'records'
    dict_file = tmp_path / "bundle_dict.json"
    dict_file.write_text(
        json.dumps({
            "origin": "export_service",
            "captured_at": "2026-09-11T00:00:00Z",
            "records": [
                {
                    "resource_id": "export_401",
                    "record_type": "USER_EXPORT",
                    "user_id": "user_201",
                    "result": "ACTIVE",
                    "created_at": "2026-09-11T00:00:00Z",
                }
            ],
        }),
        encoding="utf-8",
    )

    items_list = parse_json_bundle(list_file, "evidence_91", "2026-09-10T12:00:00Z", "records_dump")
    assert len(items_list) == 2
    assert items_list[0].status == "ABSENT"
    assert items_list[0].system_id == "account_service"
    assert items_list[1].status == "ANONYMIZED"
    assert items_list[1].system_id == "analytics_platform"

    items_dict = parse_json_bundle(dict_file, "evidence_92", "2026-09-11T00:00:00Z", "export_dump")
    assert len(items_dict) == 1
    assert items_dict[0].resource_id == "export_401"
    assert items_dict[0].status == "ACTIVE"
    assert items_dict[0].system_id == "export_service"


# -----------------------------------------------------------------------------
# 3. Handover Text Document Parser
# -----------------------------------------------------------------------------

def test_handover_txt_parser(tmp_path: Path) -> None:
    """Test shift handover pipe-separated text extraction."""
    txt_file = tmp_path / "handover.txt"
    txt_content = """CUSTOMER PLATFORM - SHIFT HANDOVER
Snapshot: 2026-10-01T12:00:00Z
- 2026-10-01T12:00:00Z | account_service | account_146 | USER_PROFILE | NOT_FOUND | e.lindberg18@yahoo.com
- 2026-10-01T12:00:00Z | analytics_platform | analytics_2034 | ANALYTICS_PROFILE | IDENTIFIABLE | novak.tomasz@icloud.com
- 2026-10-01T12:00:00Z | backup_service | backup_706 | BACKUP_ARCHIVE | BLOCKED | user_39
"""
    txt_file.write_text(txt_content, encoding="utf-8")

    items = parse_handover_txt(txt_file, "evidence_03", "2026-10-01T12:00:00Z", "customer_account_service")
    assert len(items) == 3

    assert items[0].resource_id == "account_146"
    assert items[0].status == "ABSENT"
    assert items[0].raw_payload["email"] == "e.lindberg18@yahoo.com"

    assert items[1].resource_id == "analytics_2034"
    assert items[1].status == "PRESENT"
    assert items[1].raw_payload["email"] == "novak.tomasz@icloud.com"

    assert items[2].resource_id == "backup_706"
    assert items[2].status == "BLOCKED"
    assert items[2].user_id == "user_39"


# -----------------------------------------------------------------------------
# 4. Multi-Dialect Log Parser
# -----------------------------------------------------------------------------

def test_log_file_multi_dialect_parsing(tmp_path: Path) -> None:
    """Test ingestion of bracketed, key-value, pipe, syslog, and JSON lines logs."""
    log_file = tmp_path / "combined.log"
    log_content = """
2026-07-28T05:51:16Z [DEBUG] [log_router] [collector-9] export_started: instance="collector-9" sources="platform_services" expected_source_events="87"
2026-02-18T05:47:12Z level=INFO service=integration_service trace_id=rb-01 event=connector_config_read resource_id=data_flow_3669 lookup_key=t.oliveira@gmail.com enabled=true
2026-07-03T07:51:32Z | DEBUG | security_service | tr-515 | audit_record_read | resource_id="audit_record_4413" correlation_key="user_211" rows="1"
2026-03-25T08:51:23Z <12>1 node-1 support_platform tr-74 - - level=WARN resource_id="support_9464" event="message_pii_scan" matched_value="silva.mariana@icloud.com"
2026-04-19T06:51:13Z {"severity":"INFO","logger":"search_service","service":"search_service","resource_id":"search_101","event":"index_query","match_key":"dubois.ines94@icloud.com"}
2026-03-15T07:00:00Z INFO service=account_service event=record_lookup resource_id="account_022" result="NOT_FOUND" subject_reference="zofia-novak@gmail.com"
"""
    log_file.write_text(log_content.strip(), encoding="utf-8")

    items = parse_log_file(log_file, "evidence_01", "2026-09-15T11:59:39Z", "observability_export")
    assert len(items) == 6

    # Dialect 2: key-value
    kv_item = next(i for i in items if i.resource_id == "data_flow_3669")
    assert kv_item.system_id == "integration_service"
    assert kv_item.raw_payload["email"] == "t.oliveira@gmail.com"

    # Dialect 3: pipe-delimited
    pipe_item = next(i for i in items if i.resource_id == "audit_record_4413")
    assert pipe_item.system_id == "security_service"
    assert pipe_item.user_id == "user_211"

    # Dialect 4: syslog
    syslog_item = next(i for i in items if i.resource_id == "support_9464")
    assert syslog_item.system_id == "support_platform"
    assert syslog_item.raw_payload["email"] == "silva.mariana@icloud.com"

    # Dialect 5: JSON lines
    json_item = next(i for i in items if i.resource_id == "search_101")
    assert json_item.system_id == "search_service"
    assert json_item.raw_payload["match_key"] == "dubois.ines94@icloud.com"

    # Dialect 6: result="NOT_FOUND" maps to ABSENT
    nf_item = next(i for i in items if i.resource_id == "account_022")
    assert nf_item.status == "ABSENT"


# -----------------------------------------------------------------------------
# 5. PDF Document Stream Decoding (ReportLab ASCII85 + FlateDecode)
# -----------------------------------------------------------------------------

def test_pdf_stream_decoder_pure_stdlib(tmp_path: Path) -> None:
    """Test pure-stdlib decoding of ReportLab ASCII85 + FlateDecode compressed PDF streams."""
    pdf_file = tmp_path / "synthetic_report.pdf"

    # Construct minimal synthetic PDF with ReportLab ASCII85 + FlateDecode stream
    page_content = b"""BT
/F1 12 Tf
(NORTHSTAR SHOP - CUSTOMER STATEMENT) Tj
(Customer Ingrid Dahl) Tj
(user_18) Tj
(ingrid.dahl@outlook.com) Tj
(order ORD-20261260) Tj
(statement NST-2026-0718-1842) Tj
ET"""

    # Flate compress then ASCII85 encode
    flate_data = zlib.compress(page_content)
    a85_data = base64.a85encode(flate_data, adobe=True)

    stream_obj = (
        b"<< /Filter [ /ASCII85Decode /FlateDecode ] /Length "
        + str(len(a85_data)).encode("ascii")
        + b" >>\nstream\n"
        + a85_data
        + b"\nendstream\n"
    )

    pdf_file.write_bytes(b"%PDF-1.4\n" + stream_obj + b"%%EOF")

    items = parse_pdf_document(pdf_file, "evidence_18", "2026-07-18T11:00:00Z", "account_history_service")
    assert len(items) == 1
    item = items[0]
    assert item.evidence_id == "evidence_18"
    assert item.user_id == "user_18"
    assert item.raw_payload["email"] == "ingrid.dahl@outlook.com"
    assert item.raw_payload["name"] == "Ingrid Dahl"
    assert item.raw_payload["order_id"] == "ORD-20261260"
    assert item.raw_payload["statement_id"] == "NST-2026-0718-1842"
    assert item.status == "PRESENT"


# -----------------------------------------------------------------------------
# 6. PNG Screenshot Inspection & OCR Limitation Documentation
# -----------------------------------------------------------------------------

def test_png_metadata_and_ocr_limitation(tmp_path: Path) -> None:
    """Verify PNG parser extracts metadata and explicitly documents OCR absence without failing."""
    png_file = tmp_path / "admin_console.png"
    # Create valid 1x1 PNG bytes
    png_bytes = bytes.fromhex(
        "89504E470D0A1A0A0000000D49484452000000010000000108060000001F15C4890000000A49444154789C63000100000500010D0A2D"
        "B40000000049454E44AE426082"
    )
    png_file.write_bytes(png_bytes)

    items = parse_png_metadata(png_file, "evidence_04", "2026-09-26T10:00:00Z", "account_admin_portal")
    assert len(items) == 1
    item = items[0]
    assert item.evidence_id == "evidence_04"
    assert item.evidence_type == "PNG"
    assert item.raw_payload["ocr_available"] is False
    assert item.raw_payload["file_size"] > 0


# -----------------------------------------------------------------------------
# 7. System Activity & User Audit Log Ingestion
# -----------------------------------------------------------------------------

def test_system_activity_and_user_audit_log_ingestion(tmp_path: Path) -> None:
    """Test operational CSV ingestion citing official activity_id and audit_id citations."""
    act_file = tmp_path / "system_activity.csv"
    act_file.write_text(
        """activity_id,event_time,event_type,source_system,target_system,resource_id,reported_result,details
activity_01,2026-01-04T14:56:29Z,INDEX_RECORD,account_service,search_service,search_9729,SUCCESS,Customer search-index refresh processed search_9729.
activity_02,2026-01-04T16:08:26Z,UPDATE_RECORD,account_service,search_service,search_6919,FAILED,Index update failed for user_456.
""",
        encoding="utf-8",
    )

    audit_file = tmp_path / "user_audit_log.csv"
    audit_file.write_text(
        """audit_id,user_id,event_time,field_name,old_value,new_value
audit_01,user_456,2024-12-14T16:31:44Z,email,old_alice@example.com,new_alice@example.com
audit_02,user_456,2025-01-10T11:00:00Z,phone,+1-555-0100,+1-555-0199
""",
        encoding="utf-8",
    )

    act_items = parse_system_activity(act_file)
    assert len(act_items) == 2
    assert act_items[0].evidence_id == "activity_01"
    assert act_items[0].status == "PRESENT"
    assert act_items[1].evidence_id == "activity_02"
    assert act_items[1].user_id == "user_456"

    audit_items = parse_user_audit_log(audit_file)
    assert len(audit_items) == 2
    assert audit_items[0].evidence_id == "audit_01"
    assert audit_items[0].user_id == "user_456"
    assert audit_items[0].raw_payload["historical_email"] == "old_alice@example.com"
    assert audit_items[0].raw_payload["email"] == "new_alice@example.com"


# -----------------------------------------------------------------------------
# 8. Inverted Index Multi-Hop Identifier Matching
# -----------------------------------------------------------------------------

def test_inverted_index_multi_hop_traversal() -> None:
    """Test subject retrieval matching across alias chains from ResolvedIdentity."""
    index = EvidenceCorpusIndex()

    # Evidence 1: mentions historical email
    index.index_item(
        NormalizedEvidenceItem(
            evidence_id="evidence_54",
            evidence_type="SQL",
            origin="accounts_db",
            captured_at="2026-09-01T00:00:00Z",
            resource_id="account_99",
            system_id="account_service",
            user_id="user_99",
            status="PRESENT",
            raw_payload={"email": "alice_old@example.com"},
        )
    )

    # Evidence 2: system activity on account_99 citing activity_888
    index.index_item(
        NormalizedEvidenceItem(
            evidence_id="activity_888",
            evidence_type="SYSTEM_ACTIVITY",
            origin="activity_log",
            captured_at="2026-08-01T12:00:00Z",
            event_timestamp="2026-08-01T12:00:00Z",
            resource_id="account_99",
            system_id="account_service",
            status="PRESENT",
            raw_payload={"details": "Account lookup"},
        )
    )

    # Resolved identity with current email and historical alias
    resolved = ResolvedIdentity(
        case_id="case_test",
        user_id="user_99",
        current_email="alice_new@example.com",
        historical_emails={"alice_old@example.com"},
    )

    results = index.get_subject_evidence(resolved, audit_at="2026-09-05T00:00:00Z")
    assert len(results) == 2
    evidence_ids = {r.evidence_id for r in results}
    assert "evidence_54" in evidence_ids
    assert "activity_888" in evidence_ids


# -----------------------------------------------------------------------------
# 9. Temporal Cutoff Enforcement (Boundary Tests)
# -----------------------------------------------------------------------------

def test_temporal_cutoff_boundary_filtering() -> None:
    """Test strict cutoff boundary enforcement: before, exactly at, and after audit_at."""
    item_before = NormalizedEvidenceItem(
        evidence_id="ev_before",
        evidence_type="SQL",
        origin="db",
        captured_at="2026-09-01T11:59:59Z",
        event_timestamp="2026-09-01T11:59:59Z",
    )
    item_exact = NormalizedEvidenceItem(
        evidence_id="ev_exact",
        evidence_type="SQL",
        origin="db",
        captured_at="2026-09-01T12:00:00Z",
        event_timestamp="2026-09-01T12:00:00Z",
    )
    item_after_captured = NormalizedEvidenceItem(
        evidence_id="ev_after_cap",
        evidence_type="SQL",
        origin="db",
        captured_at="2026-09-01T12:00:01Z",
        event_timestamp="2026-09-01T11:00:00Z",
    )
    item_after_event = NormalizedEvidenceItem(
        evidence_id="ev_after_evt",
        evidence_type="SQL",
        origin="db",
        captured_at="2026-09-01T11:00:00Z",
        event_timestamp="2026-09-01T12:00:01Z",
    )

    cutoff = "2026-09-01T12:00:00Z"
    assert item_before.is_temporally_valid(cutoff) is True
    assert item_exact.is_temporally_valid(cutoff) is True
    assert item_after_captured.is_temporally_valid(cutoff) is False
    assert item_after_event.is_temporally_valid(cutoff) is False


# -----------------------------------------------------------------------------
# 10. Timezone Offsets & Malformed Timestamp Handling
# -----------------------------------------------------------------------------

def test_timezone_offsets_and_malformed_timestamps() -> None:
    """Test timezone offset conversion and strict fail-closed behavior on timezone-naive timestamps."""
    # 13:00 +01:00 == 12:00 UTC (exact boundary match)
    item_offset = NormalizedEvidenceItem(
        evidence_id="ev_offset",
        evidence_type="LOG",
        origin="logs",
        captured_at="2026-09-01T13:00:00+01:00",
        event_timestamp="2026-09-01T13:00:00+01:00",
    )
    assert item_offset.is_temporally_valid("2026-09-01T12:00:00Z") is True

    # 13:00:01 +01:00 > 12:00 UTC (after boundary)
    item_offset_after = NormalizedEvidenceItem(
        evidence_id="ev_offset_after",
        evidence_type="LOG",
        origin="logs",
        captured_at="2026-09-01T13:00:01+01:00",
    )
    assert item_offset_after.is_temporally_valid("2026-09-01T12:00:00Z") is False

    # Timezone-naive timestamp fails closed
    item_naive = NormalizedEvidenceItem(
        evidence_id="ev_naive",
        evidence_type="SQL",
        origin="db",
        captured_at="2026-09-01 12:00:00",  # no timezone
    )
    assert item_naive.is_temporally_valid("2026-09-01T12:00:00Z") is False

    # Invalid cutoff timestamp fails closed
    assert item_offset.is_temporally_valid("not-a-timestamp") is False


# -----------------------------------------------------------------------------
# 11. Corrupted File Handling
# -----------------------------------------------------------------------------

def test_corrupted_file_handling_fails_closed(tmp_path: Path) -> None:
    """Test that corrupted SQL, JSON, or PDF files fail closed without throwing unhandled exceptions."""
    corrupt_sql = tmp_path / "bad.sql"
    corrupt_sql.write_text("INVALID SQL SYNTAX HERE !@#$%^&*()", encoding="utf-8")
    sql_items = parse_sql_dump(corrupt_sql, "ev_bad_sql", "2026-09-01T00:00:00Z", "test")
    assert sql_items == []

    corrupt_json = tmp_path / "bad.json"
    corrupt_json.write_text("{ this is not valid json }", encoding="utf-8")
    json_items = parse_json_bundle(corrupt_json, "ev_bad_json", "2026-09-01T00:00:00Z", "test")
    assert json_items == []

    corrupt_pdf = tmp_path / "bad.pdf"
    corrupt_pdf.write_bytes(b"%PDF-1.4\n<< /Filter [ /FlateDecode ] >>\nstream\nGARBAGE\nendstream")
    pdf_items = parse_pdf_document(corrupt_pdf, "ev_bad_pdf", "2026-09-01T00:00:00Z", "test")
    assert len(pdf_items) == 1
    # Returns empty document text safely without crashing
    assert pdf_items[0].raw_payload["document_text"] == ""


# -----------------------------------------------------------------------------
# 12. Deterministic Result Ordering
# -----------------------------------------------------------------------------

def test_deterministic_ordering_across_input_permutations() -> None:
    """Test that query results return identically ordered items regardless of index insertion order."""
    item1 = NormalizedEvidenceItem(
        evidence_id="ev_01",
        evidence_type="SQL",
        origin="db",
        event_timestamp="2026-09-01T10:00:00Z",
        resource_id="account_01",
        user_id="user_1",
    )
    item2 = NormalizedEvidenceItem(
        evidence_id="ev_02",
        evidence_type="SQL",
        origin="db",
        event_timestamp="2026-09-01T11:00:00Z",
        resource_id="account_01",
        user_id="user_1",
    )

    # Permutation A: insert item1 then item2
    idx_a = EvidenceCorpusIndex()
    idx_a.index_item(item1)
    idx_a.index_item(item2)

    # Permutation B: insert item2 then item1
    idx_b = EvidenceCorpusIndex()
    idx_b.index_item(item2)
    idx_b.index_item(item1)

    resolved = ResolvedIdentity(case_id="case_order", user_id="user_1")

    res_a = idx_a.get_subject_evidence(resolved)
    res_b = idx_b.get_subject_evidence(resolved)

    assert [i.evidence_id for i in res_a] == [i.evidence_id for i in res_b]
    assert [i.evidence_id for i in res_a] == ["ev_01", "ev_02"]


# -----------------------------------------------------------------------------
# 13. Prevention of Cross-Subject Leakage
# -----------------------------------------------------------------------------

def test_cross_subject_leakage_prevention() -> None:
    """Test that evidence belonging to subject A is strictly never returned for subject B."""
    index = EvidenceCorpusIndex()
    index.index_item(
        NormalizedEvidenceItem(
            evidence_id="ev_alice",
            evidence_type="SQL",
            origin="db",
            resource_id="account_alice",
            user_id="user_alice",
            raw_payload={"email": "alice@example.com"},
        )
    )
    index.index_item(
        NormalizedEvidenceItem(
            evidence_id="ev_bob",
            evidence_type="SQL",
            origin="db",
            resource_id="account_bob",
            user_id="user_bob",
            raw_payload={"email": "bob@example.com"},
        )
    )

    resolved_bob = ResolvedIdentity(
        case_id="case_bob",
        user_id="user_bob",
        current_email="bob@example.com",
    )

    bob_results = index.get_subject_evidence(resolved_bob)
    assert len(bob_results) == 1
    assert bob_results[0].evidence_id == "ev_bob"
    assert bob_results[0].user_id == "user_bob"
    assert all(r.evidence_id != "ev_alice" for r in bob_results)


# -----------------------------------------------------------------------------
# 14. Full Corpus Real Dataset Integration Test
# -----------------------------------------------------------------------------

def test_full_corpus_real_dataset_indexing() -> None:
    """Verify end-to-end evidence indexing and multi-hop retrieval across the actual dataset."""
    cfg = AppConfig()
    corpus = EvidenceCorpus(
        evidence_dir=cfg.evidence_dir,
        manifest_path=cfg.evidence_files_path,
        activity_path=cfg.dataset_dir / "system_activity.csv",
        audit_path=cfg.dataset_dir / "user_audit_log.csv",
    )

    idx = corpus.build_index()
    # Verify non-trivial indexing across all formats
    assert len(idx._all_items) > 7000
    assert len(idx._by_evidence_id) > 4000
    assert len(idx._by_user_id) > 300
    assert len(idx._by_resource_id) > 4000

    # Test resolution and retrieval on real cases
    id_graph = IdentityGraph(
        identities_df=pd.read_csv(cfg.user_identities_path),
        audit_log_df=pd.read_csv(cfg.user_audit_log_path),
    )

    # case_33 (user_18, Ingrid Dahl): PDF statement + exports
    res_33 = id_graph.resolve(
        case_id="case_33",
        request_email="ingrid.dahl@outlook.com",
        audit_at="2026-07-19T13:00:00Z",
    )
    assert res_33.user_id == "user_18"
    items_33 = corpus.get_subject_evidence(res_33, audit_at="2026-07-19T13:00:00Z")
    assert len(items_33) >= 1
    # PDF document citation must be present
    pdf_cites = [i for i in items_33 if i.evidence_id == "evidence_18"]
    assert len(pdf_cites) == 1
    assert pdf_cites[0].evidence_type == "PDF"

    # Legacy interface compatibility check
    legacy_refs = corpus.discover_subject_evidence(
        user_id="user_18",
        identifiers=["ingrid.dahl@outlook.com"],
        audit_at="2026-07-19T13:00:00Z",
    )
    assert len(legacy_refs) >= 1
    assert isinstance(legacy_refs[0], EvidenceReference)


# -----------------------------------------------------------------------------
# 15. Critical Regression Tests: Identity Isolation & Collision Prevention
# -----------------------------------------------------------------------------

def test_regression_same_name_user04_and_user413_isolation() -> None:
    """Regression test 1 & 2: Querying user_04 (Thandiwe Ndlovu) never returns user_413 or its resources."""
    index = EvidenceCorpusIndex()

    # Evidence directly owned by user_413
    item_413 = NormalizedEvidenceItem(
        evidence_id="evidence_54",
        evidence_type="SQL",
        origin="accounts_db",
        resource_id="account_413",
        user_id="user_413",
        status="PRESENT",
        raw_payload={"name": "Thandiwe Ndlovu", "email": "t.ndlovu413@example.com"},
    )
    index.index_item(item_413)

    # Operational system activity on user_413's resource
    act_413 = NormalizedEvidenceItem(
        evidence_id="activity_999",
        evidence_type="SYSTEM_ACTIVITY",
        origin="activity_log",
        resource_id="account_413",
        status="PRESENT",
        raw_payload={"details": "Audit scan on account_413"},
    )
    index.index_item(act_413)

    # Export record for user_413 without user_id in header but with user_413's email
    export_413 = NormalizedEvidenceItem(
        evidence_id="evidence_88",
        evidence_type="JSON",
        origin="export_service",
        resource_id="export_413",
        user_id=None,
        status="PRESENT",
        raw_payload={"name": "Thandiwe Ndlovu", "email": "t.ndlovu413@example.com"},
    )
    index.index_item(export_413)

    # Evidence directly owned by user_04
    item_04 = NormalizedEvidenceItem(
        evidence_id="evidence_54",
        evidence_type="SQL",
        origin="accounts_db",
        resource_id="account_004",
        user_id="user_04",
        status="PRESENT",
        raw_payload={"name": "Thandiwe Ndlovu", "email": "t.ndlovu04@example.com"},
    )
    index.index_item(item_04)

    # Query for user_04
    resolved_04 = ResolvedIdentity(
        case_id="case_04",
        user_id="user_04",
        current_email="t.ndlovu04@example.com",
        current_name="Thandiwe Ndlovu",
    )

    results = index.get_subject_evidence(resolved_04)
    returned_uids = {r.user_id for r in results if r.user_id}
    returned_resources = {r.resource_id for r in results if r.resource_id}

    # Assert strict canonical isolation and resource ownership
    assert "user_04" in returned_uids
    assert "user_413" not in returned_uids
    assert "account_004" in returned_resources
    assert "account_413" not in returned_resources
    assert "export_413" not in returned_resources
    assert all(r.user_id != "user_413" for r in results)
    assert all(r.resource_id != "account_413" for r in results)


def test_regression_same_name_collisions_mateo_rios_and_gabriel_costa() -> None:
    """Regression test 3: Same-name collision isolation for Mateo Rios and Gabriel Costa."""
    index = EvidenceCorpusIndex()

    # Mateo Rios collision: user_02 vs user_262
    index.index_item(
        NormalizedEvidenceItem(
            evidence_id="ev_02",
            evidence_type="SQL",
            origin="accounts_db",
            resource_id="account_002",
            user_id="user_02",
            raw_payload={"name": "Mateo Ríos", "email": "mateo.rios@gmail.com"},
        )
    )
    index.index_item(
        NormalizedEvidenceItem(
            evidence_id="ev_262",
            evidence_type="SQL",
            origin="accounts_db",
            resource_id="account_262",
            user_id="user_262",
            raw_payload={"name": "Mateo Ríos", "email": "m.rios262@outlook.com"},
        )
    )

    # Gabriel Costa collision: user_08 vs user_143
    index.index_item(
        NormalizedEvidenceItem(
            evidence_id="ev_08",
            evidence_type="SQL",
            origin="accounts_db",
            resource_id="account_008",
            user_id="user_08",
            raw_payload={"name": "Gabriel Costa", "email": "gabriel.costa@gmail.com"},
        )
    )
    index.index_item(
        NormalizedEvidenceItem(
            evidence_id="ev_143",
            evidence_type="SQL",
            origin="accounts_db",
            resource_id="account_143",
            user_id="user_143",
            raw_payload={"name": "Gabriel Costa", "email": "g.costa143@fastmail.com"},
        )
    )

    # Query Mateo Rios (user_02)
    resolved_02 = ResolvedIdentity(
        case_id="case_02",
        user_id="user_02",
        current_email="mateo.rios@gmail.com",
        current_name="Mateo Ríos",
    )
    results_02 = index.get_subject_evidence(resolved_02)
    assert {r.resource_id for r in results_02} == {"account_002"}
    assert {r.user_id for r in results_02} == {"user_02"}

    # Query Gabriel Costa (user_08)
    resolved_08 = ResolvedIdentity(
        case_id="case_08",
        user_id="user_08",
        current_email="gabriel.costa@gmail.com",
        current_name="Gabriel Costa",
    )
    results_08 = index.get_subject_evidence(resolved_08)
    assert {r.resource_id for r in results_08} == {"account_008"}
    assert {r.user_id for r in results_08} == {"user_08"}


def test_regression_legitimate_historical_alias_retrieval() -> None:
    """Regression test 4: Legitimate historical aliases still match the correct canonical subject."""
    index = EvidenceCorpusIndex()

    # Historical record citing previous email
    index.index_item(
        NormalizedEvidenceItem(
            evidence_id="evidence_54",
            evidence_type="SQL",
            origin="accounts_db",
            resource_id="account_77",
            user_id="user_77",
            raw_payload={"email": "carl.old@example.com", "name": "Carl Jenkins"},
        )
    )
    # Secondary activity on account_77
    index.index_item(
        NormalizedEvidenceItem(
            evidence_id="activity_77",
            evidence_type="SYSTEM_ACTIVITY",
            origin="activity_log",
            resource_id="account_77",
            raw_payload={"details": "Account 77 event"},
        )
    )

    resolved_77 = ResolvedIdentity(
        case_id="case_77",
        user_id="user_77",
        current_email="carl.new@example.com",
        historical_emails={"carl.old@example.com"},
        current_name="Carl Jenkins",
    )

    results_77 = index.get_subject_evidence(resolved_77)
    res_ids = {r.resource_id for r in results_77}
    assert "account_77" in res_ids
    assert len(results_77) == 2


def test_regression_evidence_without_canonical_user_id_preserved() -> None:
    """Regression test 5: Evidence lacking a user_id is safely matched when emails/resources match."""
    index = EvidenceCorpusIndex()

    # Log record with email and resource_id, but user_id is None
    index.index_item(
        NormalizedEvidenceItem(
            evidence_id="evidence_01",
            evidence_type="LOG",
            origin="logs",
            resource_id="search_555",
            user_id=None,
            raw_payload={"lookup_key": "diana@example.com", "event": "query"},
        )
    )

    resolved_diana = ResolvedIdentity(
        case_id="case_diana",
        user_id="user_99",
        current_email="diana@example.com",
    )

    results = index.get_subject_evidence(resolved_diana)
    assert len(results) == 1
    assert results[0].evidence_id == "evidence_01"
    assert results[0].resource_id == "search_555"
    assert results[0].user_id is None


def test_regression_deterministic_ordering_with_isolation_guards() -> None:
    """Regression test 6: Deterministic result ordering is preserved under input permutations."""
    item1 = NormalizedEvidenceItem(
        evidence_id="ev_01",
        evidence_type="SQL",
        origin="db",
        event_timestamp="2026-09-01T10:00:00Z",
        resource_id="account_10",
        user_id="user_10",
    )
    item2 = NormalizedEvidenceItem(
        evidence_id="ev_02",
        evidence_type="SQL",
        origin="db",
        event_timestamp="2026-09-01T11:00:00Z",
        resource_id="account_10",
        user_id="user_10",
    )

    idx_a = EvidenceCorpusIndex()
    idx_a.index_item(item1)
    idx_a.index_item(item2)

    idx_b = EvidenceCorpusIndex()
    idx_b.index_item(item2)
    idx_b.index_item(item1)

    resolved = ResolvedIdentity(case_id="case_10", user_id="user_10")

    res_a = idx_a.get_subject_evidence(resolved)
    res_b = idx_b.get_subject_evidence(resolved)

    assert [r.evidence_id for r in res_a] == ["ev_01", "ev_02"]
    assert [r.evidence_id for r in res_b] == ["ev_01", "ev_02"]
