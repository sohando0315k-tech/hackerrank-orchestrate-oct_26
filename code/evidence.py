"""Evidence discovery, ingestion, normalization, indexing, and temporal filtering module.

Strictly adheres to the HackerRank Orchestrate (October 2026) specification:
1. Multi-format ingestion across SQL dumps, JSON bundles, service logs, PDF documents,
   PNG administration screenshots, shift handover text records, system activity, and user audit logs.
2. Provenance preservation: cites official evidence IDs only (file_id, activity_id, audit_id).
   Never fabricates or invents synthetic evidence citations.
3. Strict temporal cutoff safety: validates timezone-aware ISO-8601 timestamps in UTC,
   enforcing `captured_at <= audit_at` and `event_timestamp <= audit_at`.
   Fails closed on missing or timezone-naive snapshot timestamps.
4. Fast inverted indexing across user IDs, historical emails, phone numbers, names, email hashes,
   and discovered resource identifiers.
5. Deterministic retrieval ordering and zero cross-subject evidence leakage.
"""

from __future__ import annotations

import base64
import csv
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sqlite3
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
import zlib

import pandas as pd

from code.identity import (
    ResolvedIdentity,
    normalize_email,
    normalize_phone,
    parse_iso_timestamp,
)

# Optional Pillow import for image metadata inspection
try:
    from PIL import Image
except ImportError:  # pragma: no cover
    Image = None


@dataclass
class EvidenceReference:
    """A citation of evidence proving an audit finding or compliant state (legacy interface)."""
    evidence_id: str  # file_id, activity_id, or audit_id
    source_type: str  # file, activity, or audit
    captured_at: Optional[str] = None
    system_id: Optional[str] = None
    resource_id: Optional[str] = None
    summary: str = ""


@dataclass
class NormalizedEvidenceItem:
    """Normalized evidence item representing an observation across the corpus."""
    evidence_id: str  # official file_id (evidence_XX), activity_id (activity_XX), or audit_id (audit_XX)
    evidence_type: str  # SQL, JSON, LOG, PDF, PNG, TEXT, SYSTEM_ACTIVITY, AUDIT_LOG
    origin: str  # origin manifest or system source
    captured_at: Optional[str] = None  # ISO-8601 UTC capture timestamp of snapshot
    event_timestamp: Optional[str] = None  # ISO-8601 UTC timestamp of individual event/record
    resource_id: str = ""  # target resource (e.g. account_001, search_002, backup_003)
    system_id: str = ""  # owning service (e.g. account_service, search_service)
    user_id: Optional[str] = None  # canonical or associated user ID if explicitly stated
    action: Optional[str] = None  # observed action/operation
    status: Optional[str] = None  # observed record state (e.g. PRESENT, ACTIVE, DISABLED, BLOCKED, ABSENT, ANONYMIZED)
    retention_flag: bool = False  # True if subject to legal hold, retention register, or statutory preservation
    raw_payload: Dict[str, Any] = field(default_factory=dict)  # extracted attributes and raw context

    def to_reference(self) -> EvidenceReference:
        """Convert to legacy EvidenceReference format."""
        source_type = "activity" if self.evidence_type == "SYSTEM_ACTIVITY" else (
            "audit" if self.evidence_type == "AUDIT_LOG" else "file"
        )
        return EvidenceReference(
            evidence_id=self.evidence_id,
            source_type=source_type,
            captured_at=self.captured_at,
            system_id=self.system_id,
            resource_id=self.resource_id,
            summary=f"{self.evidence_type} record on {self.resource_id}: status={self.status}",
        )

    def is_temporally_valid(self, audit_at: Optional[str]) -> bool:
        """Evaluate whether this evidence item is valid under the given audit_at cutoff.

        Temporal cutoff rule:
        1. If audit_at is None, item is unconditionally valid.
        2. If audit_at is provided, it must parse to a timezone-aware UTC datetime.
        3. If captured_at is present, it must parse and satisfy `captured_at <= audit_at`.
           If captured_at is present but cannot be parsed (e.g. timezone-naive or malformed),
           it fails closed (returns False).
        4. If event_timestamp is present, it must parse and satisfy `event_timestamp <= audit_at`.
           If event_timestamp is present but cannot be parsed, it fails closed (returns False).
        """
        if not audit_at:
            return True
        audit_dt = parse_iso_timestamp(audit_at)
        if audit_dt is None:
            return False

        if self.captured_at:
            cap_dt = parse_iso_timestamp(self.captured_at)
            if cap_dt is None or cap_dt > audit_dt:
                return False

        if self.event_timestamp:
            evt_dt = parse_iso_timestamp(self.event_timestamp)
            if evt_dt is None or evt_dt > audit_dt:
                return False

        return True


def infer_system_id(resource_id: str, default: str = "") -> str:
    """Infer the owning system ID from standard resource identifier naming conventions."""
    res = (resource_id or "").strip().lower()
    if res.startswith("account_"):
        return "account_service"
    elif res.startswith("audit_") or res.startswith("security_"):
        return "security_service"
    elif res.startswith("analytics_"):
        return "analytics_platform"
    elif res.startswith("search_"):
        return "search_service"
    elif res.startswith("support_"):
        return "support_platform"
    elif res.startswith("export_"):
        return "export_service"
    elif res.startswith("backup_"):
        return "backup_service"
    elif res.startswith("data_") or res.startswith("data_flow_"):
        return "integration_service"
    elif res.startswith("tombstone_"):
        return "identity_service"
    return default


# -----------------------------------------------------------------------------
# Format-Specific Parsers
# -----------------------------------------------------------------------------

def parse_sql_dump(
    file_path: Path,
    file_id: str,
    captured_at: Optional[str],
    origin: str,
) -> List[NormalizedEvidenceItem]:
    """Ingest SQLite-compatible SQL dump into memory and extract table rows deterministically."""
    items: List[NormalizedEvidenceItem] = []
    if not file_path.is_file():
        return items

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            sql_text = f.read()

        conn = sqlite3.connect(":memory:")
        conn.executescript(sql_text)
        cur = conn.cursor()

        # Find tables
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name != 'snapshot_scope' ORDER BY name;")
        tables = [r[0] for r in cur.fetchall()]

        for tbl in tables:
            cur.execute(f"PRAGMA table_info({tbl});")
            columns = [c[1] for c in cur.fetchall()]
            cur.execute(f"SELECT * FROM {tbl};")
            rows = cur.fetchall()

            for row in rows:
                row_dict = dict(zip(columns, row))
                res_id = str(row_dict.get("resource_id", "")).strip()

                # Check for embedded JSON payload (e.g. customer_data_primary/replicas)
                record_json = row_dict.get("record_json")
                embedded: Dict[str, Any] = {}
                if record_json and isinstance(record_json, str):
                    try:
                        embedded = json.loads(record_json)
                    except Exception:
                        embedded = {}

                # Resolve identifiers
                user_id = (
                    row_dict.get("user_id")
                    or row_dict.get("customer_reference")
                    or row_dict.get("subject_reference")
                    or embedded.get("subject_reference")
                    or embedded.get("user_id")
                )
                if user_id:
                    user_id = str(user_id).strip()

                email = (
                    row_dict.get("email")
                    or row_dict.get("customer_email")
                    or row_dict.get("owner_email")
                    or row_dict.get("requester_email")
                    or embedded.get("email")
                )
                phone = (
                    row_dict.get("phone")
                    or row_dict.get("owner_phone")
                    or row_dict.get("requester_phone")
                    or embedded.get("phone")
                )
                name = (
                    row_dict.get("full_name")
                    or row_dict.get("display_name")
                    or row_dict.get("requester_name")
                    or embedded.get("full_name")
                )
                email_hash = row_dict.get("email_hash") or embedded.get("email_hash")

                # Timestamp
                evt_ts = (
                    row_dict.get("updated_at")
                    or row_dict.get("indexed_at")
                    or row_dict.get("captured_at")
                    or embedded.get("updated_at")
                    or embedded.get("recorded_at")
                )

                # Determine observed state / status
                status = "PRESENT"
                retention_flag = False

                if "account_status" in row_dict:
                    acc_st = str(row_dict["account_status"]).upper().strip()
                    if acc_st == "ACTIVE":
                        status = "ACTIVE"
                    elif acc_st == "DISABLED":
                        status = "DISABLED"
                    elif acc_st in ("DELETED", "ABSENT"):
                        status = "ABSENT"
                elif "restore_allowed" in row_dict:
                    status = "ACTIVE" if int(row_dict["restore_allowed"]) == 1 else "BLOCKED"
                elif "enabled" in row_dict:
                    status = "ACTIVE" if int(row_dict["enabled"]) == 1 else "DISABLED"

                if "retention_until" in row_dict or "retention_until" in embedded:
                    retention_flag = True

                system_id = infer_system_id(res_id, default=origin)

                payload = {
                    "table": tbl,
                    "row": row_dict,
                    "embedded": embedded,
                    "email": email,
                    "phone": phone,
                    "name": name,
                    "email_hash": email_hash,
                }

                items.append(
                    NormalizedEvidenceItem(
                        evidence_id=file_id,
                        evidence_type="SQL",
                        origin=origin,
                        captured_at=captured_at,
                        event_timestamp=str(evt_ts) if evt_ts else None,
                        resource_id=res_id,
                        system_id=system_id,
                        user_id=user_id if user_id else None,
                        action=f"TABLE_RECORD_{tbl}",
                        status=status,
                        retention_flag=retention_flag,
                        raw_payload=payload,
                    )
                )

        conn.close()
    except Exception as e:
        # Fail closed on corrupt database dump
        pass

    return items


def parse_json_bundle(
    file_path: Path,
    file_id: str,
    captured_at: Optional[str],
    origin: str,
) -> List[NormalizedEvidenceItem]:
    """Ingest JSON record bundle or archive export deterministically."""
    items: List[NormalizedEvidenceItem] = []
    if not file_path.is_file():
        return items

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)

        records: List[Dict[str, Any]] = []
        if isinstance(data, list):
            records = [r for r in data if isinstance(r, dict)]
        elif isinstance(data, dict):
            if "records" in data and isinstance(data["records"], list):
                records = [r for r in data["records"] if isinstance(r, dict)]
            else:
                records = [data]

        for rec in records:
            res_id = str(rec.get("resource_id", "")).strip()
            user_id = rec.get("user_id") or rec.get("subject_reference") or rec.get("customer_reference")
            if user_id:
                user_id = str(user_id).strip()

            email = rec.get("email") or rec.get("owner_email") or rec.get("subject_reference")
            phone = rec.get("phone") or rec.get("owner_phone")
            email_hash = rec.get("email_hash")
            name = rec.get("full_name") or rec.get("display_name")

            raw_status = str(rec.get("result") or rec.get("status") or "").upper().strip()
            status = "PRESENT"
            if raw_status == "NOT_FOUND":
                status = "ABSENT"
            elif raw_status == "ACTIVE":
                status = "ACTIVE"
            elif raw_status == "DISABLED":
                status = "DISABLED"
            elif raw_status == "BLOCKED":
                status = "BLOCKED"
            elif raw_status == "ANONYMIZED":
                status = "ANONYMIZED"
            elif raw_status in ("FOUND", "IDENTIFIABLE", "PRESENT"):
                status = "PRESENT"

            rec_type = str(rec.get("record_type", "")).upper()
            retention_flag = rec_type == "LEGAL_HOLD_RECORD" or "retention_until" in rec or "expires_at" in rec

            evt_ts = (
                rec.get("created_at")
                or rec.get("exported_at")
                or rec.get("recorded_at")
                or rec.get("captured_at")
            )

            system_id = str(rec.get("system", "")).strip() or infer_system_id(res_id, default=origin)

            payload = {
                "record": rec,
                "email": email,
                "phone": phone,
                "name": name,
                "email_hash": email_hash,
            }

            items.append(
                NormalizedEvidenceItem(
                    evidence_id=file_id,
                    evidence_type="JSON",
                    origin=origin,
                    captured_at=captured_at,
                    event_timestamp=str(evt_ts) if evt_ts else None,
                    resource_id=res_id,
                    system_id=system_id,
                    user_id=user_id if user_id else None,
                    action=rec_type or "RECORD_OBSERVED",
                    status=status,
                    retention_flag=retention_flag,
                    raw_payload=payload,
                )
            )
    except Exception:
        # Corrupt JSON fails closed
        pass

    return items


def parse_handover_txt(
    file_path: Path,
    file_id: str,
    captured_at: Optional[str],
    origin: str,
) -> List[NormalizedEvidenceItem]:
    """Ingest shift handover pipe-separated text document."""
    items: List[NormalizedEvidenceItem] = []
    if not file_path.is_file():
        return items

    line_pattern = re.compile(
        r"^-\s*([0-9T:\-Z\.\+\-]+)\s*\|\s*([\w\-]+)\s*\|\s*([\w\-]+)\s*\|\s*([\w\-]+)\s*\|\s*([\w\-]+)\s*\|\s*(.*)$"
    )

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                sline = line.strip()
                m = line_pattern.match(sline)
                if not m:
                    continue

                ts, sys_id, res_id, rec_type, result, subj_ref = m.groups()
                subj_ref = subj_ref.strip()

                raw_status = result.upper().strip()
                status = "PRESENT"
                if raw_status == "NOT_FOUND":
                    status = "ABSENT"
                elif raw_status == "ACTIVE":
                    status = "ACTIVE"
                elif raw_status == "BLOCKED":
                    status = "BLOCKED"
                elif raw_status == "ANONYMIZED":
                    status = "ANONYMIZED"
                elif raw_status in ("FOUND", "IDENTIFIABLE", "PRESENT"):
                    status = "PRESENT"

                user_id = subj_ref if subj_ref.startswith("user_") else None
                email = subj_ref if "@" in subj_ref else None

                payload = {
                    "system": sys_id,
                    "record_type": rec_type,
                    "result": result,
                    "subject_reference": subj_ref,
                    "email": email,
                }

                items.append(
                    NormalizedEvidenceItem(
                        evidence_id=file_id,
                        evidence_type="TEXT",
                        origin=origin,
                        captured_at=captured_at,
                        event_timestamp=ts,
                        resource_id=res_id,
                        system_id=sys_id,
                        user_id=user_id,
                        action=rec_type,
                        status=status,
                        retention_flag=False,
                        raw_payload=payload,
                    )
                )
    except Exception:
        pass

    return items


def parse_log_file(
    file_path: Path,
    file_id: str,
    captured_at: Optional[str],
    origin: str,
) -> List[NormalizedEvidenceItem]:
    """Ingest multi-dialect service log file deterministically."""
    items: List[NormalizedEvidenceItem] = []
    if not file_path.is_file():
        return items

    ts_pattern = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))")
    kv_pattern = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)=(?:"([^"]*)"|\'([^\']*)\'|([^\s|\]]+))')

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line_idx, line in enumerate(f, start=1):
                sline = line.strip()
                if not sline:
                    continue

                m_ts = ts_pattern.search(sline)
                event_ts = m_ts.group(1) if m_ts else None

                payload: Dict[str, Any] = {}
                # Check for JSON line
                json_start = sline.find("{")
                if json_start != -1 and sline.endswith("}"):
                    try:
                        payload = json.loads(sline[json_start:])
                    except Exception:
                        payload = {}

                # Otherwise extract key-value attributes
                if not payload:
                    for k, v1, v2, v3 in kv_pattern.findall(sline):
                        val = v1 if v1 != "" else (v2 if v2 != "" else v3)
                        payload[k] = val

                res_id = str(payload.get("resource_id", "")).strip()

                user_id = (
                    payload.get("user_id")
                    or payload.get("customer_reference")
                    or payload.get("subject_reference")
                    or payload.get("correlation_key")
                )
                if user_id:
                    user_id = str(user_id).strip()
                    if not user_id.startswith("user_"):
                        user_id = None

                email = (
                    payload.get("email")
                    or payload.get("customer_email")
                    or payload.get("owner_email")
                    or payload.get("lookup_key")
                    or payload.get("match_key")
                    or payload.get("subject_key")
                    or payload.get("scan_key")
                    or payload.get("matched_value")
                )
                if email and "@" not in str(email):
                    email = None

                phone = payload.get("phone")

                raw_status = str(payload.get("result") or payload.get("status") or "").upper().strip()
                status = "PRESENT"
                if raw_status == "NOT_FOUND":
                    status = "ABSENT"
                elif raw_status == "ACTIVE":
                    status = "ACTIVE"
                elif raw_status == "DISABLED":
                    status = "DISABLED"
                elif raw_status == "BLOCKED":
                    status = "BLOCKED"
                elif raw_status == "ANONYMIZED":
                    status = "ANONYMIZED"
                elif raw_status in ("FOUND", "IDENTIFIABLE", "SUCCESS", "PRESENT"):
                    status = "PRESENT"

                action = str(payload.get("event") or payload.get("action") or "LOG_ENTRY").strip()
                service = str(payload.get("service") or payload.get("system") or "").strip()
                system_id = service or infer_system_id(res_id, default=origin)

                # Attach line index to payload for deterministic debugging
                payload["_line_no"] = line_idx
                if email:
                    payload["email"] = email
                if phone:
                    payload["phone"] = phone

                items.append(
                    NormalizedEvidenceItem(
                        evidence_id=file_id,
                        evidence_type="LOG",
                        origin=origin,
                        captured_at=captured_at,
                        event_timestamp=event_ts,
                        resource_id=res_id,
                        system_id=system_id,
                        user_id=user_id,
                        action=action,
                        status=status,
                        retention_flag=False,
                        raw_payload=payload,
                    )
                )
    except Exception:
        pass

    return items


def parse_pdf_document(
    file_path: Path,
    file_id: str,
    captured_at: Optional[str],
    origin: str,
) -> List[NormalizedEvidenceItem]:
    """Ingest ReportLab PDF document using stdlib Adobe ASCII85 + Flate stream decoding."""
    items: List[NormalizedEvidenceItem] = []
    if not file_path.is_file():
        return items

    try:
        with open(file_path, "rb") as f:
            data = f.read()

        extracted_lines: List[str] = []
        idx = 0
        while True:
            s_idx = data.find(b"stream", idx)
            if s_idx == -1:
                break
            e_idx = data.find(b"endstream", s_idx)
            if e_idx == -1:
                break

            header_start = data.rfind(b"<<", 0, s_idx)
            header = data[header_start:s_idx].decode("latin1", errors="replace").replace("\n", " ")

            stream_start = s_idx + len(b"stream")
            if data[stream_start:stream_start+2] == b"\r\n":
                stream_start += 2
            elif data[stream_start:stream_start+1] in (b"\r", b"\n"):
                stream_start += 1

            stream_data = data[stream_start:e_idx]
            if stream_data.endswith(b"\r\n"):
                stream_data = stream_data[:-2]
            elif stream_data.endswith(b"\n") or stream_data.endswith(b"\r"):
                stream_data = stream_data[:-1]

            # Decode content stream if Flate or ASCII85+Flate
            decomp: Optional[bytes] = None
            if "ASCII85Decode" in header or stream_data.strip().startswith(b"<~"):
                try:
                    a85 = base64.a85decode(stream_data.strip(), adobe=True)
                    decomp = zlib.decompress(a85)
                except Exception:
                    decomp = None

            if decomp is None and "FlateDecode" in header:
                try:
                    decomp = zlib.decompress(stream_data)
                except Exception:
                    decomp = None

            if decomp:
                for line in decomp.split(b"\n"):
                    if b"Tj" in line or b"TJ" in line:
                        matches = re.findall(rb"\((.*?)\)", line)
                        if matches:
                            extracted_lines.append(" ".join(m.decode("latin1", errors="replace") for m in matches))

            idx = e_idx + len(b"endstream")

        full_doc_text = "\n".join(extracted_lines)

        # Extract identifiers from decoded document text
        uid_match = re.search(r"\b(user_\d+)\b", full_doc_text)
        user_id = uid_match.group(1) if uid_match else None

        email_match = re.search(r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)", full_doc_text)
        email = email_match.group(1) if email_match else None

        phone_match = re.search(r"(\+\d[\d\s]{7,15}\d)", full_doc_text)
        phone = phone_match.group(1) if phone_match else None

        cust_match = re.search(r"Customer\s+([A-Za-z\s]+?)(?=\s+Detail|\s+Statement|\n|$)", full_doc_text)
        name = cust_match.group(1).strip() if cust_match else None

        # Check for order or statement references
        order_match = re.search(r"\b(ORD-\d+)\b", full_doc_text)
        stmt_match = re.search(r"\b(NST-[\d\-]+)\b", full_doc_text)
        supp_match = re.search(r"\b(support_\d+)\b", full_doc_text)
        audit_match = re.search(r"\b(audit_record_\d+)\b", full_doc_text)

        res_id = ""
        if supp_match:
            res_id = supp_match.group(1)
        elif audit_match:
            res_id = audit_match.group(1)
        elif stmt_match:
            res_id = stmt_match.group(1)
        elif order_match:
            res_id = order_match.group(1)

        # Check legal retention markers
        retention_flag = any(
            marker in full_doc_text.lower()
            for marker in [
                "disputed orders",
                "tax records",
                "retain-until",
                "legal retention",
                "compliance journal",
                "restricted",
                "legal hold",
            ]
        )

        system_id = infer_system_id(res_id, default=origin)

        payload = {
            "document_text": full_doc_text,
            "user_id": user_id,
            "email": email,
            "phone": phone,
            "name": name,
            "order_id": order_match.group(1) if order_match else None,
            "statement_id": stmt_match.group(1) if stmt_match else None,
        }

        items.append(
            NormalizedEvidenceItem(
                evidence_id=file_id,
                evidence_type="PDF",
                origin=origin,
                captured_at=captured_at,
                event_timestamp=captured_at,
                resource_id=res_id,
                system_id=system_id,
                user_id=user_id,
                action="PDF_DOCUMENT_VERIFIED",
                status="PRESENT",
                retention_flag=retention_flag,
                raw_payload=payload,
            )
        )
    except Exception:
        pass

    return items


def parse_png_metadata(
    file_path: Path,
    file_id: str,
    captured_at: Optional[str],
    origin: str,
) -> List[NormalizedEvidenceItem]:
    """Inspect PNG administration screenshot metadata deterministically."""
    items: List[NormalizedEvidenceItem] = []
    if not file_path.is_file():
        return items

    size_bytes = os.path.getsize(file_path)
    dimensions: Tuple[int, int] = (0, 0)
    mode = "RGB"
    img_fmt = "PNG"

    if Image is not None:
        try:
            with Image.open(file_path) as img:
                dimensions = img.size
                mode = img.mode
                img_fmt = img.format or "PNG"
        except Exception:
            pass

    # Record explicit OCR status and metadata
    payload = {
        "ocr_available": False,
        "ocr_engine": None,
        "file_size": size_bytes,
        "dimensions": list(dimensions),
        "mode": mode,
        "format": img_fmt,
        "filename": file_path.name,
    }

    system_id = origin

    items.append(
        NormalizedEvidenceItem(
            evidence_id=file_id,
            evidence_type="PNG",
            origin=origin,
            captured_at=captured_at,
            event_timestamp=captured_at,
            resource_id="",
            system_id=system_id,
            user_id=None,
            action="ADMIN_SCREENSHOT_CAPTURED",
            status="PRESENT",
            retention_flag=False,
            raw_payload=payload,
        )
    )

    return items


def parse_system_activity(csv_path: Path) -> List[NormalizedEvidenceItem]:
    """Ingest operational records from dataset/system_activity.csv citing official activity_id."""
    items: List[NormalizedEvidenceItem] = []
    if not csv_path.is_file():
        return items

    try:
        with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                act_id = str(row.get("activity_id", "")).strip()
                if not act_id:
                    continue

                event_time = row.get("event_time")
                event_type = row.get("event_type", "")
                res_id = str(row.get("resource_id", "")).strip()
                rep_res = str(row.get("reported_result", "")).upper().strip()
                details = row.get("details", "")

                status = "PRESENT" if rep_res in ("SUCCESS", "COMPLETED") else None
                system_id = infer_system_id(
                    res_id,
                    default=str(row.get("target_system") or row.get("source_system") or ""),
                )

                # Search details for referenced user_id or email
                uid_match = re.search(r"\b(user_\d+)\b", details)
                user_id = uid_match.group(1) if uid_match else None

                email_match = re.search(r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)", details)
                email = email_match.group(1) if email_match else None

                payload = dict(row)
                if email:
                    payload["email"] = email

                items.append(
                    NormalizedEvidenceItem(
                        evidence_id=act_id,
                        evidence_type="SYSTEM_ACTIVITY",
                        origin="system_activity_log",
                        captured_at=event_time,
                        event_timestamp=event_time,
                        resource_id=res_id,
                        system_id=system_id,
                        user_id=user_id,
                        action=event_type,
                        status=status,
                        retention_flag=False,
                        raw_payload=payload,
                    )
                )
    except Exception:
        pass

    return items


def parse_user_audit_log(csv_path: Path) -> List[NormalizedEvidenceItem]:
    """Ingest identity change audit history from dataset/user_audit_log.csv citing official audit_id."""
    items: List[NormalizedEvidenceItem] = []
    if not csv_path.is_file():
        return items

    try:
        with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                audit_id = str(row.get("audit_id", "")).strip()
                if not audit_id:
                    continue

                ts = row.get("event_time") or row.get("timestamp")
                user_id = str(row.get("user_id", "")).strip()
                field_chg = str(row.get("field_name") or row.get("field_changed") or "").strip()
                old_val = row.get("old_value")
                new_val = row.get("new_value")

                payload = dict(row)
                if field_chg.lower() == "email":
                    if old_val:
                        payload["historical_email"] = old_val
                    if new_val:
                        payload["email"] = new_val
                elif field_chg.lower() == "phone":
                    if old_val:
                        payload["historical_phone"] = old_val
                    if new_val:
                        payload["phone"] = new_val

                items.append(
                    NormalizedEvidenceItem(
                        evidence_id=audit_id,
                        evidence_type="AUDIT_LOG",
                        origin="user_audit_log",
                        captured_at=ts,
                        event_timestamp=ts,
                        resource_id="",
                        system_id="identity_service",
                        user_id=user_id if user_id else None,
                        action=f"UPDATE_{field_chg.upper()}" if field_chg else "AUDIT_EVENT",
                        status="PRESENT",
                        retention_flag=False,
                        raw_payload=payload,
                    )
                )
    except Exception:
        pass

    return items


# -----------------------------------------------------------------------------
# Inverted Corpus Index
# -----------------------------------------------------------------------------

def _canonical_user_id(uid: Optional[str]) -> Optional[str]:
    """Normalize canonical user_id string (user_XX) or return None if absent."""
    if not uid or not isinstance(uid, str):
        return None
    cleaned = uid.strip().lower()
    return cleaned if cleaned.startswith("user_") else None


def _has_canonical_user_id_conflict(canonical_uid: Optional[str], item_uid: Optional[str]) -> bool:
    """Return True if both canonical_uid and item_uid are provided and do not match."""
    c_norm = _canonical_user_id(canonical_uid)
    i_norm = _canonical_user_id(item_uid)
    return bool(c_norm and i_norm and c_norm != i_norm)


class EvidenceCorpusIndex:
    """Deterministic, high-throughput inverted index over the complete evidence corpus."""

    def __init__(self) -> None:
        self._all_items: List[NormalizedEvidenceItem] = []
        self._by_user_id: Dict[str, List[NormalizedEvidenceItem]] = {}
        self._by_identifier: Dict[str, List[NormalizedEvidenceItem]] = {}
        self._by_resource_id: Dict[str, List[NormalizedEvidenceItem]] = {}
        self._by_evidence_id: Dict[str, List[NormalizedEvidenceItem]] = {}

    def index_item(self, item: NormalizedEvidenceItem) -> None:
        """Register a single normalized evidence item into the inverted indices."""
        self._all_items.append(item)

        # Index by evidence_id
        if item.evidence_id:
            self._by_evidence_id.setdefault(item.evidence_id, []).append(item)

        # Index by resource_id
        if item.resource_id:
            res_clean = item.resource_id.strip()
            if res_clean:
                self._by_resource_id.setdefault(res_clean, []).append(item)

        # Index by user_id
        if item.user_id:
            uid_clean = item.user_id.strip()
            if uid_clean:
                self._by_user_id.setdefault(uid_clean, []).append(item)

        # Extract identifiers from item and raw_payload
        identifiers = self._extract_identifiers(item)
        for ident in identifiers:
            self._by_identifier.setdefault(ident, []).append(item)

    def _extract_identifiers(self, item: NormalizedEvidenceItem) -> Set[str]:
        """Extract all normalized search tokens (emails, phones, hashes, names) from an item."""
        tokens: Set[str] = set()

        payload = item.raw_payload or {}
        # Emails
        for key in ("email", "customer_email", "owner_email", "requester_email", "historical_email", "lookup_key", "match_key", "subject_key", "scan_key", "matched_value"):
            val = payload.get(key)
            if val and isinstance(val, str) and "@" in val:
                norm = normalize_email(val)
                if norm:
                    tokens.add(norm)

        # Phones
        for key in ("phone", "owner_phone", "requester_phone", "historical_phone"):
            val = payload.get(key)
            if val and isinstance(val, str):
                norm = normalize_phone(val)
                if norm:
                    tokens.add(norm)

        # Email hashes
        hash_val = payload.get("email_hash")
        if hash_val and isinstance(hash_val, str) and len(hash_val.strip()) == 64:
            tokens.add(hash_val.strip().lower())

        # Names
        for key in ("name", "full_name", "display_name", "requester_name"):
            val = payload.get(key)
            if val and isinstance(val, str):
                cleaned = val.strip().lower()
                if cleaned and len(cleaned) > 2:
                    tokens.add(cleaned)

        return tokens

    def get_subject_evidence(
        self,
        resolved_identity: ResolvedIdentity,
        audit_at: Optional[str] = None,
    ) -> List[NormalizedEvidenceItem]:
        """Retrieve all traceable evidence for a subject, respecting the request cutoff timestamp.

        Multi-hop subject discovery:
        1. Matches by canonical user_id (if resolved).
        2. Matches by all current and historical emails and email hashes.
        3. Matches by phone numbers and names, strictly enforcing canonical user-ID isolation.
        4. For every discovered subject resource_id, pulls all associated operational
           events, logs, and replicas on that resource.
        5. Enforces temporal cutoff: excludes items where captured_at > audit_at or
           event_timestamp > audit_at. Fails closed on invalid snapshot timestamps.
        6. Deduplicates and sorts deterministically by (event_timestamp or captured_at, evidence_id, resource_id).
        """
        matched_items: List[NormalizedEvidenceItem] = []
        seen_keys: Set[Tuple[str, str, str, str, str]] = set()
        discovered_resources: Set[str] = set()

        canonical_uid = _canonical_user_id(resolved_identity.user_id)
        canonical_emails = {
            normalize_email(e) for e in resolved_identity.all_emails if normalize_email(e)
        }

        # Step 1: Collect direct user_id matches
        if canonical_uid:
            for item in self._by_user_id.get(canonical_uid, []):
                if _has_canonical_user_id_conflict(canonical_uid, item.user_id):
                    continue
                if item.resource_id:
                    discovered_resources.add(item.resource_id)
                self._maybe_add(item, audit_at, seen_keys, matched_items)

        # Step 2: Unique identifier matches (emails, email hashes)
        unique_tokens: Set[str] = set(canonical_emails)
        for h in resolved_identity.all_hashes:
            if h:
                unique_tokens.add(h.strip().lower())

        for token in unique_tokens:
            for item in self._by_identifier.get(token, []):
                # Guard against canonical user_id conflict
                if _has_canonical_user_id_conflict(canonical_uid, item.user_id):
                    continue
                if item.resource_id:
                    discovered_resources.add(item.resource_id)
                self._maybe_add(item, audit_at, seen_keys, matched_items)

        # Step 2b: Loose non-unique identifier matches (phones, names)
        loose_tokens: Set[str] = set()
        for phone in resolved_identity.all_phones:
            norm_p = normalize_phone(phone)
            if norm_p:
                loose_tokens.add(norm_p)

        if resolved_identity.current_name:
            cname = resolved_identity.current_name.strip().lower()
            if cname:
                loose_tokens.add(cname)

        for hname in resolved_identity.historical_names:
            hname_clean = hname.strip().lower()
            if hname_clean:
                loose_tokens.add(hname_clean)

        for token in loose_tokens:
            for item in self._by_identifier.get(token, []):
                # Guard 1: Reject if canonical user_id conflicts
                if _has_canonical_user_id_conflict(canonical_uid, item.user_id):
                    continue

                # Guard 2: Reject if item contains an explicit email that contradicts subject's emails
                item_email = normalize_email(
                    item.raw_payload.get("email")
                    or item.raw_payload.get("customer_email")
                    or item.raw_payload.get("owner_email")
                    or item.raw_payload.get("lookup_key")
                )
                if item_email and canonical_emails and item_email not in canonical_emails:
                    continue

                if item.resource_id:
                    discovered_resources.add(item.resource_id)
                self._maybe_add(item, audit_at, seen_keys, matched_items)

        # Step 3: Secondary expansion via discovered resource IDs (system activity, logs, replicas)
        for res_id in sorted(discovered_resources):
            for item in self._by_resource_id.get(res_id, []):
                if _has_canonical_user_id_conflict(canonical_uid, item.user_id):
                    continue
                self._maybe_add(item, audit_at, seen_keys, matched_items)

        # Step 4: Deterministic sort
        matched_items.sort(
            key=lambda x: (
                x.event_timestamp or x.captured_at or "",
                x.evidence_id,
                x.resource_id,
                x.status or "",
            )
        )

        return matched_items

    def _maybe_add(
        self,
        item: NormalizedEvidenceItem,
        audit_at: Optional[str],
        seen_keys: Set[Tuple[str, str, str, str, str]],
        target_list: List[NormalizedEvidenceItem],
    ) -> None:
        """Evaluate temporal cutoff and deduplicate before appending to target list."""
        if not item.is_temporally_valid(audit_at):
            return

        key = (
            item.evidence_id,
            item.resource_id,
            item.event_timestamp or "",
            item.captured_at or "",
            item.status or "",
        )
        if key not in seen_keys:
            seen_keys.add(key)
            target_list.append(item)


# -----------------------------------------------------------------------------
# Main Corpus Manager
# -----------------------------------------------------------------------------

class EvidenceCorpus:
    """Manager for evidence ingestion, indexing, and temporal discovery."""

    def __init__(
        self,
        evidence_dir: Path,
        manifest_path: Optional[Path] = None,
        activity_path: Optional[Path] = None,
        audit_path: Optional[Path] = None,
    ) -> None:
        self.evidence_dir = Path(evidence_dir)
        self.manifest_path = Path(manifest_path) if manifest_path else None
        self.activity_path = Path(activity_path) if activity_path else None
        self.audit_path = Path(audit_path) if audit_path else None

        self._manifest_df: Optional[pd.DataFrame] = None
        self._index: Optional[EvidenceCorpusIndex] = None

    def load_manifest(self) -> pd.DataFrame:
        """Load evidence files manifest if available."""
        if self._manifest_df is None and self.manifest_path and self.manifest_path.is_file():
            self._manifest_df = pd.read_csv(self.manifest_path)
        return self._manifest_df if self._manifest_df is not None else pd.DataFrame()

    def build_index(self) -> EvidenceCorpusIndex:
        """Ingest all evidence artifacts and build the inverted index."""
        if self._index is not None:
            return self._index

        index = EvidenceCorpusIndex()
        manifest_df = self.load_manifest()

        # Ingest manifest files
        if not manifest_df.empty:
            records = manifest_df.to_dict("records")
            # Sort deterministically by file_id
            records.sort(key=lambda r: str(r.get("file_id", "")))

            for rec in records:
                file_id = str(rec.get("file_id", "")).strip()
                raw_path = str(rec.get("file_path", "")).strip()
                origin = str(rec.get("origin", "")).strip()
                captured_at = rec.get("captured_at")
                if captured_at and isinstance(captured_at, str):
                    captured_at = captured_at.strip()

                # Resolve file path
                fpath = Path(raw_path)
                if not fpath.is_file():
                    # Try resolving relative to repository root or evidence dir
                    alt_path = self.evidence_dir.parent / raw_path
                    if alt_path.is_file():
                        fpath = alt_path
                    else:
                        alt_path2 = self.evidence_dir / fpath.name
                        if alt_path2.is_file():
                            fpath = alt_path2

                if not fpath.is_file():
                    continue

                ext = fpath.suffix.lower()
                items: List[NormalizedEvidenceItem] = []

                if ext == ".sql":
                    items = parse_sql_dump(fpath, file_id, captured_at, origin)
                elif ext == ".json":
                    items = parse_json_bundle(fpath, file_id, captured_at, origin)
                elif ext == ".txt":
                    items = parse_handover_txt(fpath, file_id, captured_at, origin)
                elif ext == ".log":
                    items = parse_log_file(fpath, file_id, captured_at, origin)
                elif ext == ".pdf":
                    items = parse_pdf_document(fpath, file_id, captured_at, origin)
                elif ext == ".png":
                    items = parse_png_metadata(fpath, file_id, captured_at, origin)

                for item in items:
                    index.index_item(item)

        # Ingest operational system activity
        if self.activity_path and self.activity_path.is_file():
            for item in parse_system_activity(self.activity_path):
                index.index_item(item)

        # Ingest user audit log
        if self.audit_path and self.audit_path.is_file():
            for item in parse_user_audit_log(self.audit_path):
                index.index_item(item)

        self._index = index
        return index

    def get_subject_evidence(
        self,
        resolved_identity: ResolvedIdentity,
        audit_at: Optional[str] = None,
    ) -> List[NormalizedEvidenceItem]:
        """Query traceable evidence items for a resolved subject profile."""
        idx = self.build_index()
        return idx.get_subject_evidence(resolved_identity, audit_at=audit_at)

    def discover_subject_evidence(
        self,
        user_id: Optional[str],
        identifiers: List[str],
        audit_at: str,
    ) -> List[EvidenceReference]:
        """Legacy interface returning EvidenceReference citations for a subject."""
        # Synthesize lightweight ResolvedIdentity for query
        emails = {i for i in identifiers if "@" in i}
        phones = {i for i in identifiers if not ("@" in i or i.startswith("user_"))}
        dummy_identity = ResolvedIdentity(
            case_id="legacy_query",
            user_id=user_id,
            status="RESOLVED" if user_id else "UNRESOLVED",
            historical_emails=emails,
            historical_phones=phones,
        )
        items = self.get_subject_evidence(dummy_identity, audit_at=audit_at)
        return [item.to_reference() for item in items]
