"""Identity and historical identifier resolution module.

Responsible for:
1. Mapping case request email to current user identity snapshot (user_identities.csv).
2. Tracing historical identifier changes via audit logs (user_audit_log.csv).
3. Resolving the canonical internal user_id, historical emails, phone numbers, and hashes.
4. Detecting ambiguous or unresolved identities safely without guessing.
5. Preserving provenance for every linked identifier.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
import pandas as pd


@dataclass
class ResolvedIdentity:
    """Resolved current and historical identity profile for a case subject."""
    case_id: str
    user_id: Optional[str] = None
    status: str = "RESOLVED"  # "RESOLVED", "UNRESOLVED", "AMBIGUOUS"
    current_email: Optional[str] = None
    current_name: Optional[str] = None
    current_phone: Optional[str] = None
    historical_emails: Set[str] = field(default_factory=set)
    historical_phones: Set[str] = field(default_factory=set)
    historical_names: Set[str] = field(default_factory=set)
    email_hashes: Set[str] = field(default_factory=set)
    provenance: Dict[str, str] = field(default_factory=dict)
    confidence: float = 1.0
    ambiguity_reason: Optional[str] = None

    @property
    def is_resolved(self) -> bool:
        """Return True if identity was uniquely resolved to a canonical user_id."""
        return self.status == "RESOLVED" and self.user_id is not None

    @property
    def all_emails(self) -> Set[str]:
        """Return all emails (current and historical) associated with this subject."""
        emails = set(self.historical_emails)
        if self.current_email:
            emails.add(self.current_email)
        return emails

    @property
    def all_phones(self) -> Set[str]:
        """Return all phone numbers associated with this subject."""
        phones = set(self.historical_phones)
        if self.current_phone:
            phones.add(self.current_phone)
        return phones

    @property
    def all_hashes(self) -> Set[str]:
        """Return all SHA-256 email hashes associated with this subject."""
        return set(self.email_hashes)


def normalize_email(email: Optional[str]) -> str:
    """Normalize email address with whitespace trimming and case insensitivity."""
    if not email or not isinstance(email, str):
        return ""
    return email.strip().lower()


def normalize_phone(phone: Optional[str]) -> str:
    """Normalize phone number by stripping leading/trailing whitespace."""
    if not phone or not isinstance(phone, str):
        return ""
    return phone.strip()


def parse_iso_timestamp(ts: Optional[str]) -> Optional[datetime]:
    """Parse ISO-8601 timestamp string into timezone-aware UTC datetime.

    Conservatively returns None if timestamp is None, empty, malformed, or timezone-naive
    (strictly avoids silently guessing timezones without explicit offset/indicator).
    """
    if not ts or not isinstance(ts, str):
        return None
    cleaned = ts.strip()
    if not cleaned:
        return None
    try:
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            # Reject timezone-naive timestamps to prevent accidental temporal drift
            return None
        return dt.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


class IdentityGraph:
    """In-memory multi-hop identity graph for canonical user resolution."""

    def __init__(
        self,
        identities_df: Optional[pd.DataFrame] = None,
        audit_log_df: Optional[pd.DataFrame] = None,
    ) -> None:
        self.identities_df = identities_df
        self.audit_log_df = audit_log_df

        # Indexed lookups
        self._curr_by_email: Dict[str, Dict[str, Any]] = {}
        self._curr_by_uid: Dict[str, Dict[str, Any]] = {}
        self._audit_records_by_uid: Dict[str, List[Dict[str, Any]]] = {}
        self._email_to_uids: Dict[str, Set[str]] = {}

        if identities_df is not None and not identities_df.empty:
            self._index_current_identities(identities_df)
        if audit_log_df is not None and not audit_log_df.empty:
            self._index_audit_log(audit_log_df)

    def _index_current_identities(self, df: pd.DataFrame) -> None:
        """Index current identity snapshot deterministically."""
        records = df.to_dict("records")
        # Sort by user_id for deterministic index order
        records.sort(key=lambda r: str(r.get("user_id", "")).strip())
        for record in records:
            uid = str(record.get("user_id", "")).strip()
            if not uid:
                continue
            self._curr_by_uid[uid] = record

            raw_email = str(record.get("email", ""))
            norm_email = normalize_email(raw_email)
            if norm_email:
                self._curr_by_email[norm_email] = record
                self._email_to_uids.setdefault(norm_email, set()).add(uid)

    def _index_audit_log(self, df: pd.DataFrame) -> None:
        """Index identity change audit history deterministically."""
        records = df.to_dict("records")

        def get_sort_key(record: Dict[str, Any]) -> Tuple[datetime, str]:
            raw_ts = str(record.get("event_time", "")).strip()
            parsed = parse_iso_timestamp(raw_ts)
            dt_val = parsed if parsed is not None else datetime.max.replace(tzinfo=timezone.utc)
            return (dt_val, str(record.get("audit_id", "")))

        records.sort(key=get_sort_key)

        for record in records:
            uid = str(record.get("user_id", "")).strip()
            if not uid:
                continue
            self._audit_records_by_uid.setdefault(uid, []).append(record)

            fname = str(record.get("field_name", "")).strip().lower()
            if fname == "email":
                old_em = normalize_email(str(record.get("old_value", "")))
                new_em = normalize_email(str(record.get("new_value", "")))
                if old_em:
                    self._email_to_uids.setdefault(old_em, set()).add(uid)
                if new_em:
                    self._email_to_uids.setdefault(new_em, set()).add(uid)

    def resolve(
        self,
        case_id: str,
        request_email: str,
        audit_at: Optional[str] = None,
    ) -> ResolvedIdentity:
        """Resolve current and historical identifiers for a given deletion request email.

        Enforces:
        - Exact current-email matching.
        - Historical audit-log alias traversal.
        - Ambiguity detection (multiple matching canonical users).
        - Temporal isolation: ignore audit log events after audit_at using normalized UTC instants.
        - Conservative validation of missing, malformed, or timezone-naive timestamps.
        - Comprehensive identifier aggregation (phone numbers, hashes, aliases).
        """
        norm_req_email = normalize_email(request_email)

        profile = ResolvedIdentity(
            case_id=case_id,
            current_email=request_email.strip() if request_email else None,
            historical_emails={request_email.strip()} if request_email else set(),
            provenance={"request_email": "deletion_requests.email"},
        )

        if not norm_req_email:
            profile.status = "UNRESOLVED"
            profile.confidence = 0.0
            profile.ambiguity_reason = "Request email is empty or invalid"
            return profile

        # Parse and validate audit_at cutoff if provided
        cutoff_dt: Optional[datetime] = None
        if audit_at and audit_at.strip():
            cutoff_dt = parse_iso_timestamp(audit_at)
            if cutoff_dt is None:
                # Deliberate & conservative: an unverifiable or timezone-naive cutoff cannot safely protect data
                profile.status = "UNRESOLVED"
                profile.confidence = 0.0
                profile.ambiguity_reason = f"Audit cutoff timestamp '{audit_at}' is invalid, malformed, or timezone-naive"
                return profile

        # Candidate canonical user_ids
        candidate_uids: Set[str] = set()

        # 1. Direct match in current snapshot
        if norm_req_email in self._curr_by_email:
            candidate_uids.add(self._curr_by_email[norm_req_email]["user_id"])

        # 2. Historical match in audit log
        if norm_req_email in self._email_to_uids:
            # Check temporal cutoff for each audit record linking to this email
            for uid in self._email_to_uids[norm_req_email]:
                # If direct match already found, it's valid
                if uid in candidate_uids:
                    continue
                # Verify audit link occurred at or before audit_at
                audit_records = self._audit_records_by_uid.get(uid, [])
                for ar in audit_records:
                    if str(ar.get("field_name", "")).strip().lower() == "email":
                        old_em = normalize_email(str(ar.get("old_value", "")))
                        new_em = normalize_email(str(ar.get("new_value", "")))
                        if norm_req_email in (old_em, new_em):
                            ev_time_raw = str(ar.get("event_time", "")).strip()
                            ev_dt = parse_iso_timestamp(ev_time_raw)
                            if cutoff_dt is not None:
                                if ev_dt is None or ev_dt > cutoff_dt:
                                    continue  # Conservative temporal isolation: drop future or unparseable events
                            candidate_uids.add(uid)

        # Evaluate ambiguity
        if len(candidate_uids) == 0:
            profile.status = "UNRESOLVED"
            profile.confidence = 0.0
            profile.ambiguity_reason = f"No user identity found for email '{request_email}'"
            return profile

        if len(candidate_uids) > 1:
            profile.status = "AMBIGUOUS"
            profile.confidence = 0.5
            profile.ambiguity_reason = (
                f"Email '{request_email}' maps to multiple conflicting users: {sorted(candidate_uids)}"
            )
            return profile

        # Uniquely resolved canonical user
        canonical_uid = next(iter(candidate_uids))
        profile.user_id = canonical_uid
        profile.status = "RESOLVED"
        profile.confidence = 1.0

        # Ingest current identity snapshot attributes
        if canonical_uid in self._curr_by_uid:
            curr = self._curr_by_uid[canonical_uid]
            profile.current_name = str(curr.get("name", "")).strip() or None
            profile.current_email = str(curr.get("email", "")).strip() or None
            profile.current_phone = str(curr.get("phone", "")).strip() or None

            curr_hash = str(curr.get("email_hash", "")).strip()
            if curr_hash and curr_hash.lower() != "nan":
                profile.email_hashes.add(curr_hash)
                profile.provenance[curr_hash] = "user_identities.email_hash"

            profile.provenance[canonical_uid] = "user_identities.user_id"
            if profile.current_email:
                profile.provenance[profile.current_email] = "user_identities.email"
            if profile.current_phone:
                profile.provenance[profile.current_phone] = "user_identities.phone"

        # Ingest all historical identifier mutations from audit log up to audit_at
        user_audits = self._audit_records_by_uid.get(canonical_uid, [])
        for ar in user_audits:
            ev_time_raw = str(ar.get("event_time", "")).strip()
            ev_dt = parse_iso_timestamp(ev_time_raw)
            if cutoff_dt is not None:
                if ev_dt is None or ev_dt > cutoff_dt:
                    continue  # Skip future or unverifiable mutations

            audit_id = str(ar.get("audit_id", "")).strip()
            fname = str(ar.get("field_name", "")).strip().lower()
            old_val = str(ar.get("old_value", "")).strip()
            new_val = str(ar.get("new_value", "")).strip()

            if fname == "email":
                if old_val and old_val.lower() != "nan":
                    profile.historical_emails.add(old_val)
                    profile.provenance[old_val] = f"user_audit_log.old_value:{audit_id}"
                if new_val and new_val.lower() != "nan":
                    profile.historical_emails.add(new_val)
                    profile.provenance[new_val] = f"user_audit_log.new_value:{audit_id}"

            elif fname == "phone":
                if old_val and old_val.lower() != "nan":
                    profile.historical_phones.add(old_val)
                    profile.provenance[old_val] = f"user_audit_log.old_value:{audit_id}"
                if new_val and new_val.lower() != "nan":
                    profile.historical_phones.add(new_val)
                    profile.provenance[new_val] = f"user_audit_log.new_value:{audit_id}"

            elif fname == "email_hash":
                if old_val and old_val.lower() != "nan":
                    profile.email_hashes.add(old_val)
                    profile.provenance[old_val] = f"user_audit_log.old_value:{audit_id}"
                if new_val and new_val.lower() != "nan":
                    profile.email_hashes.add(new_val)
                    profile.provenance[new_val] = f"user_audit_log.new_value:{audit_id}"

            elif fname == "name":
                if old_val and old_val.lower() != "nan":
                    profile.historical_names.add(old_val)
                if new_val and new_val.lower() != "nan":
                    profile.historical_names.add(new_val)

        return profile


def resolve_subject_identity(
    case_id: str,
    request_email: str,
    identities_df: Optional[pd.DataFrame] = None,
    audit_log_df: Optional[pd.DataFrame] = None,
    audit_at: Optional[str] = None,
) -> ResolvedIdentity:
    """Functional interface for resolving subject identity from provided DataFrames.

    Backward-compatible drop-in replacement for starter interface.
    """
    if identities_df is None and audit_log_df is None:
        return ResolvedIdentity(
            case_id=case_id,
            current_email=request_email.strip() if request_email else None,
            historical_emails={request_email.strip()} if request_email else set(),
            status="UNRESOLVED",
            confidence=0.0,
            ambiguity_reason="No identity dataframes provided",
        )

    graph = IdentityGraph(identities_df, audit_log_df)
    return graph.resolve(case_id, request_email, audit_at=audit_at)
