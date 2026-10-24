"""Identity and historical identifier resolution module.

Responsible for:
1. Mapping case request email to current user identity snapshot (user_identities.csv).
2. Tracing historical identifier changes via audit logs (user_audit_log.csv).
3. Resolving the stable internal user_id, historical emails, phone numbers, and hashes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Set
import pandas as pd


@dataclass
class ResolvedIdentity:
    """Resolved current and historical identity profile for a case subject."""
    case_id: str
    user_id: Optional[str] = None
    current_email: Optional[str] = None
    current_name: Optional[str] = None
    current_phone: Optional[str] = None
    historical_emails: Set[str] = field(default_factory=set)
    historical_phones: Set[str] = field(default_factory=set)
    email_hashes: Set[str] = field(default_factory=set)

    @property
    def all_emails(self) -> Set[str]:
        emails = set(self.historical_emails)
        if self.current_email:
            emails.add(self.current_email)
        return emails


def resolve_subject_identity(
    case_id: str,
    request_email: str,
    identities_df: Optional[pd.DataFrame] = None,
    audit_log_df: Optional[pd.DataFrame] = None,
) -> ResolvedIdentity:
    """Resolve current and historical identifiers for a given deletion request.

    TODO: Implement multi-hop resolution across user_identities.csv and user_audit_log.csv
    in the next implementation phase.
    """
    profile = ResolvedIdentity(
        case_id=case_id,
        current_email=request_email,
        historical_emails={request_email},
    )

    if identities_df is None or audit_log_df is None:
        return profile

    # Basic lookup starter logic
    match_curr = identities_df[identities_df["email"].str.lower() == request_email.lower()]
    if not match_curr.empty:
        row = match_curr.iloc[0]
        profile.user_id = str(row.get("user_id", ""))
        profile.current_name = str(row.get("name", ""))
        profile.current_phone = str(row.get("phone", ""))
        if "email_hash" in row and pd.notna(row["email_hash"]):
            profile.email_hashes.add(str(row["email_hash"]))

    return profile
