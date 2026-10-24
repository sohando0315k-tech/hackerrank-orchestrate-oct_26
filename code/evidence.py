"""Evidence discovery, filtering, and parsing module.

Responsible for:
1. Ingesting the evidence manifest (evidence_files.csv).
2. Filtering evidence events by cutoff timestamp (`audit_at`).
3. Discovering references to subject identifiers across SQL snapshots, JSON bundles,
   logs, PDF documents, and system activity logs.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional
import pandas as pd


@dataclass
class EvidenceReference:
    """A citation of evidence proving an audit finding or compliant state."""
    evidence_id: str  # file_id, activity_id, or audit_id
    source_type: str  # file, activity, or audit
    captured_at: Optional[str] = None
    system_id: Optional[str] = None
    resource_id: Optional[str] = None
    summary: str = ""


class EvidenceCorpus:
    """Manager for evidence discovery and temporal filtering."""

    def __init__(self, evidence_dir: Path, manifest_path: Optional[Path] = None) -> None:
        self.evidence_dir = Path(evidence_dir)
        self.manifest_path = Path(manifest_path) if manifest_path else None
        self._manifest_df: Optional[pd.DataFrame] = None

    def load_manifest(self) -> pd.DataFrame:
        """Load evidence files manifest if available."""
        if self._manifest_df is None and self.manifest_path and self.manifest_path.is_file():
            self._manifest_df = pd.read_csv(self.manifest_path)
        return self._manifest_df if self._manifest_df is not None else pd.DataFrame()

    def discover_subject_evidence(
        self,
        user_id: Optional[str],
        identifiers: List[str],
        audit_at: str,
    ) -> List[EvidenceReference]:
        """Discover evidence items related to subject up to audit_at timestamp.

        TODO: Implement multimodal parsers for SQL snapshots, JSON records, logs,
        and documents in the next development phase.
        """
        return []
