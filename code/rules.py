"""Policy evaluation and deletion-status determination module.

Responsible for:
1. Classifying request intent: determining if request authorizes deletion or is NOT_APPLICABLE.
2. Applying deletion rules from deletion_rules.csv (DELETE, REDACT, ANONYMIZE, RETAIN).
3. Handling account tombstones and retention constraints.
4. Evaluating final deletion status: COMPLETE, INCOMPLETE, or NOT_APPLICABLE.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional
import pandas as pd

from code.models import DeletionStatus


@dataclass
class DeletionRule:
    """A policy rule loaded from deletion_rules.csv."""
    rule_id: str
    data_category: str
    condition: str
    required_action: str  # DELETE, REDACT, ANONYMIZE, RETAIN


class PolicyEngine:
    """Evaluates deletion policy and rules across customer resources."""

    def __init__(self, rules_path: Optional[Path] = None) -> None:
        self.rules_path = rules_path
        self.rules: Dict[str, DeletionRule] = {}
        if self.rules_path and self.rules_path.is_file():
            self._load_rules()

    def _load_rules(self) -> None:
        df = pd.read_csv(self.rules_path)
        for _, row in df.iterrows():
            rule = DeletionRule(
                rule_id=str(row["rule_id"]),
                data_category=str(row["data_category"]),
                condition=str(row["condition"]),
                required_action=str(row["required_action"]),
            )
            self.rules[rule.rule_id] = rule

    def is_deletion_authorized(self, request_text: str) -> bool:
        """Determine whether request text authorizes deletion.

        TODO: Implement robust intent analysis (handling multi-language deletion requests
        vs access/rectification/export/marketing opt-outs) in the next phase.
        """
        # Baseline check placeholder
        if not request_text or not isinstance(request_text, str):
            return False
        return True
