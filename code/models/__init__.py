"""Data models and enums for Ghost Data Still Exists deletion audit agent.

Strictly adheres to the official HackerRank Orchestrate competition specification.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Tuple


class DeletionStatus(str, Enum):
    """Allowed top-level deletion statuses."""
    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class Phase(str, Enum):
    """Execution phase for audit steps."""
    FINDING = "FINDING"
    REMEDIATION = "REMEDIATION"
    VERIFICATION = "VERIFICATION"


class State(str, Enum):
    """Permitted state values for operations."""
    PRESENT = "PRESENT"
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"
    BLOCKED = "BLOCKED"
    ABSENT = "ABSENT"
    REDACTED = "REDACTED"
    ANONYMIZED = "ANONYMIZED"


class Operation(str, Enum):
    """Allowed operations across all audit phases."""
    # Findings
    REPORT_REMAINING_RECORD = "REPORT_REMAINING_RECORD"
    REPORT_EXPOSED_PII = "REPORT_EXPOSED_PII"
    REPORT_ACTIVE_DATA_FLOW = "REPORT_ACTIVE_DATA_FLOW"
    REPORT_RESTORE_RISK = "REPORT_RESTORE_RISK"

    # Remediation
    DISABLE_DATA_FLOW = "DISABLE_DATA_FLOW"
    BLOCK_RESTORE = "BLOCK_RESTORE"
    DELETE_RECORD = "DELETE_RECORD"
    REDACT_RECORD = "REDACT_RECORD"
    ANONYMIZE_RECORD = "ANONYMIZE_RECORD"

    # Verification
    VERIFY_RECORD_ABSENT = "VERIFY_RECORD_ABSENT"
    VERIFY_RECORD_PRESENT = "VERIFY_RECORD_PRESENT"
    VERIFY_RECORD_REDACTED = "VERIFY_RECORD_REDACTED"
    VERIFY_RECORD_ANONYMIZED = "VERIFY_RECORD_ANONYMIZED"
    VERIFY_DATA_FLOW_DISABLED = "VERIFY_DATA_FLOW_DISABLED"
    VERIFY_RESTORE_BLOCKED = "VERIFY_RESTORE_BLOCKED"


# Official specification mapping: Operation -> (Phase, State)
OPERATION_CONTRACT: Dict[Operation, Tuple[Phase, State]] = {
    # FINDING phase
    Operation.REPORT_REMAINING_RECORD: (Phase.FINDING, State.PRESENT),
    Operation.REPORT_EXPOSED_PII: (Phase.FINDING, State.PRESENT),
    Operation.REPORT_ACTIVE_DATA_FLOW: (Phase.FINDING, State.ACTIVE),
    Operation.REPORT_RESTORE_RISK: (Phase.FINDING, State.ACTIVE),
    # REMEDIATION phase
    Operation.DISABLE_DATA_FLOW: (Phase.REMEDIATION, State.DISABLED),
    Operation.BLOCK_RESTORE: (Phase.REMEDIATION, State.BLOCKED),
    Operation.DELETE_RECORD: (Phase.REMEDIATION, State.ABSENT),
    Operation.REDACT_RECORD: (Phase.REMEDIATION, State.REDACTED),
    Operation.ANONYMIZE_RECORD: (Phase.REMEDIATION, State.ANONYMIZED),
    # VERIFICATION phase
    Operation.VERIFY_RECORD_ABSENT: (Phase.VERIFICATION, State.ABSENT),
    Operation.VERIFY_RECORD_PRESENT: (Phase.VERIFICATION, State.PRESENT),
    Operation.VERIFY_RECORD_REDACTED: (Phase.VERIFICATION, State.REDACTED),
    Operation.VERIFY_RECORD_ANONYMIZED: (Phase.VERIFICATION, State.ANONYMIZED),
    Operation.VERIFY_DATA_FLOW_DISABLED: (Phase.VERIFICATION, State.DISABLED),
    Operation.VERIFY_RESTORE_BLOCKED: (Phase.VERIFICATION, State.BLOCKED),
}

# Official sort order for operations within each phase
OPERATION_ORDER: Dict[Phase, List[Operation]] = {
    Phase.FINDING: [
        Operation.REPORT_REMAINING_RECORD,
        Operation.REPORT_EXPOSED_PII,
        Operation.REPORT_ACTIVE_DATA_FLOW,
        Operation.REPORT_RESTORE_RISK,
    ],
    Phase.REMEDIATION: [
        Operation.DISABLE_DATA_FLOW,
        Operation.BLOCK_RESTORE,
        Operation.DELETE_RECORD,
        Operation.REDACT_RECORD,
        Operation.ANONYMIZE_RECORD,
    ],
    Phase.VERIFICATION: [
        Operation.VERIFY_RECORD_ABSENT,
        Operation.VERIFY_RECORD_PRESENT,
        Operation.VERIFY_RECORD_REDACTED,
        Operation.VERIFY_RECORD_ANONYMIZED,
        Operation.VERIFY_DATA_FLOW_DISABLED,
        Operation.VERIFY_RESTORE_BLOCKED,
    ],
}


@dataclass
class AuditStep:
    """A single ordered step in steps_json."""
    step_no: int
    phase: Phase
    system_id: str
    resource_id: str
    operation: Operation
    state: State
    evidence_id: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert step to exact dictionary structure expected in steps_json."""
        return {
            "step_no": self.step_no,
            "phase": self.phase.value if isinstance(self.phase, Phase) else str(self.phase),
            "system_id": self.system_id,
            "resource_id": self.resource_id,
            "operation": self.operation.value if isinstance(self.operation, Operation) else str(self.operation),
            "state": self.state.value if isinstance(self.state, State) else str(self.state),
            "evidence_id": self.evidence_id,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AuditStep:
        """Instantiate AuditStep from a dictionary with strict validation."""
        return cls(
            step_no=int(data["step_no"]),
            phase=Phase(data["phase"]),
            system_id=str(data["system_id"]),
            resource_id=str(data["resource_id"]),
            operation=Operation(data["operation"]),
            state=State(data["state"]),
            evidence_id=str(data.get("evidence_id", "")),
        )


@dataclass
class CaseAuditResult:
    """Complete audit decision and steps for a single case."""
    case_id: str
    deletion_status: DeletionStatus
    steps: List[AuditStep]

    def to_row(self) -> Tuple[str, str, List[Dict[str, Any]]]:
        """Convert to tuple for serialization."""
        return (
            self.case_id,
            self.deletion_status.value,
            [s.to_dict() for s in self.steps],
        )
