"""Remediation and verification planner module.

Responsible for:
1. Synthesizing discovered findings, remediation actions, and post-remediation verification checks.
2. Enforcing strict phase ordering: FINDING -> REMEDIATION -> VERIFICATION.
3. Enforcing operation precedence within phases:
   - Findings: REPORT_REMAINING_RECORD -> REPORT_EXPOSED_PII -> REPORT_ACTIVE_DATA_FLOW -> REPORT_RESTORE_RISK
   - Remediation: DISABLE_DATA_FLOW -> BLOCK_RESTORE -> DELETE_RECORD -> REDACT_RECORD -> ANONYMIZE_RECORD
   - Verification: VERIFY_RECORD_ABSENT -> VERIFY_RECORD_PRESENT -> VERIFY_RECORD_REDACTED ->
     VERIFY_RECORD_ANONYMIZED -> VERIFY_DATA_FLOW_DISABLED -> VERIFY_RESTORE_BLOCKED
4. Sorting by system_id, then resource_id in ascending order.
5. Consecutively numbering steps starting at 1.
"""

from __future__ import annotations

from typing import List, Tuple

from code.models import (
    OPERATION_ORDER,
    AuditStep,
    Operation,
    Phase,
)

PHASE_PRIORITY = {
    Phase.FINDING: 0,
    Phase.REMEDIATION: 1,
    Phase.VERIFICATION: 2,
}


def sort_and_number_steps(steps: List[AuditStep]) -> List[AuditStep]:
    """Sort audit steps according to the official competition specification and renumber consecutively.

    Ordering rule:
    1. Phase order: FINDING -> REMEDIATION -> VERIFICATION
    2. Operation order within phase (defined by OPERATION_ORDER)
    3. Ascending order by system_id
    4. Ascending order by resource_id
    """
    def sort_key(step: AuditStep) -> Tuple[int, int, str, str]:
        phase_rank = PHASE_PRIORITY.get(step.phase, 99)
        op_list = OPERATION_ORDER.get(step.phase, [])
        op_rank = op_list.index(step.operation) if step.operation in op_list else 99
        return (phase_rank, op_rank, step.system_id, step.resource_id)

    sorted_steps = sorted(steps, key=sort_key)

    # Renumber consecutively starting at 1
    numbered_steps: List[AuditStep] = []
    for idx, s in enumerate(sorted_steps, start=1):
        s.step_no = idx
        numbered_steps.append(s)

    return numbered_steps
