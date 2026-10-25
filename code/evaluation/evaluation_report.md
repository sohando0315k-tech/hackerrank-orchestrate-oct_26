# Evaluation Report — Ghost Data Still Exists

## 1. Executive Summary

This report documents the evaluation results and systematic optimization of the **Ghost Data Still Exists** deletion-audit pipeline for the HackerRank Orchestrate (October 2026) competition.

The deterministic audit engine evaluates subject identity resolution, multi-hop evidence discovery, deletion intent classification, statutory policy rule application, and audit-step plan construction. All logic generalizes strictly to unseen test cases without hardcoded case IDs, dataset-specific answers, or synthetic evidence citations.

---

## 2. Benchmark Metrics: Baseline vs Optimized

The pipeline was benchmarked against the official ground truth in `dataset/sample_output.csv` (32 sample cases, 193 total steps):

| Metric | Baseline | Optimized Final | Delta / Improvement |
| :--- | :---: | :---: | :---: |
| **Deletion Status Accuracy** | **100.00%** (32/32) | **100.00%** (32/32) | **Maintained Perfect** |
| **Exact Case Match Accuracy** | **18.75%** (6/32) | **46.88%** (15/32) | **+28.13% (+250% relative)** |
| **Phase Alignment** | 73.06% (141/193) | **92.75%** (179/193) | **+19.69%** |
| **Evidence ID Citation Accuracy** | 77.20% (149/193) | **92.75%** (179/193) | **+15.55%** |
| **Operation Accuracy** | 50.26% (97/193) | **83.94%** (162/193) | **+33.68%** |
| **State Accuracy** | 53.37% (103/193) | **83.94%** (162/193) | **+30.57%** |
| **System ID Accuracy** | 51.30% (99/193) | **83.94%** (162/193) | **+32.64%** |
| **Resource ID Accuracy** | 52.85% (102/193) | **78.24%** (151/193) | **+25.39%** |
| **Full Pipeline Runtime (518 cases)** | 1.09s | **1.54s** (3.0 ms/case) | **Real-time Deterministic** |

Cases with 100% exact step-sequence and field match include: `case_01`, `case_02`, `case_05`, `case_06`, `case_07`, `case_08`, `case_10`, `case_11`, `case_12`, `case_13`, `case_14`, `case_15`, `case_16`, `case_17`, `case_19`.

---

## 3. Systematic Root Cause Failures Addressed

1. **Multi-Line Log Trace Correlation:**
   - *Issue:* Log events in microservice distributed traces often span multiple log entries (e.g. `event=profile_lookup_started` with `lookup_key="..."` followed by `event=profile_lookup_completed` with `resource_id="..."`). Uncorrelated single-line parsing failed to link the resource with the subject identity.
   - *Fix:* Implemented trace correlation across log dialects (`service_events`, `readback_logs`, `syslog`, `pipe-delimited`) associating `correlation_key`, `lookup_key`, and `subject_reference` with downstream resource lookups and audit entries.
   - *Impact:* Resolved primary account and security audit verifications for `case_12`, `case_15`, `case_17`, and `case_19`.

2. **SQL Read Replica Nested Document Unpacking:**
   - *Issue:* Database read replicas stored JSON documents in nested column payloads (e.g. `doc` or `prof` JSON strings in `customer_data_read_replica_20260921.sql`), concealing residual customer profiles.
   - *Fix:* Enhanced SQL dump parser to unpack serialized JSON objects and map canonical subject identifiers.
   - *Impact:* Recovered un-deleted search index records `search_1007` (`case_16`) and `search_8911` (`case_22`).

3. **Support Replica Contact Query Classification (Rule 01 vs Rule 05):**
   - *Issue:* Support replica log entries with `deletion_marker_check` or `contact_query_completed` were mistakenly classified as support conversation tickets (`SUPPORT_MESSAGE`, requiring redaction) rather than customer contact profile entries (`USER_PROFILE`, requiring deletion under Rule 01/06).
   - *Fix:* Conditioned classification on replica contact queries and marker status checks to enforce `REPORT_REMAINING_RECORD` -> `DELETE_RECORD` -> `VERIFY_RECORD_ABSENT`.
   - *Impact:* Converted `case_10` into a 100% exact match.

4. **Connector and Data Flow Compliance Logic:**
   - *Issue:* Active integration connectors with `status="ACTIVE"` were bypassing compliance checks if delivery status was not explicitly stopped.
   - *Fix:* Enforced strict verification that enabled connectors or active flows generate `REPORT_ACTIVE_DATA_FLOW` findings and `DISABLE_DATA_FLOW` remediation.
   - *Impact:* Resolved compliance verification for `data_flow_9522` in `case_11`.

5. **Operational Activity Log Isolation:**
   - *Issue:* `system_activity.csv` records represent an internal deletion worker audit trail rather than residual storage repositories. Treating operational log lines as storage findings caused phantom PII findings (e.g. citing `activity_4011`).
   - *Fix:* Restricted residual findings strictly to authentic evidence artifacts, while using activity records solely for operational history and primary profile reconciliation.
   - *Impact:* Eliminated false-positive findings in `case_07`, `case_08`, and `case_17`.

6. **Primary Account Absence Verification and Deduplication:**
   - *Issue:* Users without positive profile hits in secondary evidence were missing primary account absence verification in `account_service`, or duplicate historical accounts from old traces were included.
   - *Fix:* Generalized primary account resolution to discover authentic account lookups, check canonical initial cohorts, and deduplicate to retain the latest authoritative primary profile.
   - *Impact:* Eliminated redundant steps and ensured every valid deletion request audits primary account absence.

---

## 4. Team-Created Evaluation Cases

To test generalization to challenging unseen scenarios beyond the 32 sample cases, three comprehensive unit evaluation suites were implemented in `tests/test_team_evaluation.py`:

1. **`test_eval_case_1_ambiguous_identity_conflict_protection`:**
   - *Scenario:* Subject `alice.eval@example.com` (`user_101`) is audited in an environment containing cross-subject evidence belonging to `user_999`.
   - *Result:* Pipeline strictly isolates canonical user IDs, filtering out the conflicting `user_999` record and verifying only `user_101`'s legitimate primary account.
   - *Status:* **PASSED**.

2. **`test_eval_case_2_partial_statutory_retention_exception`:**
   - *Scenario:* User requests account and support history deletion but requests compliance retention of security audit logs. Evidence contains an unredacted support ticket and a security audit event within retention.
   - *Result:* Pipeline flags the support ticket for redaction (`REPORT_EXPOSED_PII` -> `REDACT_RECORD` -> `VERIFY_RECORD_REDACTED`), preserves the security audit record without finding (`VERIFY_RECORD_PRESENT`), orders steps into `FINDING` -> `REMEDIATION` -> `VERIFICATION`, and outputs `INCOMPLETE`.
   - *Status:* **PASSED**.

3. **`test_eval_case_3_restore_access_risk_remediation`:**
   - *Scenario:* User requests complete deletion, but a backup archive (`backup_7741`) retains active restore access (`restore_allowed = True`).
   - *Result:* Pipeline identifies restore risk under Rule 14 (`REPORT_RESTORE_RISK`), plans remediation (`BLOCK_RESTORE` with `evidence_id=""`), plans future verification (`VERIFY_RESTORE_BLOCKED` with `evidence_id=""`), and sets status to `INCOMPLETE`.
   - *Status:* **PASSED**.

---

## 5. Verification & Specification Conformance

- **Unit Test Suite:** 107 passing tests (`pytest tests/`) in 3.08 seconds.
- **Output Validation:** Full 518-case output file `output.csv` validated via `code.output.validate_output_file`:
  - Exactly 518 data rows sorted by `case_id`.
  - Header: `case_id,deletion_status,steps_json`.
  - Valid status enum: `COMPLETE`, `INCOMPLETE`, `NOT_APPLICABLE`.
  - Strict step numbering and phase ordering (`FINDING` -> `REMEDIATION` -> `VERIFICATION`).
  - Proposed remediation and future verification steps in `INCOMPLETE` cases use empty string `""` for `evidence_id`.
