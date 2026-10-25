# Ghost Data Still Exists — AI-Powered Deletion Audit Agent

A production-grade statutory deletion audit and remediation pipeline designed for the **HackerRank Orchestrate (October 2026)** competitive engineering challenge.

---

## 1. Project Purpose

Following a catastrophic $2.4 million compliance breach where a supposedly "Complete" deletion request was resurrected in Northstar Shop's production systems, this system audits customer deletion requests. It investigates participant-visible evidence across databases, replicas, search indices, logs, and backups to prove whether customer data was truly expunged, redacted, or anonymized, or whether ghost records and restore vulnerabilities persist.

---

## 2. Challenge Overview

For each case in `dataset/deletion_requests.csv` (518 evaluation cases) and `dataset/sample_output.csv` (32 benchmark cases), the audit pipeline:
1. **Determines authorization:** Verifies whether `request_text` authorizes deletion or represents an out-of-scope inquiry (e.g. access, rectification, marketing opt-out) categorized as `NOT_APPLICABLE`.
2. **Resolves identity:** Traces current and historical identifiers (emails, phone numbers, identity hashes, canonical internal `user_id`) using `user_identities.csv` and `user_audit_log.csv`.
3. **Inspects evidence:** Evaluates database snapshots, application logs, documents, and system activity strictly up to the `audit_at` temporal cutoff boundary.
4. **Applies statutory policy:** Enforces the 15 statutory rules in `deletion_rules.csv`, accounting for legal holds, security audit exemptions, and retention tombstones.
5. **Generates ordered steps:**
   - **`COMPLETE`**: Evidence-backed verification checks proving current compliance.
   - **`INCOMPLETE`**: Concrete findings, ordered remediation steps, and post-remediation verification checks (enforcing empty `evidence_id: ""` for proposed actions).
   - **`NOT_APPLICABLE`**: Empty JSON array (`[]`).
6. **Produces submission output:** Exactly 518 sorted rows in `output.csv`.

---

## 3. Architecture & Approach Overview

The solution uses a deterministic, verifiable, multi-stage compliance pipeline designed for high accuracy and sub-2-second execution:

- **Multi-Hop Identity Graph (`code.identity`):**
  Unifies current identity records with historical audit logs. Constructs an identity graph resolving emails, aliases, and user IDs to canonical subjects while enforcing cross-subject conflict protection.
- **Multi-Format Evidence Indexer & Temporal Filter (`code.evidence`):**
  Parses heterogeneous evidence corpora (SQLite replica databases, JSON bundles, system activity logs, structured audit traces). Normalizes identifiers, correlates multi-line dialect logs, and strictly enforces temporal boundaries (`captured_at <= audit_at` and `event_timestamp <= audit_at`).
- **Intent Classification & Statutory Policy Engine (`code.policy`):**
  Classifies deletion requests versus non-deletion inquiries. Evaluates evidence against all 15 statutory deletion rules (`deletion_rules.csv`) governing user profiles, payment tokens, fraud records, support replicas, marketing lists, and security audits.
- **Deterministic Remediation & Verification Planner (`code.planner`):**
  Translates policy findings into compliant audit steps. Strictly follows official phase precedence (`FINDING` &rarr; `REMEDIATION` &rarr; `VERIFICATION`), operation ordering (`DELETE` &rarr; `PURGE` &rarr; `MASK` &rarr; `ANONYMIZE` &rarr; `VERIFY_ABSENCE`), and ascending resource ordering.
- **Output Serialization & Schema Validator (`code.output`):**
  Serializes predictions to root-level `output.csv` and performs strict schema validation on headers, row count (518 data rows), JSON syntax, and rule conformance.

---

## 4. Prerequisites

- Python 3.10+ (tested on Python 3.10, 3.11, 3.12, 3.14)
- Git 2.40+

---

## 5. Setup Instructions

### 5.1 Clone the Repository

```bash
git clone https://github.com/sohando0315k-tech/hackerrank-orchestrate-oct_26.git
cd hackerrank-orchestrate-oct_26
```

### 5.2 Virtual Environment Creation & Activation

**Linux / macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Windows PowerShell:**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

*(If script execution is disabled on PowerShell, enable it for the current process: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`)*

### 5.3 Dependency Installation

Install runtime dependencies and test packages:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
```

---

## 6. How to Run the Pipeline and Tests

### 6.1 Run the Full Audit Pipeline

Execute the end-to-end audit pipeline on all 518 cases and generate `output.csv`:

```bash
python -m code.main
```

### 6.2 Validate Configuration & Inputs (Dry Run)

Verify all input paths and dataset availability without executing an audit:

```bash
python -m code.main --dry-run
```

### 6.3 Validate Output File Schema

Validate any output CSV against the competition schema rules:

```bash
python -m code.main --validate-only output.csv
```

### 6.4 Run Benchmark Evaluation

Evaluate predictions against the official sample answers and generate markdown reports:

```bash
python -m code.evaluation.main --predictions output.csv --truth dataset/sample_output.csv --report reports/evaluation_report.md
```

### 6.5 Running Tests

**Full Test Suite (when dataset is present):**
```bash
python -m pytest tests/ -v
```
*Runs all 107 automated unit, policy, evidence, planner, output, and team evaluation tests.*

**Offline / Core Test Suite (when dataset is excluded):**
```bash
python -m pytest tests/ -v -k "not real_dataset and not test_load_statutory_rules"
```
*Runs 104 isolated unit and contract tests that do not depend on the local competition dataset files.*

---

## 7. Expected Input and Output Paths

| Type | Path | Description |
| :--- | :--- | :--- |
| **Input: Requests** | `dataset/deletion_requests.csv` | 518 full evaluation cases |
| **Input: Sample** | `dataset/sample_deletion_requests.csv` | 32 sample cases with known ground truth |
| **Input: Identities** | `dataset/user_identities.csv` | Current identity snapshot |
| **Input: Audit Log** | `dataset/user_audit_log.csv` | Historical identifier changes |
| **Input: Activity** | `dataset/system_activity.csv` | Global system events and claims |
| **Input: Rules** | `dataset/deletion_rules.csv` | 15 treatment rules for data categories |
| **Input: Evidence** | `dataset/evidence/` | Heterogeneous SQLite DBs, logs, JSONs, PDFs |
| **Output: Submission** | `output.csv` | Root-level CSV with 518 sorted cases |
| **Evaluation Report** | `code/evaluation/evaluation_report.md` | Required submission evaluation report |
| **Token Usage Report**| `code/evaluation/usage_report.md` | Required cost and token breakdown |

---

## 8. Current Implementation Status

- [x] **Project Foundation:** Git repository configured, clean modular architecture established.
- [x] **Configuration Layer:** Robust, dynamic path resolution across environments (`code.config`).
- [x] **Domain Models:** Strict enums for all 15 operations, states, and phases (`code.models`).
- [x] **Multi-Hop Identity Resolution:** Identity graph resolving emails and aliases with conflict protection (`code.identity`).
- [x] **Evidence Extraction Engine:** Multi-format parser, dialect correlation, and temporal filtering (`code.evidence`).
- [x] **Statutory Policy Engine:** Rule matching and deletion intent classification (`code.policy`).
- [x] **Remediation Planner:** Deterministic step synthesis and dependency sorting (`code.planner`).
- [x] **Output & Validation:** Exact CSV schema and JSON step validator (`code.output`).
- [x] **CLI Interfaces:** Fully functional CLI entry points for pipeline execution and evaluation.
- [x] **Test Coverage:** 107 passing tests covering unit logic, integration flows, and edge cases.
