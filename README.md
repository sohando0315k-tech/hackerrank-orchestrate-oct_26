# Ghost Data Still Exists — AI-Powered Deletion Audit Agent

A production-grade AI audit agent designed for the **HackerRank Orchestrate (October 2026)** competitive engineering challenge.

---

## 1. Project Purpose

Following a catastrophic $2.4 million compliance breach where a supposedly "Complete" deletion request was resurrected in Northstar Shop's systems, this system audits customer deletion requests. It investigates participant-visible evidence across databases, replicas, search indices, logs, and backups to prove whether customer data was truly expunged, redacted, or anonymized, or whether ghost records and restore vulnerabilities persist.

---

## 2. Challenge Overview

For each case in `dataset/deletion_requests.csv`, the audit agent:
1. **Determines authorization:** Verifies whether `request_text` actually authorizes deletion or is `NOT_APPLICABLE` (e.g. access, rectification, marketing opt-out).
2. **Resolves identity:** Traces current and historical identifiers (emails, phones, hashes, internal `user_id`) using `user_identities.csv` and `user_audit_log.csv`.
3. **Inspects evidence:** Evaluates database snapshots, application logs, documents, and system activity up to `audit_at`.
4. **Applies policy:** Enforces the 15 statutory rules in `deletion_rules.csv`, accounting for tombstones and retention constraints.
5. **Generates ordered steps:**
   - **`COMPLETE`**: Evidence-backed verification checks proving current compliance.
   - **`INCOMPLETE`**: Concrete findings, ordered remediation steps, and post-remediation verification checks.
   - **`NOT_APPLICABLE`**: Empty JSON array (`[]`).
6. **Produces submission output:** Exactly 518 sorted rows in `output.csv`.

---

## 3. Prerequisites

- Python 3.10+ (tested on Python 3.14 on Windows 11)
- Git 2.40+
- Windows PowerShell (or macOS/Linux terminal)

---

## 4. Setup Instructions (Windows PowerShell)

Open PowerShell and navigate to the project directory:

```powershell
cd "c:\Users\prathamesh mitkari\Downloads\New folder (2)"
```

### 4.1 Virtual Environment Creation & Activation

Create and activate an isolated Python virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

*(If script execution is disabled, enable it for the current session via `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`)*

### 4.2 Dependency Installation

Install runtime and development dependencies:

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
```

---

## 5. How to Run the Program and Tests

### 5.1 CLI Orchestration

Display command-line options:

```powershell
python -m code.main --help
```

Verify inputs and configuration without executing an audit (Dry Run):

```powershell
python -m code.main --dry-run
```

Validate an output CSV against the official competition schema:

```powershell
python -m code.main --validate-only dataset\sample_output.csv
```

### 5.2 Evaluation CLI

Display evaluation options:

```powershell
python -m code.evaluation.main --help
```

Evaluate predictions against the official sample answers:

```powershell
python -m code.evaluation.main --predictions dataset\sample_output.csv --truth dataset\sample_output.csv --report reports\sample_evaluation.md
```

### 5.3 Running Unit Tests

Run the full pytest suite:

```powershell
python -m pytest -q
```

---

## 6. Expected Input and Output Paths

| Type | Path | Description |
| --- | --- | --- |
| **Input: Requests** | `dataset/deletion_requests.csv` | 518 full evaluation cases |
| **Input: Sample** | `dataset/sample_deletion_requests.csv` | 32 sample cases with known ground truth |
| **Input: Identities** | `dataset/user_identities.csv` | Current identity snapshot |
| **Input: Audit Log** | `dataset/user_audit_log.csv` | Historical identifier changes |
| **Input: Activity** | `dataset/system_activity.csv` | Global system events and claims |
| **Input: Rules** | `dataset/deletion_rules.csv` | 15 treatment rules for data categories |
| **Input: Evidence** | `dataset/evidence/` | Heterogeneous SQLite DBs, logs, JSONs, PDFs |
| **Output: Submission** | `output.csv` | Root-level CSV with 518 sorted cases |
| **Evaluation Report** | `code/evaluation/evaluation_report.md` | Required submission report |
| **Token Usage Report**| `code/evaluation/usage_report.md` | Required cost and token breakdown |

---

## 7. Current Implementation Status

- [x] **Project Foundation:** Git repository configured, clean architecture established.
- [x] **Configuration Layer:** Robust path resolution without hardcoded paths (`code.config`).
- [x] **Domain Models:** Strict enums for all 15 operations, states, and phases (`code.models`).
- [x] **Output & Validation:** Exact CSV schema and JSON step validator (`code.output`).
- [x] **CLI Interfaces:** Fully functional CLI entry points for execution and evaluation.
- [x] **Test Coverage:** Automated unit tests covering configuration, schema validation, and edge cases.
- [ ] **Agent Pipeline Implementation:** Identity resolution, evidence ingestion, rules execution, and step planning (scheduled for subsequent phases).

---

## 8. Planned Development Stages

1. **Stage 1 (Current): Foundation & Contracts** — Base models, schema validators, tests, and configuration.
2. **Stage 2: Multi-Hop Identity Resolution** — Resolving emails and historical aliases into canonical subject entities.
3. **Stage 3: Evidence Extraction Engine** — Parsing SQLite replicas, JSON snapshots, and application logs up to `audit_at`.
4. **Stage 4: Policy & Intent Classification** — Deterministic policy matching and deletion intent verification.
5. **Stage 5: Remediation Planner** — Step synthesis, dependency sorting, and verification checks.
6. **Stage 6: End-to-End Validation & Submission Packaging** — Generating final `output.csv`, `evaluation_report.md`, and `code.zip`.
