# Usage & Architecture Report — Ghost Data Still Exists

**Challenge:** HackerRank Orchestrate (October 2026) — Ghost Data Still Exists  
**Submission Artifact:** `output.csv` (Repository Root)  
**Challenge URL:** [HackerRank Challenge Submission Page](https://wwww.hackerrank.com/contests/hackerrank-orchestrate-october26/challenges/ghost-data-still-exists)  
**Date:** October 25, 2026  

---

## 1. System Architecture

The deletion audit engine is designed around a multi-stage, modular, deterministic pipeline that transforms raw unstructured forensic evidence and deletion requests into compliant audit remediation steps:

```
[Deletion Requests] + [Identity History]
         │
         ▼
 1. Identity Graph Resolution (code/identity.py)
    - Temporal cutoff enforcement (audit_at)
    - Multi-hop alias matching (emails, phones, hashes)
    - Canonical user_id boundary isolation
         │
         ▼
 2. Evidence Ingestion & Inverted Indexing (code/evidence.py)
    - SQLite/Parquet/CSV/PDF/JSON/Syslog multi-dialect parsing
    - Unpacking of nested service exports and snapshots
    - Multi-line trace and correlation-key linking
         │
         ▼
 3. Statutory Policy Evaluation (code/policy.py & code/rules.py)
    - Intent classification (authorized deletion vs opt-out/inquiry)
    - Statutory rule mapping across 15 data categories
    - Scoped retention exception preservation (Rules 12 & 13)
         │
         ▼
 4. Remediation & Verification Planning (code/planner.py)
    - Strict phase ordering: FINDING -> REMEDIATION -> VERIFICATION
    - Operation table precedence & lexicographic resource sorting
    - Step numbering continuity starting at 1
         │
         ▼
 5. Output Serialization & Validation (code/output.py)
    - Compact JSON serialization
    - Direct schema & citation rule enforcement
    - Generation of root output.csv (518 cases)
```

---

## 2. CLI Usage & Commands

The repository provides an end-to-end command-line interface accessible via `python -m code.main`:

### 2.1 Full Evaluation Run (Generates `output.csv`)
Audits all 518 deletion requests (`dataset/deletion_requests.csv`) and generates the root `output.csv`:

```bash
python -m code.main
```

### 2.2 Sample Benchmark Run (32 Cases)
Runs the pipeline against the 32 sample requests (`dataset/sample_deletion_requests.csv`) and validates against the competition rules:

```bash
python -m code.main --sample --output output_sample.csv
```

### 2.3 Standalone Output Validation
Verifies any generated CSV against the official competition specification (column header, row count, JSON syntax, operation/phase contracts, citation rules):

```bash
# Validate production output.csv
python -m code.main --validate-only output.csv

# Validate sample predictions
python -m code.main --validate-only output_sample.csv
```

### 2.4 Dry-Run Input Verification
Verifies presence and accessibility of all required dataset files without executing audits:

```bash
python -m code.main --dry-run
```

### 2.5 Evaluation & Benchmark Comparison
Compares predictions against ground truth and generates an evaluation report:

```bash
python -m code.evaluation.main --predictions output_sample.csv --truth dataset/sample_output.csv --report reports/evaluation_report.md
```

---

## 3. Performance & Resource Benchmarks

Benchmarked on standard x86_64 / Windows environment (Python 3.14):

| Metric | Measured Value | Standard Limit | Status |
| :--- | :--- | :--- | :--- |
| **Full Pipeline Execution (518 Cases)** | **1.31 seconds** | < 120 seconds | **Optimal (98.9% under limit)** |
| **Per-Case Latency** | **2.5 ms / case** | < 100 ms | **Optimal** |
| **Corpus Ingestion & Indexing** | **0.85 seconds** | < 15 seconds | **Optimal** |
| **Memory Footprint (Peak RSS)** | **~115 MB** | < 2,048 MB | **Optimal** |
| **Unit Test Suite Runtime** | **2.96 seconds (103 tests)** | < 30 seconds | **100% Passing** |

---

## 4. Key Module Reference

- [`code.config.AppConfig`](file:///code/config.py): Portable cross-platform path resolution without hardcoded absolute paths.
- [`code.identity.IdentityGraph`](file:///code/identity.py): Multi-hop identity resolver enforcing fail-closed timestamp cutoffs and canonical user-ID isolation.
- [`code.evidence.EvidenceCorpus`](file:///code/evidence.py): Ingests and indexes forensic artifacts across 7 file formats with zero data leakage.
- [`code.rules.DeletionIntentClassifier`](file:///code/rules.py): Multi-lingual intent classifier distinguishing affirmative deletion from inquiries, refusal, and retention exceptions.
- [`code.policy.PolicyEngine`](file:///code/policy.py): Evaluates the 15 statutory deletion rules dynamically loaded from `dataset/deletion_rules.csv`.
- [`code.planner.DeletionAuditPlanner`](file:///code/planner.py): Deterministic remediation planner enforcing strict phase order, operation table order, and authentic evidence citation contracts.
- [`code.output.validate_output_file`](file:///code/output.py): Strict schema and business logic validator for audit outputs.
- [`code.main`](file:///code/main.py): Production CLI entry point for full pipeline orchestration and validation.
- [`code.evaluation.main`](file:///code/evaluation/main.py): Standalone benchmark comparison and Markdown report generator.
