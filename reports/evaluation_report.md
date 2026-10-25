# Evaluation Report — Ghost Data Still Exists

## Summary Metrics

- **Total Cases Evaluated:** 32
- **Status Accuracy:** 100.00% (32/32)
- **Exact Case Match Accuracy:** 18.75% (6/32)
- **Expected Total Steps:** 193
- **Predicted Total Steps:** 168

## Field-Level Accuracy

| Field | Correct Matches | Total Expected | Accuracy |
| --- | --- | --- | --- |
| `phase` | 141 | 193 | 73.06% |
| `system_id` | 99 | 193 | 51.30% |
| `resource_id` | 102 | 193 | 52.85% |
| `operation` | 97 | 193 | 50.26% |
| `state` | 103 | 193 | 53.37% |
| `evidence_id` | 149 | 193 | 77.20% |

## Discrepancies and Findings

- Case 'case_03': step count mismatch. Expected 3, got 2.
- Case 'case_04': step count mismatch. Expected 2, got 1.
- Case 'case_07': step count mismatch. Expected 4, got 7.
- Case 'case_08': step count mismatch. Expected 4, got 5.
- Case 'case_09': step count mismatch. Expected 5, got 6.
- Case 'case_11': step count mismatch. Expected 14, got 12.
- Case 'case_15': step count mismatch. Expected 5, got 4.
- Case 'case_16': step count mismatch. Expected 7, got 4.
- Case 'case_17': step count mismatch. Expected 5, got 9.
- Case 'case_18': step count mismatch. Expected 14, got 12.
- Case 'case_19': step count mismatch. Expected 8, got 7.
- Case 'case_20': step count mismatch. Expected 8, got 6.
- Case 'case_21': step count mismatch. Expected 3, got 1.
- Case 'case_22': step count mismatch. Expected 8, got 4.
- Case 'case_23': step count mismatch. Expected 8, got 6.
- Case 'case_24': step count mismatch. Expected 7, got 6.
- Case 'case_25': step count mismatch. Expected 3, got 1.
- Case 'case_26': step count mismatch. Expected 6, got 5.
- Case 'case_27': step count mismatch. Expected 6, got 5.
- Case 'case_28': step count mismatch. Expected 6, got 4.
- Case 'case_29': step count mismatch. Expected 14, got 12.
- Case 'case_30': step count mismatch. Expected 14, got 12.
- Case 'case_31': step count mismatch. Expected 3, got 2.
- Case 'case_32': step count mismatch. Expected 5, got 4.