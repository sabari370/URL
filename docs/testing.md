# Testing and Quality Assurance

PhishGuard AI includes an automated test suite implemented with **Pytest**. The tests validate all core functional units, boundary conditions, input sanitization routines, and API endpoints **without requiring active network connections or MongoDB instances**.

---

## 1. Test Suite Structure

The test suite is located under the `tests/` directory:

```text
tests/
├── __init__.py
├── test_url_analyzer.py      # URL parsing, RFC compliance, and feature extraction
├── test_risk_engine.py       # Explainability factors and recommendation logic
└── test_api.py               # REST API HTTP status codes and contract tests
```

---

## 2. Test Cases Overview

### A. URL Validation & Feature Extraction (`test_url_analyzer.py`)
- `test_valid_https_url`: Verifies standard HTTPS addresses parse cleanly.
- `test_valid_http_url`: Verifies standard HTTP addresses are permitted.
- `test_empty_url` & `test_whitespace_only_url`: Rejects blank or whitespace-only inputs.
- `test_missing_scheme_auto_prepends_http`: Auto-corrects domain inputs lacking a protocol.
- `test_unsupported_scheme_ftp` & `test_unsupported_scheme_file`: Correctly blocks non-web schemes (`ftp://`, `file:///`).
- `test_url_length_exceeded`: Enforces the 2048-character maximum length limit.
- `test_ip_based_url_accepted_for_analysis`: Permits raw IP addresses for inspection without executing them.
- `test_localhost` & `test_127_loopback`: Validates private network range detection.
- `test_allowed_extensions`: Ensures only whitelisted image formats (`.png`, `.jpg`, `.jpeg`) can be submitted for QR decoding.
- `test_extract_features_keys`: Asserts that all 40 numerical features are present in the extraction output.
- `test_https_flag`, `test_ip_host_detection`, `test_suspicious_keyword_counter`, `test_subdomain_depth_count`, `test_at_symbol_detection`, `test_shortener_detection`, `test_punycode_detection`: Validates accurate detection of individual threat indicators.

### B. Risk Engine & Explainability (`test_risk_engine.py`)
- `test_factor_structure`: Verifies factor dictionary schemas (`factor`, `value`, `level`, `risk_contribution`, `description`).
- `test_https_disclaimer_present`: Ensures the HTTPS factor clearly articulates that transport encryption does not prove legitimacy.
- `test_risk_summary_counts`: Validates aggregation math across high, medium, and low factor tiers.
- `test_recommendation_copy`: Checks appropriate guidance text for all three classification levels.

### C. REST API Integration (`test_api.py`)
- `test_health_check`: Asserts `GET /api/health` returns HTTP 200 with service health telemetry.
- `test_analyze_valid_url`: Asserts `POST /api/analyze` accepts valid JSON and outputs complete risk reports.
- `test_analyze_missing_url`: Asserts `POST /api/analyze` returns HTTP 400 when the URL parameter is omitted.
- `test_analyze_non_json_request`: Asserts HTTP 400 when invalid content types are posted.
- `test_api_history_unauthorized_without_session`: Asserts HTTP 401 unauthorized protection for protected endpoints.

---

## 3. Running the Test Suite

Execute the following command in PowerShell:

```powershell
pytest tests/ -v
```

### Result:
```text
tests/test_api.py::TestAPIEndpoints::test_health_check PASSED            [  3%]
tests/test_api.py::TestAPIEndpoints::test_analyze_valid_url PASSED       [  6%]
...
tests/test_url_analyzer.py::TestFeatureExtraction::test_features_to_vector_ordering PASSED [100%]

============================= 32 passed in 3.47s ==============================
```
