# System Architecture

## Architecture Diagram

```text
+-----------------------------------------------------------------------------+
|                               PRESENTATION LAYER                            |
|  - HTML5 / CSS3 / Dark Theme                                                |
|  - Bootstrap 5.3 Responsive Grid                                            |
|  - Chart.js Telemetry (Activity & Ratio Visualizations)                     |
|  - Client-side Form Validation & File Preview (main.js / qr.js)             |
+-----------------------------------------------------------------------------+
                                       ▲
                                       │ HTTP / JSON
                                       ▼
+-----------------------------------------------------------------------------+
|                          APPLICATION CONTROLLER LAYER                       |
|                          Flask Web Framework (Python)                       |
|                                                                             |
|  +--------------------+  +--------------------+  +-----------------------+  |
|  |   auth_routes.py   |  |   scan_routes.py   |  |  dashboard_routes.py  |  |
|  | (Register / Login) |  | (URL & QR Scanner) |  |  (History / Charts)   |  |
|  +--------------------+  +--------------------+  +-----------------------+  |
|                                  +-------------------+                      |
|                                  |  admin_routes.py  |                      |
|                                  | (Role Management) |                      |
|                                  +-------------------+                      |
+-----------------------------------------------------------------------------+
                                       │
                +----------------------+----------------------+
                │                                             │
                ▼                                             ▼
+-------------------------------+             +-------------------------------+
|      BUSINESS SERVICE LAYER   |             |     MACHINE LEARNING LAYER    |
|                               |             |                               |
|  - url_analyzer.py            |             |  - feature_extraction.py      |
|    (Orchestration pipeline)   |             |    (40-dim Lexical Extractor) |
|  - qr_service.py              |             |  - predict.py                 |
|    (Pillow / OpenCV Decoder)  |             |    (Random Forest Inference)  |
|  - risk_engine.py             |             |  - feature_scaler.pkl         |
|    (Explainability & Advisory)|             |    (StandardScaler)           |
+-------------------------------+             +-------------------------------+
                │                                             ▲
                ▼                                             │
+-------------------------------------------------------------+---------------+
|                               PERSISTENCE LAYER                             |
|                           MongoDB Document Database                         |
|                                                                             |
|  - Collection 'users'          : User credentials, roles, timestamps        |
|  - Collection 'scans'          : Scan history, extracted features, scores   |
|  - Collection 'model_metadata' : Accuracy, training dates, confusion matrix|
+-----------------------------------------------------------------------------+
```

---

## Architectural Layers

### 1. Presentation Layer
- Modern, accessible dark-themed cybersecurity interface.
- Asynchronous form submissions with loading spinners and drag-and-drop file upload.
- Dynamic responsive charts powered by Chart.js.

### 2. Controller & Routing Layer
- Modular Blueprints partition concerns cleanly across authentication, scanning, dashboard telemetry, and administrative management.
- Central error handlers intercept 400, 401, 403, 404, and 500 exceptions, displaying user-friendly guidance without disclosing server stack traces.

### 3. Business Service Layer
- **`url_analyzer`**: Orchestrates validation, feature extraction, ML inference, and risk factor breakdown.
- **`qr_service`**: Isolates barcode decoding; verifies image bounds and prevents auto-navigation.
- **`risk_engine`**: Decouples probabilistic classification from human-readable explainability factors and contextual advice.

### 4. Machine Learning Layer
- Pure Python extraction engine mapping URL text to numerical tensors.
- Serialized Scikit-learn Random Forest model operating with standard scaling.

### 5. Persistence Layer
- Document-oriented MongoDB storage with indexed query execution.
- Graceful degradation mode: if database is unreachable, the scanner and ML engine continue to function in standalone mode.
