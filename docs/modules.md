# System Modules Specification

The **PhishGuard AI** architecture is decoupled into distinct modules:

| Module | File Path | Primary Responsibilities |
| :--- | :--- | :--- |
| **App Entrypoint** | `app.py` | Flask factory (`create_app`), Blueprint registration, global context injection, error handling, server startup. |
| **Configuration** | `config.py` | Environment loading, risk threshold definitions, session security policies, upload boundaries. |
| **Validators** | `utils/validators.py` | Scheme whitelist enforcement (`http`/`https`), length limits, private network check, file extension filters. |
| **Logger** | `utils/logger.py` | Rotating file-based and console logging with formatted timestamps and log levels. |
| **Helpers** | `utils/helpers.py` | Text truncation, risk-to-badge mapping, classification color formatting, pagination math. |
| **Feature Extractor** | `ml/feature_extraction.py` | 40-dimensional non-invasive lexical, entropy, delimiter, structural, and keyword feature extraction. |
| **Training Pipeline** | `ml/train_model.py` | Dataset cleaning, train-test splitting, StandardScaler fitting, RandomForestClassifier training, model serialization. |
| **Model Evaluator** | `ml/evaluate_model.py` | Standalone evaluation generating accuracy, precision, recall, F1, and confusion matrix reports. |
| **Predictor Engine** | `ml/predict.py` | Lazy-loaded thread-safe inference engine converting raw URLs to probabilistic scores. |
| **URL Analyzer** | `services/url_analyzer.py` | Orchestration coordinator connecting validation, ML inference, and risk explainability. |
| **Risk Engine** | `services/risk_engine.py` | Translates numerical features into human-readable risk factors with defensive security context. |
| **QR Service** | `services/qr_service.py` | Computer vision image decoding for QR barcodes via pyzbar and OpenCV. |
| **Database Service** | `services/database_service.py` | PyMongo database connector, CRUD operations, aggregation pipelines, and index management. |
| **Auth Routes** | `routes/auth_routes.py` | User registration, login, logout, password hashing with bcrypt, session authorization guards. |
| **Scan Routes** | `routes/scan_routes.py` | Web scanner form handler, QR upload handler, and REST API endpoints (`/api/analyze`, `/api/health`). |
| **Dashboard Routes**| `routes/dashboard_routes.py`| User analytics dashboard, 7-day chart data builder, paginated scan history, and record deletion. |
| **Admin Routes** | `routes/admin_routes.py` | Administrative telemetry, global scan metrics, model file status, and user role management. |
