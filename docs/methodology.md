# System Methodology

The engineering methodology of **PhishGuard AI** is structured into five iterative phases:

```text
[ Data Preparation ] ──> [ Feature Engineering ] ──> [ Model Training & Evaluation ]
                                                                   │
[ Web Application & API ] <── [ Explainability & Risk Engine ] <───┘
```

---

## 1. Data Collection and Curation
The system operates on balanced collections of legitimate (benign) and fraudulent (phishing) web addresses:
- **Benign Samples**: High-reputation public services, documentation portals, and educational domains (e.g. Wikipedia, Python Docs, GitHub).
- **Phishing Samples**: Synthesized and real-world phishing patterns containing direct IP addressing, excessive subdomain depth, homograph typosquatting, credential-harvesting keywords, and suspicious top-level domains.
- Data cleaning enforces duplicate removal, null handling, and binary label normalization (`0` = benign, `1` = phishing).

## 2. Feature Engineering Pipeline
The feature extraction module inspects the anatomy of the URL string across four distinct domains:
- **Lexical Dimensions**: Overall URL length, hostname length, path segment length, query parameter count, and token counts.
- **Character Frequencies**: Occurrences of delimiters (`.`, `-`, `_`, `/`, `?`, `=`, `&`, `@`, `!`, `~`, `%`, `#`), digit counts, and letter-to-digit ratios.
- **Topological & Structural Properties**: Subdomain depth count, double-slash delimiters, raw IP address detection, non-standard network ports, and high-risk TLD identification.
- **Information Entropy**: Shannon entropy calculation across the full URL and hostname to identify random algorithmic string generation (DGA).

## 3. Supervised Machine Learning
- **Algorithm**: Ensemble **Random Forest Classifier** composed of 100 decision trees.
- **Feature Scaling**: Numerical vectors are standardized using `StandardScaler` to normalize disparate feature ranges.
- **Validation**: Stratified train/test splitting (80% training, 20% holdout test) to preserve exact class balance across partitions.
- **Persistence**: Trained models and transformers are serialized to `.pkl` artifacts using `joblib`.

## 4. Risk Engine and Explainability
- Predicted class probabilities (`P(phishing)`) are scaled onto an integer range of `0 – 100`.
- Risk thresholds categorize results:
  - `0 – 29`: **Likely Safe**
  - `30 – 59`: **Suspicious**
  - `60 – 100`: **Likely Phishing**
- An explainability engine evaluates individual feature thresholds and outputs structured, human-readable risk factors explaining why specific characteristics triggered alerts.

## 5. Web Platform and API Integration
- Flask application factory registers modular Blueprints (`auth`, `scan`, `dashboard`, `admin`).
- MongoDB collections persist audit logs, user credentials, and model metadata.
- REST endpoints allow automated systems to ingest analysis results programmatically.
