# Database Design

PhishGuard AI employs **MongoDB**, a flexible, high-performance document-oriented NoSQL database. MongoDB's JSON-like document structure (BSON) naturally accommodates nested feature matrices and variable telemetry payloads without requiring schema migrations or complex multi-table relational joins.

---

## Collections Specification

### 1. Collection: `users`
Stores user identities, credentials, and access roles.

| Field | Type | Description | Constraints |
| :--- | :--- | :--- | :--- |
| `_id` | ObjectId | Unique document identifier | Primary Key (Indexed) |
| `name` | String | Full name of the user | Required, Min 2 chars |
| `email` | String | Email address (login identifier)| Required, Unique Index, Lowercase |
| `password_hash` | String | Encrypted password string | Required, bcrypt salt cost 12 |
| `role` | String | Authorization role (`user` or `admin`)| Default: `'user'` |
| `created_at` | DateTime | Timestamp of registration | Default: UTC Now |

#### Example Document:
```json
{
  "_id": {"$oid": "664a7812bc8f42019a12e401"},
  "name": "S. Sabari",
  "email": "sabari@example.com",
  "password_hash": "$2b$12$e8xYz9A7KlM4N...encrypted",
  "role": "admin",
  "created_at": {"$date": "2024-05-19T10:15:30.000Z"}
}
```

---

### 2. Collection: `scans`
Maintains immutable audit records of all URL and QR inspections.

| Field | Type | Description | Constraints |
| :--- | :--- | :--- | :--- |
| `_id` | ObjectId | Unique scan identifier | Primary Key |
| `user_id` | String | Reference to user `_id` | Optional (null if guest/API), Indexed |
| `url` | String | Target URL string analyzed | Required, Indexed |
| `classification`| String | Final verdict (`Likely Safe`, `Suspicious`, `Likely Phishing`)| Required |
| `risk_score` | Integer | Risk score (`0 – 100`) | Required |
| `probability` | Double | Model phishing probability (`0.0 – 1.0`)| Required |
| `features` | Object | Full key-value dictionary of extracted features | Required |
| `scanned_at` | DateTime | Timestamp of scan execution | Required, Descending Index |

#### Example Document:
```json
{
  "_id": {"$oid": "664a7890bc8f42019a12e402"},
  "user_id": "664a7812bc8f42019a12e401",
  "url": "http://paypal-security-update.account-verify.xyz/login.php",
  "classification": "Likely Phishing",
  "risk_score": 92,
  "probability": 0.9241,
  "features": {
    "url_length": 58,
    "has_ip_host": 0,
    "subdomain_count": 2,
    "has_https": 0,
    "suspicious_keyword_count": 3,
    "has_suspicious_tld": 1
  },
  "scanned_at": {"$date": "2024-05-19T10:18:22.000Z"}
}
```

---

### 3. Collection: `model_metadata`
Maintains records of model training sessions, holdout evaluation metrics, and feature lists.

| Field | Type | Description | Constraints |
| :--- | :--- | :--- | :--- |
| `_id` | ObjectId | Unique metadata identifier | Primary Key |
| `model_name` | String | ML algorithm name | e.g. "Random Forest Classifier" |
| `version` | String | Pipeline version | e.g. "1.0.0" |
| `training_date` | String | Timestamp of training run | Formatted string |
| `dataset_file` | String | Filename of training data | e.g. "sample_dataset.csv" |
| `total_samples` | Integer | Total dataset rows | e.g. 400 |
| `train_samples` | Integer | Training set size | e.g. 320 |
| `test_samples` | Integer | Test set size | e.g. 80 |
| `feature_count` | Integer | Total extracted features | e.g. 40 |
| `feature_names` | Array[String]| Ordered list of feature names | For vector alignment |
| `metrics` | Object | Accuracy, precision, recall, F1, and confusion matrix | Key metrics |
| `recorded_at` | DateTime | Database persistence timestamp | UTC Now |

---

## Indexing Strategy

1. **`users.email`** (`ASCENDING`, `unique=True`): Enforces unique user registrations and ensures O(1) login lookups.
2. **`scans.user_id` + `scans.scanned_at`** (`Compound Index`): Optimizes user dashboard queries, paginated history browsing, and date-range filters.
3. **`scans.scanned_at`** (`DESCENDING`): Accelerates recent system-wide scans retrieval in the admin panel.
