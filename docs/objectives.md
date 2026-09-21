# Project Objectives

The primary objective of **PhishGuard AI** is to design, implement, and validate a secure, machine-learning-assisted web application for URL phishing detection and risk assessment.

### Specific Technical Objectives:

1. **Safe Input Processing & Validation**: Implement rigorous client-side and server-side URL normalization routines restricted strictly to `http` and `https` protocols, avoiding arbitrary schema execution.
2. **Lexical & Structural Feature Extraction**: Extract over 30 non-invasive numerical features from URL strings without initiating outbound network requests or DNS lookups.
3. **Machine Learning Model Engineering**: Train and evaluate an ensemble **Random Forest Classifier** with balanced class weighting, achieving high precision and recall on labeled datasets.
4. **Calibrated Risk Quantification**: Formulate a configurable scoring mechanism mapping model probabilities to a 0–100 risk scale categorized across three risk tiers (Likely Safe, Suspicious, Likely Phishing).
5. **Explainable Artificial Intelligence (XAI)**: Provide granular factor breakdowns detailing specific structural traits (e.g., token length, subdomain depth, keyword anomalies, port indicators) contributing to the risk calculation.
6. **QR Code Link Extraction**: Integrate computer vision decoding to extract and analyze embedded URLs from QR images prior to navigation, mitigating quishing attacks.
7. **Secure Data Persistence**: Utilize MongoDB for storing user accounts, scan audit trails, and model training metadata with indexed query optimization.
8. **Role-Based Access Control (RBAC)**: Implement secure session management with `bcrypt` password hashing, distinguishing standard analysts from system administrators.
9. **Interactive Telemetry Dashboard**: Build responsive visualizations using Chart.js to monitor 7-day scan trends and classification ratios.
10. **Public RESTful Web API**: Deliver programmatic JSON endpoints (`/api/analyze`, `/api/health`) with input validation and health status checks.
