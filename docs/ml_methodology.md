# Machine Learning Methodology

## 1. Problem Formulation
URL phishing detection is modeled as a **binary classification problem**. Given an arbitrary input URL string \( u \), a feature extraction function \( \phi(u) \) maps the string into a \( d \)-dimensional real-valued feature vector:

\[
\mathbf{x} = \phi(u) \in \mathbb{R}^{d}, \quad \text{where } d = 40
\]

A supervised classification algorithm estimates the posterior probability of the URL belonging to the phishing class:

\[
P(Y = 1 \mid \mathbf{x}) \in [0, 1]
\]

where \( Y = 0 \) denotes a **benign** link and \( Y = 1 \) denotes a **phishing** link.

---

## 2. Feature Taxonomy

The feature extraction module derives 40 numerical properties grouped into four domains:

### A. Lexical & Length Metrics
- `url_length`, `hostname_length`, `path_length`, `query_length`, `fragment_length`, `longest_token_length`
- Longer URLs and hostnames correlate with token embedding and brand obfuscation.

### B. Character Distributions & Delimiters
- `dot_count`, `hyphen_count`, `underscore_count`, `slash_count`, `question_mark_count`, `equal_count`, `ampersand_count`, `at_symbol_count`, `exclamation_count`, `tilde_count`, `percent_count`, `hash_count`, `digit_count`, `letter_count`, `special_char_count`
- Ratios: `digit_ratio`, `letter_ratio`

### C. Structural & Topological Anomalies
- `subdomain_count`: Nested subdomains often mimic trusted domains (e.g. `login.paypal.evil.com`).
- `has_ip_host`: Binary indicator flagging direct IP addressing (e.g. `http://192.168.1.1/login`).
- `has_https`: Binary indicator for TLS encryption (interpreted responsibly).
- `has_suspicious_port`: Detection of non-standard web ports (e.g., 8080, 8443, 9090, 4444).
- `has_suspicious_tld`: Detection of high-risk top-level domains (.tk, .ml, .ga, .xyz, etc.).
- `has_punycode`: Detection of `xn--` prefixes indicative of IDN homograph spoofing.
- `is_url_shortener`: Identifies popular shorteners (bit.ly, tinyurl) that obscure destination paths.

### D. Information Theory & Heuristics
- `url_entropy`, `hostname_entropy`: Shannon entropy \( H = -\sum p_i \log_2 p_i \) identifies algorithmically generated pseudorandom domain names (DGA).
- `suspicious_keyword_count`: Frequency of credential and account-related keywords (`login`, `verify`, `banking`, `secure`, `update`).

---

## 3. Algorithm Selection: Random Forest

**Random Forest** was selected as the primary baseline classifier over single decision trees and logistic regression for several reasons:

1. **Non-Linear Interactions**: Phishing URLs combine multiple subtle characteristics (e.g., HTTPS present *plus* high entropy *plus* @ symbol). Random Forest captures high-order non-linear interactions across diverse lexical features.
2. **Robustness to Overfitting**: By aggregating 100 independently bootstrapped decision trees with random feature sub-sampling (bagging), variance is substantially reduced compared to individual decision trees.
3. **Handle Imbalanced/Mixed Scales**: Tree-based splits are scale-invariant, although feature standardization (`StandardScaler`) is applied to stabilize numerical convergence.
4. **Calibrated Probabilistic Output**: The fraction of trees voting for the phishing class yields a smooth probability estimation \( P \in [0, 1] \), enabling continuous 0–100 risk scoring.

---

## 4. Training Pipeline & Evaluation

```text
CSV Dataset ──> Data Cleaning ──> Feature Extraction ──> Stratified Split (80/20)
                                                                 │
Models Serialized <── Evaluation Metrics <── Model Training <── StandardScaler
```

- **Stratified Split**: Preserves the exact 50:50 class proportion in both training (320 samples) and testing (80 samples) sets.
- **Evaluation Metrics**:
  - **Accuracy**: Overall fraction of correct predictions: \( \frac{TP + TN}{TP + TN + FP + FN} \)
  - **Precision**: Fraction of predicted phishing links that are genuinely phishing: \( \frac{TP}{TP + FP} \) (minimizes false alarms)
  - **Recall**: Fraction of actual phishing attacks correctly caught: \( \frac{TP}{TP + FN} \) (minimizes missed attacks)
  - **F1-Score**: Harmonic mean balancing precision and recall: \( 2 \times \frac{Precision \times Recall}{Precision + Recall} \)
  - **Confusion Matrix**: Quantitative breakdown of True Negatives, False Positives, False Negatives, and True Positives.
