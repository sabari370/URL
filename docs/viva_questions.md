# Viva Voce Examination Questions and Answers

This document prepares the student (**S. Sabari**) for the BCA Final-Year Project Viva Voce examination. It contains 37 detailed, academic, and practical questions covering cybersecurity, machine learning, software architecture, and implementation decisions.

---

### Q1: What is phishing?
**Answer:** Phishing is a form of social engineering where an attacker impersonates a trustworthy entity (such as a bank, email provider, or tech company) to deceive victims into revealing sensitive information like login credentials, credit card numbers, or personal identity details.

---

### Q2: What is URL phishing?
**Answer:** URL phishing is an attack where the adversary creates a fraudulent web address designed to mimic a legitimate service (e.g. `http://paypal-security-check.xyz/login`). When victims click the link, they are taken to a counterfeit website that captures their entered data.

---

### Q3: What is Machine Learning, and why is it useful in this project?
**Answer:** Machine Learning is a branch of Artificial Intelligence where algorithms learn patterns from data rather than relying solely on hardcoded rules. In this project, ML is useful because attackers constantly invent new phishing domains; a trained model can generalize patterns (such as length, delimiter distribution, and keyword presence) to recognize previously unseen phishing links.

---

### Q4: Why did you choose Random Forest instead of a single Decision Tree or Logistic Regression?
**Answer:** Random Forest is an ensemble method that builds multiple decision trees (100 in our implementation) using random subsets of data and features (bagging). It was chosen because:
1. It reduces overfitting and variance compared to a single decision tree.
2. It captures complex non-linear feature interactions (e.g., HTTPS present *plus* high entropy *plus* IP host).
3. It provides smooth, calibrated probabilities for risk scoring.

---

### Q5: What features did you extract from the URL?
**Answer:** We extracted 40 numerical features across four categories:
1. **Lexical metrics**: URL length, hostname length, path length, query length, fragment length.
2. **Character counts & delimiters**: Dots, hyphens, underscores, slashes, `@` symbols, digits, special characters.
3. **Topological properties**: Subdomain depth count, raw IP host indicator, suspicious port flag, high-risk TLD indicator, shortener detection, punycode flag.
4. **Information entropy**: Shannon entropy of URL and hostname to catch algorithmic random domains (DGA).

---

### Q6: How does the system detect whether an IP address is used as a hostname?
**Answer:** We parse the URL using Python’s `urllib.parse`, isolate the hostname, and evaluate it against IPv4 regular expressions (`^(\d{1,3}\.){3}\d{1,3}$`) and bracketed IPv6 notation. Legitimate web services almost always use domain names rather than raw IP addresses.

---

### Q7: What is Shannon entropy in URL analysis?
**Answer:** Shannon entropy measures the unpredictability or randomness of characters in a string:
\[
H = -\sum p_i \log_2 p_i
\]
Attackers frequently use Domain Generation Algorithms (DGAs) that create random strings like `xq78z9wkl2.xyz`. These strings have significantly higher entropy than typical human-readable domains like `wikipedia.org`.

---

### Q8: What is binary classification?
**Answer:** Binary classification is a supervised learning task where the target output has only two discrete categories. In our system, the classes are `0` for Benign (legitimate) and `1` for Phishing.

---

### Q9: What is the difference between Precision and Recall?
**Answer:**
- **Precision** is the ratio of true phishing URLs detected out of all URLs predicted as phishing: \(\frac{TP}{TP + FP}\). It measures how accurate the positive warnings are.
- **Recall** (Sensitivity) is the ratio of true phishing URLs detected out of all actual phishing URLs: \(\frac{TP}{TP + FN}\). It measures the model's ability to catch attacks without missing them.

---

### Q10: Which is more dangerous in phishing detection: a False Positive or a False Negative?
**Answer:** A **False Negative** is significantly more dangerous. A False Negative means a dangerous phishing URL is misclassified as safe, leading the user to enter their credentials and become compromised. A False Positive simply causes inconvenience by flagging a safe site for extra caution.

---

### Q11: What is the F1-score?
**Answer:** The F1-score is the harmonic mean of Precision and Recall:
\[
F1 = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}
\]
It provides a single balanced metric when evaluating performance, especially when class distributions or misclassification costs vary.

---

### Q12: What is a Confusion Matrix?
**Answer:** A confusion matrix is a table that summarizes the performance of a classification model by comparing actual labels against predicted labels:
- **True Positive (TP)**: Actual phishing correctly predicted as phishing.
- **True Negative (TN)**: Actual benign correctly predicted as benign.
- **False Positive (FP)**: Actual benign incorrectly predicted as phishing.
- **False Negative (FN)**: Actual phishing incorrectly predicted as benign.

---

### Q13: What is overfitting and how did you prevent it?
**Answer:** Overfitting occurs when a machine learning model memorizes training data noise and performs poorly on unseen data. We prevented overfitting by:
1. Using an ensemble Random Forest rather than an unconstrained single tree.
2. Limiting tree depth (`max_depth=15`).
3. Using an independent holdout test dataset (80/20 stratified split).
4. Relying on structural feature abstractions rather than raw memorized strings.

---

### Q14: What is stratified train-test splitting?
**Answer:** Stratified splitting ensures that both the training set and testing set have the exact same proportion of target classes as the original dataset (in our case, 50% benign and 50% phishing). This prevents distribution bias during model training and evaluation.

---

### Q15: What is feature scaling and why did you use StandardScaler?
**Answer:** Feature scaling transforms numerical variables onto a comparable scale. `StandardScaler` standardizes features by subtracting the mean and scaling to unit variance (\(z = \frac{x - \mu}{\sigma}\)). This ensures features with large numbers (like URL length: 150) do not dominate features with small binary values (like `has_ip_host`: 0 or 1).

---

### Q16: What is Joblib and why is it used?
**Answer:** Joblib is a Python library optimized for serializing and deserializing large NumPy arrays and Scikit-learn model pipelines to disk (`.pkl` files). It allows us to train the model once offline and load it into memory instantly during runtime without retraining.

---

### Q17: Why does the system state that "HTTPS does not guarantee safety"?
**Answer:** HTTPS (Hypertext Transfer Protocol Secure) indicates that the communication channel between the user's browser and the server is encrypted using SSL/TLS. However, it says **nothing** about the identity or honesty of the website owner. Today, automated certificate authorities (such as Let's Encrypt) grant free SSL certificates to any domain, meaning attackers can easily enable HTTPS on their phishing sites.

---

### Q18: What is Server-Side Request Forgery (SSRF) and how does your system prevent it?
**Answer:** SSRF is a critical vulnerability where an attacker tricks a web server into making unauthorized network requests to internal or external systems. PhishGuard AI prevents SSRF by **never making HTTP requests, socket connections, or DNS resolutions** to user-submitted URLs. The analysis is strictly non-invasive and lexical.

---

### Q19: What is QR phishing (Quishing)?
**Answer:** Quishing is phishing delivered via Quick Response (QR) barcodes. Attackers place malicious QR codes in emails, physical mail, or public stickers. Because humans cannot visually read the encoded URL inside a QR pattern, they are vulnerable to scanning it. Our system decodes the image, displays the raw URL for human inspection, and analyzes it safely.

---

### Q20: How does the QR scanner decode images without visiting the URL?
**Answer:** The server accepts an uploaded image file, validates its format and size (max 16MB), uses computer vision libraries (`pyzbar` or `OpenCV QRCodeDetector`) to extract the text string, and passes that string directly into our lexical analysis pipeline without opening a web browser or socket.

---

### Q21: Why did you use MongoDB instead of a relational database like MySQL?
**Answer:**
1. **Document Structure**: Inspection telemetry includes dynamic, nested JSON feature dictionaries which fit naturally into MongoDB's BSON format.
2. **Schema Flexibility**: As new features are added to the ML pipeline, documents can evolve without requiring rigid SQL table schema migrations (`ALTER TABLE`).
3. **High Write Performance**: Audit logs and scans can be inserted rapidly without transactional locking overhead.

---

### Q22: What indexes were created in MongoDB and why?
**Answer:**
1. `users.email` (Unique): Ensures no duplicate accounts and enables O(1) user lookups during login.
2. `scans.user_id` + `scans.scanned_at` (Compound): Optimizes queries for displaying a user's dashboard and paginated scan history.
3. `scans.scanned_at` (Descending): Enables fast retrieval of the most recent system-wide scans in the admin panel.

---

### Q23: Why did you choose Flask for the backend?
**Answer:** Flask is a lightweight, modular Python WSGI web framework. It provides flexibility through Blueprints, integrates natively with Python ML libraries (Scikit-learn, Pandas, NumPy), has minimal overhead, and makes the architecture clean and easy to explain during academic defense.

---

### Q24: What is a Flask Blueprint?
**Answer:** A Blueprint is a way to organize related routes and handlers into modular components in Flask. In PhishGuard AI, we separated the app into four Blueprints: `auth_bp` (login/register), `scan_bp` (URL & QR scanning + REST API), `dashboard_bp` (history & analytics), and `admin_bp` (system administration).

---

### Q25: How are user passwords stored securely?
**Answer:** Passwords are never stored in plain text. They are hashed using **bcrypt** with a salt work factor of 12. bcrypt is a slow, one-way cryptographic hash function designed to resist brute-force dictionary attacks and GPU cracking.

---

### Q26: How does the application calculate the Risk Score?
**Answer:** The Random Forest classifier outputs a probability of phishing \(P \in [0.0, 1.0]\). We multiply this probability by 100 and round to an integer:
\[
\text{Risk Score} = \text{round}(P \times 100)
\]
This produces an intuitive score from 0 (lowest risk) to 100 (highest risk).

---

### Q27: What are the risk score thresholds used in the project?
**Answer:**
- `0 – 29`: **Likely Safe** (Low risk, standard web structure)
- `30 – 59`: **Suspicious** (Caution advised, some anomalous features present)
- `60 – 100`: **Likely Phishing** (High risk, significant phishing characteristics detected)
These thresholds are centrally configured in `config.py`.

---

### Q28: What is Explainable AI (XAI) in your system?
**Answer:** Rather than simply returning a black-box label, our Explainable Risk Engine breaks down the specific feature values (e.g. URL length: 85 chars, 3 subdomains, direct IP addressing) and provides contextual descriptions explaining *why* those traits are associated with attacks and how users should protect themselves.

---

### Q29: What is an IDN Homograph / Punycode attack?
**Answer:** Internationalized Domain Names (IDNs) allow non-Latin characters in domain names. An attacker can register a domain using Cyrillic characters that look identical to Latin characters (e.g., Cyrillic 'а' vs Latin 'a'). In standard ASCII, these domains are represented using the `xn--` Punycode prefix. Our feature extractor detects the `xn--` prefix to flag potential homograph attacks.

---

### Q30: What is the purpose of the '@' symbol in phishing URLs?
**Answer:** In URL specifications (RFC 3986), characters before the `@` symbol are treated as user-info/credentials, and the browser navigates to the host *following* the `@`. Attackers use this to craft deceptive links like `http://www.google.com@evil-phishing-site.xyz/login`. The user sees "google.com" at the start, but the browser loads the phishing site.

---

### Q31: How does your system handle missing or offline ML models?
**Answer:** If the `.pkl` model file is not found, the system displays a clear, honest warning: *"ML model is not available. Please train the model using: python ml/train_model.py"*. It intentionally **never fabricates fake accuracy numbers or hardcoded predictions**.

---

### Q32: What is the REST API and what endpoints did you build?
**Answer:** A REST API allows external programs to interact with our service via HTTP requests exchanging JSON payloads. We built:
- `POST /api/analyze`: Takes a JSON body `{"url": "..."}` and returns the classification, score, and feature factors.
- `GET /api/health`: Reports server, database, and ML model availability status.
- `GET /api/history`: Returns the authenticated user's recent scan logs.

---

### Q33: How does the application prevent brute-force attacks and rate limit abuse?
**Answer:** We enforce input length limits (max 2048 chars for URLs, max 16MB for QR uploads), input sanitization, and session timeouts. For API endpoints, requests are rate-limited to 60 requests per minute per IP address.

---

### Q34: What are the main limitations of this system?
**Answer:**
1. **Lexical analysis only**: We do not fetch or inspect live webpage HTML or JavaScript.
2. **Sample dataset**: The included 400-sample dataset is for demonstration; production deployment requires retraining on larger datasets.
3. **Probabilistic output**: No machine learning classifier can guarantee 100% accuracy without false positives or negatives.

---

### Q35: How would you improve this project in the future?
**Answer:**
1. Build a browser extension for real-time protection while browsing.
2. Integrate external threat intelligence feeds like Google Safe Browsing.
3. Implement a sandboxed headless browser to capture screenshots and perform visual brand logo comparison.
4. Experiment with Deep Learning (character-level 1D-CNN or Bi-LSTM) on raw URL sequences.

---

### Q36: Did your system achieve 100% accuracy on the test set? Is 100% realistic in real-world phishing?
**Answer:** On our 400-sample balanced dataset, the model achieved 100% accuracy on the 80-sample holdout test set because the synthetic benign and phishing patterns were distinct. However, in real-world deployments with millions of adversarial URLs, accuracy typically ranges between 95% and 98% due to sophisticated attacker obfuscation and legitimate edge cases.

---

### Q37: What is the significance of the project disclaimer?
**Answer:** Cybersecurity applications must operate ethically and transparently. We include a prominent disclaimer stating that predictions are probabilistic assessments and not guaranteed security verdicts. This ensures users do not abandon common sense or defense-in-depth practices based solely on an automated score.
