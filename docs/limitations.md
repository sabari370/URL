# Project Limitations

Every cybersecurity detection system operates under specific operational constraints. Acknowledging these boundaries is essential for academic rigor and realistic threat modeling.

### 1. Static Lexical Scope
PhishGuard AI analyzes the **textual and structural anatomy** of the URL string. It intentionally avoids executing HTTP requests against the destination. Consequently, it cannot evaluate:
- Live webpage HTML DOM structure or login form action endpoints.
- Client-side JavaScript obfuscation or dynamic payload delivery.
- Cloaking techniques that serve benign pages to automated scanners and phishing pages to human victims.

### 2. Demonstration Dataset Size
The project includes a 400-sample balanced dataset for development and viva demonstrations. While adequate for demonstrating the machine learning pipeline, robust production deployment requires retraining on comprehensive repositories containing hundreds of thousands of samples (e.g. the UCI PhiUSIIL repository).

### 3. Probabilistic Uncertainty
Machine learning classifiers output statistical probabilities rather than absolute deterministic truths. A score of 85 represents an elevated likelihood of phishing based on historical patterns, not a guaranteed security verdict. False positives and false negatives remain inherent in statistical modeling.

### 4. Absence of Live Threat Intelligence Feeds
The system currently does not query external commercial threat feeds (e.g. Google Safe Browsing, VirusTotal, APWG). It operates purely on localized heuristic and machine learning inference.

### 5. Adversarial Machine Learning Evasion
Sophisticated threat actors can employ adversarial perturbation—crafting URLs with standard lengths, typical subdomains, and zero suspicious keywords—to evade lexical classifiers while hosting credential harvesting portals.

### 6. Single-Protocol Focus
The system is intentionally restricted to `http://` and `https://` schemes. Non-web phishing vectors (e.g., telephone vishing, SMS smishing with deep-links to native apps) are outside the current architectural scope.
