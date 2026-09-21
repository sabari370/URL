# Project Abstract

**Project Title:** AI-Based URL Phishing Detection and Risk Analysis System  
**System Name:** PhishGuard AI  
**Author:** S. Sabari, BCA Student  

---

## Abstract

Phishing remains one of the most persistent and damaging vectors in modern cybercrime, exploiting human trust to harvest sensitive credentials, financial accounts, and personal data. Traditional defense mechanisms rely heavily on static blocklists and reputation feeds, which struggle to detect zero-day phishing campaigns and disposable deceptive domains. 

This project, **PhishGuard AI**, develops a full-stack, machine-learning-driven web application designed to evaluate suspicious web links in real time through comprehensive lexical, structural, and topological URL feature analysis. By extracting over 30 safe, non-invasive indicators—including URL length, subdomain depth, raw IP addressing, character entropy, and keyword densities—an ensemble **Random Forest Classifier** assesses the probabilistic risk of the target link.

The system translates model outputs into an intuitive **Risk Score (0–100)** and categorizes links into **Likely Safe**, **Suspicious**, or **Likely Phishing**. An integrated explainability engine breaks down the contributing factors, providing transparent reasoning for the verdict and practical cybersecurity recommendations. Additionally, the platform supports **QR code (Quishing) scanning**, **user authentication**, **audit history**, and an **analytics dashboard** backed by **MongoDB**. 

Operating under a strict non-invasive architecture, the system never makes HTTP requests to user-submitted links, preventing Server-Side Request Forgery (SSRF) and ensuring safe demonstrations during academic evaluations.
