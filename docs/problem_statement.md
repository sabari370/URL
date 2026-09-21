# Problem Statement

Phishing attacks have evolved from rudimentary email spam into highly sophisticated, multi-channel social engineering operations. Attackers routinely register disposable lookalike domains, leverage free automated SSL/TLS certificates, embed deceptive hyperlinks in mobile messaging apps, and encode malicious addresses into physical Quick Response (QR) barcodes (quishing).

Traditional signature-based and reputation-based security tools suffer from key vulnerabilities:

1. **Detection Latency**: Static blocklists take hours or days to register newly spawned phishing domains, leaving a window of exposure during which most attacks succeed.
2. **Superficial Trust Cues**: Modern browsers emphasize the presence of HTTPS (the "padlock" icon). Non-technical users conflate encryption in transit with domain legitimacy, unaware that over 80% of phishing sites employ valid TLS certificates.
3. **Black-Box Confusion**: Existing security warnings rarely explain why a link is dangerous, failing to educate users or enable informed risk assessment.
4. **Physical Attack Vectors**: QR codes obfuscate the destination address entirely until rendered by a device camera, depriving users of the ability to inspect the link beforehand.
5. **Server Safety Risks**: Online analysis tools that automatically crawl or visit user-submitted URLs risk introducing Server-Side Request Forgery (SSRF), malware infection, or credential leakage on the analysis host.

There is a distinct requirement for an accessible, transparent, and secure analysis platform that can statically inspect URL structures, classify them with trained machine learning algorithms, articulate specific risk factors, and operate in complete isolation from the destination servers.
