"""
PhishGuard AI - Risk Analysis and Explainability Engine
Deconstructs extracted URL features and explains contributing risk factors.
Provides actionable security recommendations without misrepresenting transport security.
"""

from typing import Any, Dict, List


def analyze_risk_factors(
    features: Dict[str, Any],
    risk_score: int
) -> List[Dict[str, Any]]:
    """
    Analyze extracted URL features and combine them with the ML risk score.

    IMPORTANT:
    The ML classification/risk score is NOT changed here.
    This function only improves explainability in the Feature Risk Breakdown.
    """

    factors = []

    # ---------------------------------------------------------
    # 1. URL Length
    # ---------------------------------------------------------
    url_len = features.get("url_length", 0)

    if url_len > 75:
        level = "HIGH"
        contribution = "high"
        description = (
            f"URL is unusually long ({url_len} chars). "
            "Phishing links often embed tokens, tracking parameters, "
            "or deceptive paths."
        )
    elif url_len > 54:
        level = "MEDIUM"
        contribution = "medium"
        description = (
            f"URL length ({url_len} chars) is moderately high "
            "compared to standard web addresses."
        )
    else:
        level = "LOW"
        contribution = "low"
        description = (
            "URL length is within normal, concise operational bounds."
        )

    factors.append({
        "factor": "URL Length",
        "value": f"{url_len} characters",
        "level": level,
        "risk_contribution": contribution,
        "description": description
    })

    # ---------------------------------------------------------
    # 2. Suspicious Keywords
    # ---------------------------------------------------------
    kw_count = features.get("suspicious_keyword_count", 0)

    if kw_count >= 2:
        level = "HIGH"
        contribution = "high"
        description = (
            f"Found {kw_count} security/account keywords "
            "(e.g. login, verify, secure, banking). "
            "Commonly used to impersonate authentication portals."
        )
    elif kw_count == 1:
        level = "MEDIUM"
        contribution = "medium"
        description = (
            "Detected a keyword commonly associated with "
            "authentication or account management."
        )
    else:
        level = "LOW"
        contribution = "low"
        description = (
            "No typical credential-harvesting or urgent account "
            "keywords found."
        )

    factors.append({
        "factor": "Suspicious Keywords",
        "value": f"{kw_count} detected" if kw_count else "None",
        "level": level,
        "risk_contribution": contribution,
        "description": description
    })

    # ---------------------------------------------------------
    # 3. Subdomain Depth
    # ---------------------------------------------------------
    subdomains = features.get("subdomain_count", 0)

    if subdomains >= 3:
        level = "HIGH"
        contribution = "high"
        description = (
            f"Excessive subdomain nesting ({subdomains} levels). "
            "Attackers can prepend trusted brand names as subdomains "
            "to deceive victims."
        )
    elif subdomains == 2:
        level = "MEDIUM"
        contribution = "medium"
        description = (
            "Multi-tier subdomain structure observed. "
            "Verify that the primary registered domain matches "
            "the expected service."
        )
    else:
        level = "LOW"
        contribution = "low"
        description = (
            "Standard single-domain or simple subdomain structure."
        )

    factors.append({
        "factor": "Subdomain Depth",
        "value": f"{subdomains} subdomains",
        "level": level,
        "risk_contribution": contribution,
        "description": description
    })

    # ---------------------------------------------------------
    # 4. IP Address Hostname
    # ---------------------------------------------------------
    has_ip = features.get("has_ip_host", 0)

    if has_ip:
        level = "HIGH"
        contribution = "high"
        description = (
            "URL connects directly to an IP address instead of "
            "a registered domain name. This can be a suspicious "
            "indicator for consumer-facing services."
        )
        value = "Direct IP used"
    else:
        level = "LOW"
        contribution = "low"
        description = "Hostname uses standard DNS domain registration."
        value = "Domain-based"

    factors.append({
        "factor": "Host IP Addressing",
        "value": value,
        "level": level,
        "risk_contribution": contribution,
        "description": description
    })

    # ---------------------------------------------------------
    # 5. HTTPS
    # ---------------------------------------------------------
    has_https = features.get("has_https", 0)

    if has_https:
        level = "LOW"
        contribution = "low"
        description = (
            "Connection uses SSL/TLS encryption. HTTPS protects "
            "data in transit but does NOT guarantee website legitimacy. "
            "Phishing sites can also use HTTPS."
        )
        value = "HTTPS Active"
    else:
        level = "MEDIUM"
        contribution = "medium"
        description = (
            "URL uses unencrypted HTTP. Data transmitted over "
            "this link may be vulnerable to interception."
        )
        value = "Plain HTTP"

    factors.append({
        "factor": "Transport Encryption (HTTPS)",
        "value": value,
        "level": level,
        "risk_contribution": contribution,
        "description": description
    })

    # ---------------------------------------------------------
    # 6. Special Characters
    # ---------------------------------------------------------
    special_chars = features.get("special_char_count", 0)
    has_at = features.get("at_symbol_count", 0)

    if has_at > 0:
        factors.append({
            "factor": "URL '@' Delimiter",
            "value": "Present",
            "level": "HIGH",
            "risk_contribution": "high",
            "description": (
                "The '@' symbol can obscure the actual destination "
                "host and is a known URL spoofing indicator."
            )
        })

    if special_chars > 4:
        level = "HIGH"
        contribution = "high"
        description = (
            f"High density of unusual characters ({special_chars}). "
            "This can indicate URL obfuscation."
        )
    elif special_chars >= 2:
        level = "MEDIUM"
        contribution = "medium"
        description = (
            "Moderate presence of special characters in URL structure."
        )
    else:
        level = "LOW"
        contribution = "low"
        description = (
            "Clean URL syntax with low special character density."
        )

    factors.append({
        "factor": "Special Characters",
        "value": f"{special_chars} characters",
        "level": level,
        "risk_contribution": contribution,
        "description": description
    })

    # ---------------------------------------------------------
    # 7. URL Shortener
    # ---------------------------------------------------------
    is_shortener = features.get("is_url_shortener", 0)

    if is_shortener:
        factors.append({
            "factor": "URL Shortener",
            "value": "Known Shortener",
            "level": "HIGH",
            "risk_contribution": "high",
            "description": (
                "URL utilizes a shortening service that can conceal "
                "the actual destination."
            )
        })

    # ---------------------------------------------------------
    # 8. Suspicious TLD
    # ---------------------------------------------------------
    has_suspicious_tld = features.get("has_suspicious_tld", 0)

    if has_suspicious_tld:
        factors.append({
            "factor": "Top-Level Domain (TLD)",
            "value": "High-Risk TLD",
            "level": "HIGH",
            "risk_contribution": "high",
            "description": (
                "The domain extension has characteristics associated "
                "with some disposable or abusive domains. "
                "TLD alone does not prove maliciousness."
            )
        })

    # ---------------------------------------------------------
    # 9. Non-standard Port
    # ---------------------------------------------------------
    has_susp_port = features.get("has_suspicious_port", 0)

    if has_susp_port:
        port_num = features.get("port", 0)

        factors.append({
            "factor": "Non-Standard Port",
            "value": f"Port {port_num}",
            "level": "HIGH",
            "risk_contribution": "high",
            "description": (
                f"URL targets a non-standard web service port ({port_num}) "
                "rather than standard ports 80/443."
            )
        })

    # ---------------------------------------------------------
    # 10. Punycode
    # ---------------------------------------------------------
    has_punycode = features.get("has_punycode", 0)

    if has_punycode:
        factors.append({
            "factor": "Punycode Encoding",
            "value": "xn-- Detected",
            "level": "HIGH",
            "risk_contribution": "high",
            "description": (
                "Punycode representation detected. Internationalized "
                "domain names can be used in homograph-style attacks."
            )
        })

    # ---------------------------------------------------------
    # 11. ML Risk Assessment
    #
    # This is the IMPORTANT FIX.
    #
    # It does not modify the ML score.
    # It simply makes the Feature Risk Breakdown explain
    # why the overall result can be Suspicious/Phishing even
    # when individual lexical features look normal.
    # ---------------------------------------------------------
    if risk_score >= 60:
        ml_level = "HIGH"
        ml_contribution = "high"
        ml_description = (
            f"The machine-learning model calculated an overall "
            f"phishing risk of {risk_score}/100. Multiple learned "
            "URL patterns indicate elevated phishing probability."
        )
    elif risk_score >= 30:
        ml_level = "MEDIUM"
        ml_contribution = "medium"
        ml_description = (
            f"The machine-learning model calculated an overall "
            f"phishing risk of {risk_score}/100. The URL has enough "
            "learned patterns to require additional verification."
        )
    else:
        ml_level = "LOW"
        ml_contribution = "low"
        ml_description = (
            f"The machine-learning model calculated an overall "
            f"phishing risk of {risk_score}/100. No strong learned "
            "phishing pattern was detected."
        )

    factors.append({
        "factor": "ML Risk Assessment",
        "value": f"{risk_score}/100",
        "level": ml_level,
        "risk_contribution": ml_contribution,
        "description": ml_description
    })

    return factors


def get_risk_summary(
    factors: List[Dict[str, Any]]
) -> Dict[str, int]:
    """
    Summarizes factor levels by count.
    """
    summary = {
        "high": 0,
        "medium": 0,
        "low": 0
    }

    for factor in factors:
        level = factor.get("level", "LOW").lower()

        if level in summary:
            summary[level] += 1

    return summary


def get_recommendation(classification: str) -> str:
    """
    Provides defensive guidance based on final classification.
    """

    if classification == "Likely Phishing":
        return (
            "CRITICAL WARNING: This URL exhibits significant indicators "
            "associated with phishing campaigns. Do NOT click this link, "
            "enter login credentials, submit personal information, or "
            "authorize payments. If you received this link via email or "
            "message, delete it and report it to your organization's "
            "IT security team."
        )

    elif classification == "Suspicious":
        return (
            "CAUTION ADVISED: This URL contains atypical structural "
            "patterns or potential risk factors. Verify the authenticity "
            "of the sender independently through a trusted, alternative "
            "channel. Do not input passwords or financial information "
            "on unverified domains."
        )

    else:
        return (
            "ASSESSED AS LIKELY SAFE: Lexical and structural indicators "
            "align with standard legitimate web services. However, "
            "always remain vigilant: verify that the domain name matches "
            "your intended destination and ensure HTTPS is active."
        )