"""
PhishGuard AI - URL Feature Extraction
Extracts safe, non-invasive features from URL strings for ML classification.
IMPORTANT: This module never makes HTTP requests to submitted URLs.
All features are derived purely from lexical/structural URL analysis.
"""
from urllib.parse import urlparse, parse_qs, unquote
from typing import Dict, Any, List
import re
import math


# Known URL shortener domains
URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'short.link',
    'is.gd', 'buff.ly', 'ht.ly', 'tiny.cc', 'su.pr', 'twit.ac',
    'shorturl.at', 'rb.gy', 'cutt.ly', 'snip.ly', 'bl.ink'
}

# Common two-part country-code top-level domains
TWO_PART_TLDS = {
    '.co.uk', '.co.in', '.com.au', '.co.nz', '.co.za', '.com.br',
    '.co.jp', '.org.uk', '.gov.in', '.edu.in', '.ac.in', '.ac.uk',
    '.net.in', '.org.in', '.gov.uk', '.com.sg', '.com.mx'
}

# Action and credential harvesting keywords commonly observed in phishing URLs
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'sign-in', 'account', 'update', 'confirm',
    'verify', 'secure', 'banking', 'support', 'helpdesk',
    'password', 'credential', 'suspend', 'unusual', 'activity',
    'limited', 'access', 'click', 'free', 'winner', 'prize',
    'urgent', 'immediately', 'validate', 'restore', 'billing', 'invoice'
]

# Frequently targeted brand names for impersonation detection
BRAND_TARGETS = [
    'paypal', 'amazon', 'apple', 'google', 'microsoft', 'facebook',
    'instagram', 'netflix', 'ebay', 'wellsfargo', 'chase', 'bankofamerica'
]

# Common high-risk TLDs correlated with abusive campaigns
SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work',
    '.click', '.link', '.download', '.stream', '.gdn', '.icu'
}


def extract_features(url: str) -> Dict[str, Any]:
    """
    Extract ML features from a URL string.

    Args:
        url: The URL string to analyze (must be pre-validated).

    Returns:
        A dictionary of feature name -> numeric value.
        All values are numeric (int or float) for ML compatibility.
    """
    features: Dict[str, Any] = {}

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ''
        path = parsed.path or ''
        query = parsed.query or ''
        fragment = parsed.fragment or ''
        netloc = parsed.netloc or ''
    except Exception:
        return _empty_features()

    url_lower = url.lower()

    # === Lexical / Length Features ===
    features['url_length'] = len(url)
    features['hostname_length'] = len(hostname)
    features['path_length'] = len(path)
    features['query_length'] = len(query)
    features['fragment_length'] = len(fragment)

    # === Character Count Features ===
    features['dot_count'] = url.count('.')
    features['hyphen_count'] = url.count('-')
    features['underscore_count'] = url.count('_')
    features['slash_count'] = url.count('/')
    features['question_mark_count'] = url.count('?')
    features['equal_count'] = url.count('=')
    features['ampersand_count'] = url.count('&')
    features['at_symbol_count'] = url.count('@')
    features['exclamation_count'] = url.count('!')
    features['tilde_count'] = url.count('~')
    features['percent_count'] = url.count('%')
    features['hash_count'] = url.count('#')
    features['digit_count'] = sum(c.isdigit() for c in url)
    features['letter_count'] = sum(c.isalpha() for c in url)

    # Special char count (non-alphanumeric, non-standard URL chars)
    special_chars = re.findall(r'[^a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]', url)
    features['special_char_count'] = len(special_chars)

    # === URL Structure Features ===
    # Check for two-part country code TLDs (e.g. .co.uk, .co.in)
    has_two_part_tld = any(hostname.lower().endswith(t) for t in TWO_PART_TLDS)
    tld_offset = 2 if has_two_part_tld else 1

    hostname_parts = hostname.split('.') if hostname else []
    features['hostname_dot_count'] = len(hostname_parts) - 1 if hostname_parts else 0
    # Subdomain count = parts minus 1 (domain) minus TLD parts
    features['subdomain_count'] = max(0, len(hostname_parts) - 1 - tld_offset)

    # Registered base domain for brand-spoofing verification
    registered_domain = hostname_parts[-(tld_offset + 1)] if len(hostname_parts) > tld_offset else hostname

    # Path segments
    path_segments = [p for p in path.split('/') if p]
    features['path_segment_count'] = len(path_segments)

    # Query parameters
    try:
        params = parse_qs(query)
        features['query_param_count'] = len(params)
    except Exception:
        features['query_param_count'] = 0

    # Double slash occurrences after scheme
    after_scheme = url[url.find('//') + 2:] if '//' in url else url
    features['double_slash_count'] = after_scheme.count('//')

    # === Encoding Features ===
    features['has_percent_encoding'] = 1 if '%' in url else 0
    features['percent_encoded_char_count'] = len(re.findall(r'%[0-9A-Fa-f]{2}', url))

    # === Security Indicator Features ===
    features['has_https'] = 1 if parsed.scheme == 'https' else 0

    # Suspicious port
    suspicious_ports = {8080, 8443, 9090, 3000, 4444, 1337, 31337, 666}
    port = parsed.port
    features['has_suspicious_port'] = 1 if port and port in suspicious_ports else 0
    features['port'] = port if port else 0

    # === IP Address Host ===
    features['has_ip_host'] = 1 if _is_ip_address(hostname) else 0

    # === Domain/Host Features ===
    # TLD
    tld = '.' + hostname_parts[-1] if len(hostname_parts) >= 2 else ''
    features['has_suspicious_tld'] = 1 if tld in SUSPICIOUS_TLDS else 0

    # Punycode (internationalized domain name used in homograph attacks)
    features['has_punycode'] = 1 if 'xn--' in hostname.lower() else 0

    # URL shortener
    base_domain = '.'.join(hostname_parts[-2:]) if len(hostname_parts) >= 2 else hostname
    features['is_url_shortener'] = 1 if base_domain.lower() in URL_SHORTENERS else 0

    # === Keyword & Brand Spoofing Features ===
    action_kw_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)
    # Brand spoofing: brand name present in URL, but NOT the registered domain
    brand_spoof_count = sum(1 for brand in BRAND_TARGETS if brand in url_lower and brand != registered_domain.lower())
    features['suspicious_keyword_count'] = action_kw_count + brand_spoof_count

    # === Entropy ===
    features['url_entropy'] = _calculate_entropy(url)
    features['hostname_entropy'] = _calculate_entropy(hostname)

    # === Ratio Features ===
    total_chars = len(url) if url else 1
    features['digit_ratio'] = features['digit_count'] / total_chars
    features['letter_ratio'] = features['letter_count'] / total_chars

    # === Longest Token ===
    tokens = re.split(r'[/\-._?=&]', url)
    features['longest_token_length'] = max((len(t) for t in tokens if t), default=0)

    return features


def get_feature_names() -> List[str]:
    """Return the ordered list of feature names used by the ML model."""
    # Extract from a dummy URL to get consistent ordering
    dummy = extract_features('http://example.com')
    return list(dummy.keys())


def features_to_vector(features: Dict[str, Any], feature_names: List[str]) -> List[float]:
    """Convert a feature dict to an ordered numeric vector for ML inference."""
    return [float(features.get(name, 0)) for name in feature_names]


def _is_ip_address(hostname: str) -> bool:
    """Check if hostname is an IPv4 or IPv6 address."""
    # IPv4
    ipv4_pattern = re.compile(
        r'^(\d{1,3}\.){3}\d{1,3}$'
    )
    if ipv4_pattern.match(hostname):
        parts = hostname.split('.')
        if all(0 <= int(p) <= 255 for p in parts):
            return True
    # IPv6 (bracketed)
    if hostname.startswith('[') and hostname.endswith(']'):
        return True
    return False


def _calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    entropy = -sum((count / n) * math.log2(count / n) for count in freq.values())
    return round(entropy, 4)


def _empty_features() -> Dict[str, Any]:
    """Return a zero-valued feature dict when parsing fails."""
    return {name: 0 for name in get_feature_names()}
