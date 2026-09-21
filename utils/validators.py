"""
PhishGuard AI - URL Validators
Validates and normalizes user-submitted URLs safely.
IMPORTANT: This module never makes HTTP requests to submitted URLs.
"""
from urllib.parse import urlparse, urlunparse
from typing import Tuple, Optional
import re

# Only allow these schemes
ALLOWED_SCHEMES = {'http', 'https'}

# Maximum URL length to process
MAX_URL_LENGTH = 2048

# Private/loopback IP ranges that should not be analyzed as external URLs
_PRIVATE_IP_PATTERNS = re.compile(
    r'^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|0\.0\.0\.0|localhost|::1)'
)


def validate_url(url: str) -> Tuple[bool, str, Optional[str]]:
    """
    Validate a URL submitted by the user.

    Returns:
        (is_valid, error_message, normalized_url)
        - is_valid: True if the URL can be analyzed
        - error_message: human-readable error if invalid, else empty string
        - normalized_url: cleaned URL string if valid, else None
    """
    if not url or not url.strip():
        return False, 'URL cannot be empty.', None

    url = url.strip()

    if len(url) > MAX_URL_LENGTH:
        return False, f'URL is too long (max {MAX_URL_LENGTH} characters).', None

    # Check for existing scheme
    scheme_match = re.match(r'^([a-zA-Z][a-zA-Z0-9+.-]*)://', url)
    if scheme_match:
        found_scheme = scheme_match.group(1).lower()
        if found_scheme not in ALLOWED_SCHEMES:
            return False, f'Unsupported scheme "{found_scheme}". Only http and https are supported.', None
    else:
        # Prepend default scheme if missing
        url = 'http://' + url

    try:
        parsed = urlparse(url)
    except Exception:
        return False, 'URL could not be parsed. Please check the format.', None

    # Check scheme
    if parsed.scheme not in ALLOWED_SCHEMES:
        return False, f'Unsupported scheme "{parsed.scheme}". Only http and https are supported.', None

    # Must have a hostname
    if not parsed.netloc or not parsed.hostname:
        return False, 'URL must have a valid hostname.', None

    # Basic hostname character validation
    hostname = parsed.hostname
    if not re.match(r'^[a-zA-Z0-9._\-\[\]:]+$', hostname):
        return False, 'URL contains an invalid hostname.', None

    # Reconstruct normalized URL
    normalized = urlunparse(parsed)

    return True, '', normalized


def is_private_address(hostname: str) -> bool:
    """Check if hostname resolves to a private/loopback address pattern."""
    return bool(_PRIVATE_IP_PATTERNS.match(hostname.lower()))


def allowed_file(filename: str, allowed_extensions: set) -> bool:
    """Check if an uploaded filename has an allowed extension."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in allowed_extensions
