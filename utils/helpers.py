"""
PhishGuard AI - Helper Utilities
General-purpose helper functions.
"""
from datetime import datetime
from typing import Any, Dict, Optional


def format_datetime(dt: datetime, fmt: str = '%Y-%m-%d %H:%M:%S') -> str:
    """Format a datetime object to string."""
    if dt is None:
        return 'N/A'
    return dt.strftime(fmt)


def truncate_url(url: str, max_length: int = 60) -> str:
    """Truncate long URLs for display."""
    if len(url) <= max_length:
        return url
    return url[:max_length - 3] + '...'


def risk_level_to_badge(risk_score: int) -> Dict[str, str]:
    """Return Bootstrap badge class and label for a given risk score."""
    if risk_score < 30:
        return {'class': 'badge-safe', 'label': 'Likely Safe', 'icon': 'shield-check'}
    elif risk_score < 60:
        return {'class': 'badge-suspicious', 'label': 'Suspicious', 'icon': 'exclamation-triangle'}
    else:
        return {'class': 'badge-danger', 'label': 'Likely Phishing', 'icon': 'x-circle'}


def classification_to_color(classification: str) -> str:
    """Return CSS color class for a classification string."""
    mapping = {
        'Likely Safe': 'text-success',
        'Suspicious': 'text-warning',
        'Likely Phishing': 'text-danger',
    }
    return mapping.get(classification, 'text-secondary')


def paginate_list(items: list, page: int, per_page: int = 20) -> Dict[str, Any]:
    """Paginate a list and return page data with metadata."""
    total = len(items)
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = max(1, min(page, total_pages))
    start = (page - 1) * per_page
    end = start + per_page
    return {
        'items': items[start:end],
        'page': page,
        'per_page': per_page,
        'total': total,
        'total_pages': total_pages,
        'has_prev': page > 1,
        'has_next': page < total_pages,
    }


def safe_int(value: Any, default: int = 0) -> int:
    """Safely convert a value to int."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
