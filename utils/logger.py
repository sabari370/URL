"""
PhishGuard AI - Application Logger
Configures structured logging for the application.
"""
import logging
import os
from logging.handlers import RotatingFileHandler
from typing import Optional


def setup_logger(name: str, log_file: str = 'logs/phishguard.log',
                 level: int = logging.DEBUG) -> logging.Logger:
    """Create and configure a logger with console and file handlers."""
    # Create logs directory if it doesn't exist
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    logger = logging.getLogger(name)
    logger.setLevel(level)

    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s [%(name)s:%(lineno)d] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)

    # File handler (5MB max, 5 backups)
    file_handler = RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=5)
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger


# Module-level logger
app_logger = setup_logger('phishguard')
