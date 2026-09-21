"""
PhishGuard AI - QR Code Decoding Service
Decodes QR code images to extract embedded URLs.
Security Notice: Decoded URLs are analyzed strictly lexically;
the system NEVER visits, fetches, or renders the destination.
"""
import logging
import os
import re
from typing import Any, Dict
from PIL import Image

logger = logging.getLogger("phishguard.qr")


def is_probable_url(text: str) -> bool:
    """Checks whether the decoded string has URL structure."""
    if not text:
        return False
    text = text.strip()
    if text.startswith(("http://", "https://")):
        return True
    # Domain pattern check (e.g. example.com/path)
    domain_match = re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$", text)
    return bool(domain_match)


def decode_qr_from_image(image_path: str) -> Dict[str, Any]:
    """
    Decodes a QR code from an image file.
    Tries pyzbar first, then OpenCV QRCodeDetector.

    Args:
        image_path: Filesystem path to the uploaded image.

    Returns:
        Dict with status, decoded text, and whether the payload is a URL.
    """
    if not os.path.isfile(image_path):
        return {
            "success": False,
            "error": "Image file does not exist on disk."
        }

    # Verify file size <= 16MB
    if os.path.getsize(image_path) > 16 * 1024 * 1024:
        return {
            "success": False,
            "error": "Image file exceeds maximum limit of 16MB."
        }

    # Verify image integrity via Pillow
    try:
        with Image.open(image_path) as img:
            img.verify()
    except Exception as e:
        logger.warning(f"Corrupt or invalid image file: {e}")
        return {
            "success": False,
            "error": "Uploaded file is not a valid image or is corrupted."
        }

    decoded_text = None

    # Method 1: pyzbar
    try:
        from pyzbar.pyzbar import decode as pyzbar_decode
        with Image.open(image_path) as pil_img:
            results = pyzbar_decode(pil_img)
            if results:
                decoded_text = results[0].data.decode("utf-8", errors="ignore").strip()
                logger.info(f"QR decoded successfully via pyzbar: {decoded_text[:60]}")
    except Exception as e:
        logger.debug(f"pyzbar decoding skipped or failed: {e}")

    # Method 2: OpenCV QRCodeDetector
    if not decoded_text:
        try:
            import cv2
            img_cv = cv2.imread(image_path)
            if img_cv is not None:
                detector = cv2.QRCodeDetector()
                data, bbox, _ = detector.detectAndDecode(img_cv)
                if data:
                    decoded_text = data.strip()
                    logger.info(f"QR decoded successfully via OpenCV: {decoded_text[:60]}")
        except Exception as e:
            logger.debug(f"OpenCV QR decoding skipped or failed: {e}")

    if not decoded_text:
        return {
            "success": False,
            "error": "No valid QR code could be detected in the uploaded image. Please ensure the QR code is clearly visible, well-lit, and unblurred."
        }

    return {
        "success": True,
        "decoded_data": decoded_text,
        "is_url": is_probable_url(decoded_text)
    }
