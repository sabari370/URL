"""
Comprehensive Verification Script for PhishGuard AI
Tests all routes, forms, auth sessions, QR processing, and error handlers.
"""
import io
import os
import sys
import qrcode
from PIL import Image

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app import create_app


def run_full_verification():
    app = create_app()
    app.config["TESTING"] = True
    client = app.test_client()

    print("\n" + "="*60)
    print("PHISHGUARD AI - FULL ROUTE & ENDPOINT VERIFICATION SUITE")
    print("="*60)

    results = []

    def check(name, condition, details=""):
        status = "PASS" if condition else "FAIL"
        results.append((name, status, details))
        print(f"[{status}] {name} {('- ' + details) if details else ''}")
        return condition

    # 1. Landing Page
    resp = client.get("/")
    check("GET / (Homepage)", resp.status_code == 200 and b"PhishGuard" in resp.data)

    # 2. Scanner Page
    resp = client.get("/scan")
    check("GET /scan (Scanner Form)", resp.status_code == 200 and b"URL Security Scanner" in resp.data)

    # 3. Scan POST (Safe URL)
    resp = client.post("/scan", data={"url": "https://www.google.com"}, follow_redirects=True)
    check("POST /scan (Benign URL)", resp.status_code == 200 and b"Likely Safe" in resp.data)

    # 4. Scan POST (Phishing URL)
    resp = client.post("/scan", data={"url": "http://paypal-security-update.account-verify.xyz/login.php?urgent=true"}, follow_redirects=True)
    check("POST /scan (Phishing URL)", resp.status_code == 200 and b"Likely Phishing" in resp.data)

    # 5. Scan POST (Invalid URL)
    resp = client.post("/scan", data={"url": "ftp://files.evil.com/malware.exe"}, follow_redirects=True)
    check("POST /scan (Unsupported Scheme)", resp.status_code == 200 and b"Unsupported scheme" in resp.data)

    # 6. GET /result
    resp = client.get("/result")
    check("GET /result", resp.status_code == 200 and b"Security Analysis Report" in resp.data)

    # 7. QR Scanner Page
    resp = client.get("/qr-scan")
    check("GET /qr-scan", resp.status_code == 200 and b"QR Code (Quishing) Scanner" in resp.data)

    # 8. QR Upload and Scan with real QR code
    qr_img = qrcode.make("https://en.wikipedia.org/wiki/Computer_security")
    img_byte_arr = io.BytesIO()
    qr_img.save(img_byte_arr, format="PNG")
    img_byte_arr.seek(0)

    resp = client.post(
        "/qr-scan",
        data={"qr_image": (img_byte_arr, "test_qr.png")},
        content_type="multipart/form-data",
        follow_redirects=True
    )
    check("POST /qr-scan (Valid QR Image)", resp.status_code == 200 and b"Security Analysis Report" in resp.data)

    # 9. Security Tips Page
    resp = client.get("/security-tips")
    check("GET /security-tips", resp.status_code == 200 and b"Essential Phishing Prevention Guidelines" in resp.data)

    # 10. Authentication Flow: Register
    import uuid
    test_email = f"analyst_{uuid.uuid4().hex[:6]}@test.com"
    resp = client.post(
        "/auth/register",
        data={
            "name": "Security Analyst",
            "email": test_email,
            "password": "Password123!",
            "confirm_password": "Password123!"
        },
        follow_redirects=True
    )
    check("POST /auth/register", resp.status_code == 200 and (b"Registration successful" in resp.data or b"Sign in" in resp.data))

    # 11. Authentication Flow: Login
    resp = client.post(
        "/auth/login",
        data={
            "email": test_email,
            "password": "Password123!"
        },
        follow_redirects=True
    )
    check("POST /auth/login", resp.status_code == 200 and b"Security Analytics Dashboard" in resp.data)

    # 12. Authenticated Dashboard
    resp = client.get("/dashboard")
    check("GET /dashboard (Authenticated)", resp.status_code == 200 and b"Total URLs Scanned" in resp.data)

    # 13. Perform scan while authenticated to verify history saving
    resp = client.post("/scan", data={"url": "https://www.python.org/downloads"}, follow_redirects=True)
    check("POST /scan (Authenticated Save)", resp.status_code == 200 and b"Security Analysis Report" in resp.data)

    # 14. Scan History Page
    resp = client.get("/history")
    check("GET /history (Authenticated)", resp.status_code == 200 and b"Inspection History" in resp.data)

    # 15. REST API: GET /api/health
    resp = client.get("/api/health")
    health_json = resp.get_json() or {}
    check("GET /api/health", resp.status_code == 200 and health_json.get("status") in ["healthy", "degraded"])

    # 16. REST API: POST /api/analyze
    resp = client.post(
        "/api/analyze",
        json={"url": "https://www.github.com"}
    )
    analyze_json = resp.get_json() or {}
    check("POST /api/analyze (API JSON)", resp.status_code == 200 and analyze_json.get("success") is True)

    # 17. REST API: GET /api/history (Authenticated in session)
    resp = client.get("/api/history")
    history_json = resp.get_json() or {}
    check("GET /api/history (API Session)", resp.status_code == 200 and "scans" in history_json)

    # 18. Custom 404 Error Page
    resp = client.get("/this-route-does-not-exist-at-all")
    check("GET /404 (Custom Error Page)", resp.status_code == 404 and b"Page Not Found" in resp.data)

    # 19. Logout
    resp = client.get("/auth/logout", follow_redirects=True)
    check("GET /auth/logout", resp.status_code == 200 and b"Detect Suspicious URLs" in resp.data)

    # 20. Protected route redirection after logout
    resp = client.get("/dashboard", follow_redirects=False)
    check("GET /dashboard (Unauthenticated Redirect)", resp.status_code == 302 and "/auth/login" in resp.headers.get("Location", ""))

    print("="*60)
    failed = [r for r in results if r[1] == "FAIL"]
    if not failed:
        print("ALL 20 VERIFICATION CHECKS PASSED PERFECTLY!")
    else:
        print(f"FAILURES DETECTED: {len(failed)}")
        for f in failed:
            print(f" - {f[0]}: {f[2]}")
    print("="*60 + "\n")
    return len(failed) == 0


if __name__ == "__main__":
    success = run_full_verification()
    sys.exit(0 if success else 1)
