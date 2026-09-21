"""
Generates a realistic, balanced sample dataset of 400 URLs (200 benign, 200 phishing)
for development, local testing, and offline training.
"""
import csv
import os

BENIGN_DOMAINS = [
    "google.com", "github.com", "wikipedia.org", "python.org", "microsoft.com",
    "stackoverflow.com", "apple.com", "amazon.com", "mozilla.org", "apache.org",
    "ubuntu.com", "debian.org", "docker.com", "flask.palletsprojects.com", "numpy.org",
    "pandas.pydata.org", "scikit-learn.org", "w3schools.com", "khanacademy.org", "coursera.org",
    "mit.edu", "stanford.edu", "harvard.edu", "cern.ch", "nasa.gov",
    "nih.gov", "bbc.com", "reuters.com", "theguardian.com", "nytimes.com",
    "medium.com", "dev.to", "gitlab.com", "bitbucket.org", "digitalocean.com",
    "cloudflare.com", "atlassian.com", "slack.com", "zoom.us", "spotify.com"
]

BENIGN_PATHS = [
    "", "/", "/about", "/docs", "/documentation", "/faq", "/contact", "/search?q=machine+learning",
    "/wiki/Computer_science", "/help/article/1049", "/news/2024/05/tech-trends", "/explore",
    "/courses/computer-science", "/research/papers/view?id=4921", "/pricing", "/features",
    "/blog/engineering-insights", "/downloads/releases/stable", "/terms", "/privacy"
]

PHISHING_PATTERNS = [
    # IP-based hostnames
    "http://192.168.1.105/login/verification/account.php",
    "http://10.0.0.45/secure/update/billing-confirm.html",
    "http://172.16.0.88/signin/security/auth.asp",
    "http://192.168.0.12/paypal/verify_account/index.htm",
    "http://192.168.10.15/appleid/auth/signin",
    "http://192.168.1.1:8080/admin/session/login.php",
    "http://10.1.1.250:9090/secure/bank/transfer",
    "http://172.20.10.5/chase/online-banking/verify",
    "http://192.168.100.55/wells-fargo/login/credentials",
    "http://10.0.1.99/google-docs/share/document-login",
    
    # URL Shorteners with phishing keywords
    "https://bit.ly/3xVerifyAccountSecurity2024",
    "http://tinyurl.com/paypal-account-urgent-restore",
    "https://t.co/secure-login-appleid-verify99",
    "http://is.gd/chase-bank-alert-update-account",
    "https://cutt.ly/netflix-suspend-subscription-pay",
    "http://shorturl.at/amaz0n-prime-renewal-billing",
    "https://rb.gy/microsoft365-urgent-password-reset",
    "http://tiny.cc/bankofamerica-auth-confirm",
    "https://bl.ink/secure-doc-dropbox-sign-in",
    "http://buff.ly/ebay-account-suspended-verify",

    # Homograph and Typosquatting domains
    "http://www.g00gle.com.account-security.tk/verify",
    "http://paypa1-security-center.com.xyz/login",
    "http://amaz0n-orders-support.service-update.ga/auth",
    "http://m1crosoft-office365-verify.ml/login.php",
    "http://app1e-id-support.cloud-storage.gq/restore",
    "http://faceb00k-security-team.top/checkpoint",
    "http://netfl1x-billing-update.work/renew",
    "http://chase-bank-sec-login.account-confirm.cf/signin",
    "http://wellsfarg0-online-access.click/auth",
    "http://dropb0x-secure-share.download/view",

    # Excessive subdomains & brand spoofing
    "http://paypal.com.account.verification.urgent.security-notice.tk/auth",
    "http://secure.login.apple.com.id.customer-service.ml/login",
    "http://accounts.google.com.signin.security-challenge.ga/verify",
    "http://signin.ebay.com.update.creditcard.billing.gq/login",
    "http://auth.microsoft.com.password.reset.support-desk.top/action",
    "http://secure.bankofamerica.com.online.banking.access.xyz/signin",
    "http://portal.office.com.enterprise.mail.session.work/owa",
    "http://login.yahoo.com.mail.inbox.access-denied.click/auth",
    "http://update.netflix.com.payment.card-expired.stream/account",
    "http://verify.instagram.com.badge.verification.help.icu/confirm",

    # Sensitive keywords in query params & suspicious chars
    "http://account-verification-service.top/login.php?user=urgent&auth=token&redirect=https://legit.com",
    "http://client-billing-restore.xyz/update?session=92830192830192&token=sec992&status=suspended",
    "http://secure-gateway-auth.work/verify?action=restore&account=unusual_activity&pin=required",
    "http://mail-storage-quota.club/owa/auth.aspx?email=user%40company.com&action=upgrade",
    "http://identity-management-portal.biz/confirm.php?ref=security_alert&urgent=true",
    "http://user-credential-validation.link/auth?step=2&verify_phone=true&code=required",
    "http://e-banking-auth-center.xyz/secure/pin?challenge=sms&acc=primary",
    "http://helpdesk-it-support-ticket.info/resolve?ticket_id=8921&login=ldap",
    "http://cloud-file-share-notice.top/download.php?file=invoice_urgent.pdf&auth=required",
    "http://payment-processing-issue.cc/invoice/pay?inv=99281&amount=499.00&confirm=card",

    # URLs with '@' symbol technique
    "http://www.google.com@phishing-harvest-server.xyz/login.html",
    "http://support.apple.com@credential-trap-service.top/signin",
    "http://service.paypal.com@verify-identity-billing.ml/webapps/mpp",
    "http://microsoft.com@cloud-auth-verification.ga/office365",
    "http://chase.com@secure-banking-restore.cf/session/login"
]

def generate_dataset():
    data = []
    
    # Generate 200 benign URLs
    benign_count = 0
    for domain in BENIGN_DOMAINS:
        for path in BENIGN_PATHS:
            scheme = "https://" if benign_count % 3 != 0 else "http://"
            url = f"{scheme}www.{domain}{path}"
            data.append((url, 0))
            benign_count += 1
            if benign_count >= 200:
                break
        if benign_count >= 200:
            break

    # Generate 200 phishing URLs
    phishing_urls = list(PHISHING_PATTERNS)
    # Expand programmatically to reach exactly 200 phishing patterns
    counter = 1
    tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".click", ".stream", ".icu", ".download"]
    keywords = ["login", "verify", "secure", "update", "account", "banking", "billing", "confirm", "suspend", "unlock"]
    brands = ["paypal", "apple", "google", "amazon", "chase", "wells-fargo", "netflix", "microsoft", "instagram"]
    
    while len(phishing_urls) < 200:
        brand = brands[counter % len(brands)]
        kw1 = keywords[counter % len(keywords)]
        kw2 = keywords[(counter + 3) % len(keywords)]
        tld = tlds[counter % len(tlds)]
        
        pattern_type = counter % 4
        if pattern_type == 0:
            url = f"http://{brand}-{kw1}-{kw2}-notice{counter}{tld}/auth/login.php?client={counter}"
        elif pattern_type == 1:
            url = f"http://secure.{kw1}.{brand}.account-check{counter}{tld}/webapps/verify?token={counter}99182"
        elif pattern_type == 2:
            url = f"http://192.168.{counter % 250}.{(counter * 7) % 250}:8080/{brand}/account/{kw1}.html"
        else:
            url = f"http://{brand}.com.{kw1}.portal-secure{counter}{tld}/session/auth/{kw2}"
        
        phishing_urls.append(url)
        counter += 1

    for p_url in phishing_urls[:200]:
        data.append((p_url, 1))

    output_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dataset", "sample_dataset.csv")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label"])
        for row in data:
            writer.writerow(row)

    print(f"Generated {len(data)} rows in {output_path} (Benign: 200, Phishing: 200)")

if __name__ == "__main__":
    generate_dataset()
