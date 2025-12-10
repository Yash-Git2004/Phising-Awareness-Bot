import email
import re
from email.policy import default
from urllib.parse import urlparse

import tldextract

IP_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

SUSPICIOUS_EXT = {'.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', '.jar', '.msi', '.ps1'}

PHISHING_KEYWORDS = [
    'urgent', 'verify', 'verify your account', 'update your account', 'password',
    'confirm', 'click here', 'account suspended', 'limited time', 'immediately',
    'login to', 'reset your password', 'bank', 'paypal', 'ssn', 'social security'
]


def extract_urls(text):
    # naive URL extractor
    url_regex = re.compile(r"(https?://[^\s'\"]+|www\.[^\s'\"]+)")
    return url_regex.findall(text or "")


def is_ip_url(url):
    try:
        parsed = urlparse(url if url.startswith('http') else 'http://' + url)
        host = parsed.hostname or ''
        return bool(IP_REGEX.search(host))
    except Exception:
        return False


def domain_from_url(url):
    try:
        parsed = urlparse(url if url.startswith('http') else 'http://' + url)
        host = parsed.hostname or ''
        ext = tldextract.extract(host)
        domain = ext.registered_domain
        return domain.lower() if domain else host.lower()
    except Exception:
        return ''


def extract_sender_from_headers(raw_email):
    try:
        msg = email.message_from_string(raw_email, policy=default)
        from_hdr = msg['From'] or ''
        reply_to = msg['Reply-To'] or ''
        return from_hdr, reply_to
    except Exception:
        return '', ''


def find_attachments(raw_email):
    try:
        msg = email.message_from_string(raw_email, policy=default)
        exts = []
        for part in msg.walk():
            if part.get_content_disposition() == 'attachment':
                fn = part.get_filename('') or ''
                for ext in SUSPICIOUS_EXT:
                    if fn.lower().endswith(ext):
                        exts.append(fn)
        return exts
    except Exception:
        return []