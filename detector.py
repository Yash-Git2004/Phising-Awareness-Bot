from utils import (
    extract_urls, is_ip_url, domain_from_url, PHISHING_KEYWORDS,
    extract_sender_from_headers, find_attachments
)
import re


class PhishDetector:
    def __init__(self):
        # Weights for different indicators
        self.weights = {
            'suspicious_url': 30,
            'ip_url': 20,
            'http_not_https': 10,
            'multiple_links': 8,
            'urgent_language': 15,
            'suspicious_attachment': 25,
            'sender_mismatch': 25,
            'bad_tld': 12,
        }

    def analyze(self, raw_email_text):
        # returns {score: int, max_score:int, breakdown: list of (name, score, explanation)}
        breakdown = []
        total = 0
        max_possible = sum(self.weights.values())

        # Extract sender
        from_hdr, reply_to = extract_sender_from_headers(raw_email_text)

        # Extract body (naive: entire text)
        body = raw_email_text

        # URLs
        urls = extract_urls(body)

        # Indicator: suspicious URL patterns (e.g., domain with many dashes, weird tlds)
        suspicious_urls = []
        bad_tld_count = 0
        for u in urls:
            dom = domain_from_url(u)
            if dom and (dom.count('-') >= 2 or len(dom.split('.')) > 3):
                suspicious_urls.append(u)
            # simple check for odd tlds: very long suffix
            if dom and any(len(p) > 10 for p in dom.split('.')):
                bad_tld_count += 1

        if suspicious_urls:
            val = self.weights['suspicious_url']
            breakdown.append(('suspicious_url', val, f'URLs with suspicious patterns: {suspicious_urls}'))
            total += val

        # Indicator: IP-based URLs
        ip_urls = [u for u in urls if is_ip_url(u)]
        if ip_urls:
            val = self.weights['ip_url']
            breakdown.append(('ip_url', val, f'URLs using raw IP addresses: {ip_urls}'))
            total += val

        # Indicator: http (not https) links
        http_only = [u for u in urls if u.startswith('http://')]
        if http_only:
            val = self.weights['http_not_https']
            breakdown.append(('http_not_https', val, f'Non-HTTPS links found: {http_only}'))
            total += val

        # Indicator: multiple links (phishy mass redirects)
        if len(urls) >= 3:
            val = self.weights['multiple_links']
            breakdown.append(('multiple_links', val, f'Email contains {len(urls)} links'))
            total += val

        # Indicator: urgent language / phishing keywords
        body_lower = body.lower()
        hits = [kw for kw in PHISHING_KEYWORDS if kw in body_lower]
        if hits:
            # scale by number of matches
            val = min(self.weights['urgent_language'], int(len(hits) * 3))
            breakdown.append(('urgent_language', val, f'Phishing keywords found: {hits}'))
            total += val

        # Indicator: suspicious attachments
        atts = find_attachments(raw_email_text)
        if atts:
            val = self.weights['suspicious_attachment']
            breakdown.append(('suspicious_attachment', val, f'Suspicious attachments: {atts}'))
            total += val

        # Indicator: sender mismatch (sender domain vs link domains)
        sender_domain = ''
        try:
            # crude extraction of email in From header
            import re
            m = re.search(r"[\w\.-]+@[\w\.-]+", from_hdr or '')
            if m:
                sender_domain = m.group(0).split('@')[-1].lower()
        except Exception:
            sender_domain = ''

        link_domains = set(domain_from_url(u) for u in urls if domain_from_url(u))
        # remove empty or matching
        link_domains = {d for d in link_domains if d}
        mismatch = False
        if sender_domain and link_domains:
            # if none of the link domains contain the sender domain -> mismatch
            if not any(sender_domain.endswith(ld) or ld.endswith(sender_domain) or ld.endswith(sender_domain.split('.')[-1]) for ld in link_domains):
                mismatch = True

        if mismatch:
            val = self.weights['sender_mismatch']
            breakdown.append(('sender_mismatch', val, f"Sender domain '{sender_domain}' doesn't match link domains {list(link_domains)}"))
            total += val

        # indicator: bad tld count
        if bad_tld_count:
            val = min(self.weights['bad_tld'], bad_tld_count * 4)
            breakdown.append(('bad_tld', val, f'Unusual domain parts count: {bad_tld_count}'))
            total += val

        # Normalize to 0-100
        score = int((total / max_possible) * 100) if max_possible else 0
        # Round and clamp
        score = max(0, min(100, score))

        return {
            'score': score,
            'max_score': 100,
            'raw_total': total,
            'max_possible_raw': max_possible,
            'breakdown': breakdown,
            'sender': from_hdr,
            'reply_to': reply_to,
            'urls': urls,
        }