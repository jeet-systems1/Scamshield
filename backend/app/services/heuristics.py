"""
Heuristic-based threat detection.
Fast, deterministic, no external API calls.
Returns a list of ThreatSignal-compatible dicts.
"""
import re
import tldextract
from urllib.parse import urlparse
from typing import List, Dict, Any

# High-risk TLDs commonly used in phishing
HIGH_RISK_TLDS = {
    "tk", "ml", "ga", "cf", "gq",  # free Freenom TLDs
    "xyz", "top", "club", "online", "site", "website",
    "info", "biz", "click", "link", "live",
}

# Brands commonly impersonated in phishing
IMPERSONATED_BRANDS = [
    "paypal", "amazon", "apple", "google", "microsoft", "netflix",
    "facebook", "instagram", "whatsapp", "bank", "chase", "wellsfargo",
    "citibank", "hdfc", "sbi", "icici", "paytm", "phonepe", "gpay",
    "fedex", "dhl", "ups", "usps", "irs", "gov",
]

# Urgency/scam keywords for SMS/text analysis
URGENCY_KEYWORDS = [
    "urgent", "act now", "immediately", "account suspended", "verify now",
    "click here", "limited time", "expires today", "you have won",
    "congratulations", "prize", "lottery", "claim your", "free gift",
    "otp", "one time password", "do not share", "bank account",
    "kyc", "update your", "blocked", "suspended", "unusual activity",
    "confirm your identity", "security alert", "unauthorized",
]

# Patterns that suggest credential harvesting
CREDENTIAL_PATTERNS = [
    r"login", r"signin", r"sign-in", r"verify", r"confirm",
    r"update.*account", r"secure.*account", r"validate",
]


def analyze_url(url: str) -> List[Dict[str, Any]]:
    """Run all URL heuristics. Returns list of signal dicts."""
    signals = []
    parsed = urlparse(url)
    ext = tldextract.extract(url)

    domain = ext.domain.lower()
    suffix = ext.suffix.lower()
    subdomain = ext.subdomain.lower()
    full_domain = f"{domain}.{suffix}"
    path = parsed.path.lower()
    query = parsed.query.lower()

    # 1. High-risk TLD
    if suffix in HIGH_RISK_TLDS:
        signals.append({
            "name": "high_risk_tld",
            "value": suffix,
            "weight": 25,
            "description": f"The domain uses '.{suffix}' which is frequently used in scam websites.",
        })

    # 2. Brand impersonation in domain
    for brand in IMPERSONATED_BRANDS:
        if brand in domain and domain != brand:
            signals.append({
                "name": "brand_impersonation",
                "value": f"{brand} in {full_domain}",
                "weight": 40,
                "description": f"The domain contains '{brand}' but is not the official {brand} website. This is a common phishing trick.",
            })
            break

    # 3. Excessive subdomains (e.g. paypal.secure.login.evil.com)
    subdomain_depth = len(subdomain.split(".")) if subdomain else 0
    if subdomain_depth >= 3:
        signals.append({
            "name": "excessive_subdomains",
            "value": subdomain_depth,
            "weight": 20,
            "description": f"The URL has {subdomain_depth} subdomain levels, which is unusual for legitimate sites.",
        })

    # 4. IP address as host (e.g. http://192.168.1.1/login)
    ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    if ip_pattern.match(parsed.netloc.split(":")[0]):
        signals.append({
            "name": "ip_address_url",
            "value": parsed.netloc,
            "weight": 35,
            "description": "The URL uses a raw IP address instead of a domain name. Legitimate services almost never do this.",
        })

    # 5. HTTP (not HTTPS)
    if parsed.scheme == "http":
        signals.append({
            "name": "no_https",
            "value": "http",
            "weight": 15,
            "description": "The URL uses HTTP (not HTTPS), meaning your data is not encrypted.",
        })

    # 6. Credential-harvesting path keywords
    full_url_lower = url.lower()
    for pattern in CREDENTIAL_PATTERNS:
        if re.search(pattern, full_url_lower):
            signals.append({
                "name": "credential_harvesting_path",
                "value": pattern,
                "weight": 20,
                "description": "The URL path contains words like 'login' or 'verify' which are common in pages designed to steal passwords.",
            })
            break

    # 7. Excessively long URL
    if len(url) > 100:
        signals.append({
            "name": "long_url",
            "value": len(url),
            "weight": 10,
            "description": f"The URL is unusually long ({len(url)} characters). Scammers often use long URLs to hide the real destination.",
        })

    # 8. URL shortener (hides real destination)
    shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "short.link", "rb.gy"]
    if any(s in full_domain for s in shorteners):
        signals.append({
            "name": "url_shortener",
            "value": full_domain,
            "weight": 15,
            "description": "This is a shortened URL that hides the real destination. Scammers use these to disguise malicious links.",
        })

    # 9. Suspicious keywords in path/query
    suspicious_path_words = ["free", "prize", "winner", "claim", "reward", "gift"]
    for word in suspicious_path_words:
        if word in path or word in query:
            signals.append({
                "name": "suspicious_path_keyword",
                "value": word,
                "weight": 15,
                "description": f"The URL contains '{word}' which is commonly used in scam and prize fraud links.",
            })
            break

    return signals


def analyze_text(text: str) -> List[Dict[str, Any]]:
    """Run all SMS/text heuristics. Returns list of signal dicts."""
    signals = []
    text_lower = text.lower()

    # 1. Urgency keywords
    found_urgency = [kw for kw in URGENCY_KEYWORDS if kw in text_lower]
    if found_urgency:
        signals.append({
            "name": "urgency_language",
            "value": found_urgency[:5],
            "weight": 30,
            "description": f"The message uses urgent language like '{found_urgency[0]}' to pressure you into acting quickly without thinking.",
        })

    # 2. Embedded URLs
    url_pattern = re.compile(r"https?://\S+|www\.\S+", re.IGNORECASE)
    urls_found = url_pattern.findall(text)
    if urls_found:
        signals.append({
            "name": "embedded_url",
            "value": urls_found[0][:80],
            "weight": 20,
            "description": "The message contains a link. Scam messages often include links to fake websites.",
        })

    # 3. Brand impersonation in text
    for brand in IMPERSONATED_BRANDS:
        if brand in text_lower:
            signals.append({
                "name": "brand_mention",
                "value": brand,
                "weight": 25,
                "description": f"The message mentions '{brand}'. Scammers often pretend to be from well-known companies.",
            })
            break

    # 4. Requests for personal info
    personal_info_patterns = [
        r"otp", r"password", r"pin", r"cvv", r"card number",
        r"account number", r"aadhaar", r"ssn", r"social security",
        r"date of birth", r"mother.?s maiden",
    ]
    for pattern in personal_info_patterns:
        if re.search(pattern, text_lower):
            signals.append({
                "name": "personal_info_request",
                "value": pattern,
                "weight": 45,
                "description": "The message asks for sensitive personal information. Legitimate organizations never ask for OTPs, passwords, or PINs via SMS.",
            })
            break

    # 5. Prize/lottery fraud
    prize_patterns = [r"you.?ve won", r"you have won", r"winner", r"lottery", r"prize", r"claim.*reward"]
    for pattern in prize_patterns:
        if re.search(pattern, text_lower):
            signals.append({
                "name": "prize_fraud",
                "value": pattern,
                "weight": 40,
                "description": "The message claims you've won something. This is a classic scam tactic — you cannot win a lottery you didn't enter.",
            })
            break

    # 6. Suspicious phone number patterns (all-caps sender, short codes used for fraud)
    if re.search(r"\b\d{10,}\b", text):
        signals.append({
            "name": "phone_number_in_text",
            "value": "phone number detected",
            "weight": 10,
            "description": "The message contains a phone number. Scammers often ask you to call back to extract money or information.",
        })

    return signals


def calculate_risk_score(signals: List[Dict[str, Any]]) -> int:
    """
    Aggregate signal weights into a 0-100 risk score.
    Uses diminishing returns so multiple small signals don't
    artificially inflate the score past what's warranted.
    """
    if not signals:
        return 0

    total = sum(s["weight"] for s in signals)
    # Cap at 100, apply slight diminishing returns above 70
    if total <= 70:
        return min(total, 100)
    else:
        overflow = total - 70
        return min(70 + int(overflow * 0.5), 100)


def get_risk_level(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    elif score >= 50:
        return "HIGH"
    elif score >= 25:
        return "MEDIUM"
    else:
        return "LOW"


def get_threat_categories(signals: List[Dict[str, Any]]) -> List[str]:
    category_map = {
        "brand_impersonation": "Brand Impersonation",
        "brand_mention": "Brand Impersonation",
        "high_risk_tld": "Suspicious Domain",
        "ip_address_url": "Suspicious Domain",
        "excessive_subdomains": "Suspicious Domain",
        "no_https": "Insecure Connection",
        "credential_harvesting_path": "Credential Harvesting",
        "personal_info_request": "Credential Harvesting",
        "urgency_language": "Social Engineering",
        "prize_fraud": "Fraud / Scam",
        "url_shortener": "Hidden Destination",
        "embedded_url": "Suspicious Link",
        "long_url": "Obfuscation",
        "suspicious_path_keyword": "Fraud / Scam",
        "phone_number_in_text": "Social Engineering",
    }
    seen = set()
    categories = []
    for signal in signals:
        cat = category_map.get(signal["name"])
        if cat and cat not in seen:
            categories.append(cat)
            seen.add(cat)
    return categories
