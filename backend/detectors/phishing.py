import math
import re
from urllib.parse import urlparse

# Well-known target brands commonly spoofed in phishing attacks
TARGET_BRANDS = [
    "google", "paypal", "microsoft", "amazon", "apple", "netflix",
    "facebook", "instagram", "chase", "bankofamerica", "wellsfargo",
    "sbi", "hdfc", "binance", "coinbase", "meta", "whatsapp",
    "dropbox", "linkedin", "twitter", "adobe", "outlook", "icloud",
    "axis", "icici", "paytm", "phonepe", "gpay", "upi", "uidai",
    "incometax", "epfo", "irctc", "ration", "pension"
]

SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "click", "buzz", "fit", "tk", "ml", "ga",
    "cf", "gq", "rest", "surf", "monster", "bar", "live", "icu", "site",
    "pw", "cc", "ws", "info", "biz", "online", "store", "shop", "fun",
    "uno", "world", "solutions", "tech", "digital", "link", "space"
}

# Domains considered broadly safe — NOT automatically "clean" but lower default risk
KNOWN_SAFE_DOMAINS = {
    "google.com", "youtube.com", "microsoft.com", "apple.com",
    "amazon.com", "facebook.com", "instagram.com", "linkedin.com",
    "gov.in", "nic.in", "ac.in", "edu", "gov", "mil",
    "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com",
    "paytm.com", "phonepe.com", "npci.org.in", "upi.org",
    "rbi.org.in", "sebi.gov.in", "irdai.gov.in", "irctc.co.in"
}

SUSPICIOUS_KEYWORDS = [
    "verify", "login", "update", "account", "secure", "banking", "wallet",
    "confirm", "password", "security", "authenticate", "signin", "support",
    "billing", "payment", "suspension", "unauthorized", "kyc", "recover",
    "reset", "blocked", "locked", "urgent", "verify-now", "click-here",
    "prize", "free", "reward", "bonus", "winner", "lucky", "claim", "otp",
    "aadhaar", "pan", "aadhar", "election", "income-tax", "ration-card"
]

def calculate_shannon_entropy(text: str) -> float:
    """Computes Shannon entropy to detect algorithmic/randomized domain generation (DGA)."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)

def levenshtein_distance(s1: str, s2: str) -> int:
    """Standard Levenshtein edit distance algorithm."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def check_typosquatting(domain_name: str):
    """Detects brand spoofing, homoglyphs, and typosquatting."""
    domain_clean = domain_name.lower().split(".")[0]
    # Replace common homoglyphs: 0 -> o, 1 -> l, etc.
    normalized = domain_clean.replace("0", "o").replace("1", "l").replace("vv", "w").replace("rn", "m")

    matches = []
    for brand in TARGET_BRANDS:
        if brand in domain_clean and brand != domain_clean:
            matches.append({"brand": brand, "type": "Subdomain / Keyword Embedded", "similarity": 95})
            continue

        dist = levenshtein_distance(normalized, brand)
        if dist == 1 and len(brand) >= 4:
            matches.append({"brand": brand, "type": "Levenshtein Typosquatting (Edit dist: 1)", "similarity": 88})
        elif dist == 2 and len(brand) >= 7:
            matches.append({"brand": brand, "type": "Typosquatting Variant (Edit dist: 2)", "similarity": 75})

    return matches

def is_known_safe(hostname: str) -> bool:
    """Returns True if the hostname is a trusted, well-known domain."""
    hostname = hostname.lower()
    for safe in KNOWN_SAFE_DOMAINS:
        if hostname == safe or hostname.endswith("." + safe):
            return True
    # Government TLDs
    if hostname.endswith(".gov.in") or hostname.endswith(".nic.in") or hostname.endswith(".ac.in") or hostname.endswith(".edu"):
        return True
    return False

def analyze_url(url: str) -> dict:
    """
    Exhaustive heuristic & algorithmic phishing threat analysis.
    Returns risk score (0-100), risk level, flags, and mitigation guidance.
    """
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    full_str = url.lower()

    flags = []
    risk_score = 0
    threat_breakdown = {}

    ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    known_safe = is_known_safe(hostname)

    # -------------------------------------------------------------------------
    # 0. Baseline Trust Score — any URL not on a known-safe list starts with
    #    a default "unverified" penalty so the user is never misled into thinking
    #    an unknown site is automatically safe.
    # -------------------------------------------------------------------------
    if not known_safe:
        risk_score += 25
        flags.append({
            "severity": "low",
            "title": "Unverified / Unknown Domain",
            "desc": f"'{hostname}' is not in the registry of known-trusted domains. Exercise standard caution."
        })
    else:
        # Even known-safe domains can host malicious paths; no penalty but track it
        threat_breakdown["known_safe_domain"] = True

    # 1. Scheme Check
    if parsed.scheme != "https":
        risk_score += 20
        flags.append({"severity": "medium", "title": "Insecure Protocol (HTTP)", "desc": "Uses unencrypted HTTP — credentials and data are exposed in transit."})
    
    # 2. IP Address in Hostname
    if re.match(ip_pattern, hostname):
        risk_score += 40
        flags.append({"severity": "high", "title": "Raw IP Address Host", "desc": f"Host is a raw numerical IP ({hostname}), typical of adversary C2 or phishing nodes."})

    # 3. Shannon Entropy (DGA Detection)
    domain_entropy = calculate_shannon_entropy(hostname)
    threat_breakdown["domain_entropy"] = domain_entropy
    if domain_entropy > 4.0:
        risk_score += 25
        flags.append({"severity": "high", "title": "High Domain Entropy", "desc": f"Entropy of {domain_entropy} indicates potential Domain Generation Algorithm (DGA)."})
    elif domain_entropy > 3.5:
        risk_score += 12
        flags.append({"severity": "medium", "title": "Elevated Entropy", "desc": f"Domain entropy {domain_entropy} shows random character patterns."})

    # 4. Typosquatting & Brand Impersonation
    typos = check_typosquatting(hostname)
    if typos:
        for t in typos:
            risk_score += 45
            flags.append({"severity": "critical", "title": f"Target Impersonation: {t['brand'].upper()}", "desc": f"Detected {t['type']} mimicking legitimate service."})

    # 5. Suspicious TLD
    tld = hostname.split(".")[-1].lower() if "." in hostname else ""
    if tld in SUSPICIOUS_TLDS:
        risk_score += 25
        flags.append({"severity": "high", "title": f"High-Abuse TLD (.{tld})", "desc": f"Top-level domain .{tld} has very high historical correlation with spam/phishing operations."})

    # 6. Excessive Subdomains
    subdomain_parts = hostname.split(".")
    if len(subdomain_parts) >= 4 and not re.match(ip_pattern, hostname):
        risk_score += 18
        flags.append({"severity": "medium", "title": "Subdomain Stacking", "desc": f"{len(subdomain_parts)} domain segments detected, common in evasive redirects."})

    # 7. Sensitive Urgency/Auth Keywords in URL
    detected_kw = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_str]
    threat_breakdown["detected_keywords"] = detected_kw
    if len(detected_kw) >= 3:
        risk_score += 30
        flags.append({"severity": "critical", "title": "Multiple Phishing Lure Keywords", "desc": f"Highly suspicious tokens found: {', '.join(detected_kw[:5])}"})
    elif len(detected_kw) >= 2:
        risk_score += 20
        flags.append({"severity": "high", "title": "Phishing Lure Keywords", "desc": f"Security-sensitive keywords in URL: {', '.join(detected_kw)}"})
    elif len(detected_kw) == 1:
        risk_score += 10
        flags.append({"severity": "low", "title": "Sensitive Action Keyword", "desc": f"Contains security keyword: {', '.join(detected_kw)}"})

    # 8. Special Character Obfuscation
    if "@" in url:
        risk_score += 35
        flags.append({"severity": "critical", "title": "Credential Obfuscation (@)", "desc": "Uses '@' sign to disguise the true destination authority — classic phishing redirect trick."})
    if "%" in url or "//" in path:
        risk_score += 15
        flags.append({"severity": "medium", "title": "URL Encoding / Double Slashes", "desc": "Path contains obfuscated hex encoding or abnormal slashes."})

    # 9. URL Length
    if len(url) > 120:
        risk_score += 15
        flags.append({"severity": "medium", "title": "Excessive URL Length", "desc": f"Length {len(url)} chars — unusually long URLs often conceal phishing redirects."})
    elif len(url) > 80:
        risk_score += 8
        flags.append({"severity": "low", "title": "Long URL", "desc": f"URL length {len(url)} chars is above typical threshold."})

    # 10. Path Depth (deep nesting common in evasion)
    path_parts = [p for p in path.split("/") if p]
    if len(path_parts) > 4:
        risk_score += 12
        flags.append({"severity": "low", "title": "Deep URL Path", "desc": f"{len(path_parts)} path segments — deeply nested URLs often used to evade shallow URL scanners."})

    # 11. Query string with sensitive params
    if query:
        sensitive_params = ["token", "redirect", "url", "return", "next", "target", "rurl", "dest"]
        found_params = [p for p in sensitive_params if p in query.lower()]
        if found_params:
            risk_score += 15
            flags.append({"severity": "medium", "title": "Open Redirect Parameters", "desc": f"Query contains redirect/token parameters ({', '.join(found_params)}) — used in phishing redirectors."})

    # 12. Non-standard port
    if parsed.port and parsed.port not in (80, 443):
        risk_score += 20
        flags.append({"severity": "high", "title": f"Non-Standard Port ({parsed.port})", "desc": "Legitimate services rarely use non-standard ports. Common indicator of rogue infrastructure."})

    # Cap risk score between 0 and 100
    final_score = min(max(risk_score, 0), 100)

    if final_score >= 65:
        risk_level = "CRITICAL / PHISHING"
        status_color = "red"
        verdict = "MALICIOUS PHISHING TARGET DETECTED"
        recommendation = "Block immediately. Do NOT enter credentials, click links, or download files from this URL."
    elif final_score >= 35:
        risk_level = "SUSPICIOUS"
        status_color = "amber"
        verdict = "SUSPICIOUS CHARACTERISTICS DETECTED"
        recommendation = "Proceed with caution. Verify via official contact channel. Do not enter sensitive data."
    else:
        risk_level = "LOW RISK"
        status_color = "emerald"
        verdict = "LOW RISK — MINIMAL ADVERSARIAL INDICATORS"
        recommendation = "URL appears consistent with known-safe infrastructure. Standard vigilance recommended."

    return {
        "url": url,
        "hostname": hostname,
        "protocol": parsed.scheme,
        "risk_score": final_score,
        "risk_level": risk_level,
        "status_color": status_color,
        "verdict": verdict,
        "recommendation": recommendation,
        "flags": flags,
        "metrics": {
            "entropy": domain_entropy,
            "url_length": len(url),
            "subdomain_count": len(subdomain_parts),
            "detected_keywords_count": len(detected_kw),
            "has_ip_host": bool(re.match(ip_pattern, hostname)),
            "typosquatting_hits": len(typos),
            "is_known_safe_domain": known_safe
        }
    }
