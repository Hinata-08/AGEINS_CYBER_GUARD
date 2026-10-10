import re
from typing import Dict, Any, List

URGENCY_KEYWORDS = [
    "urgent", "immediately", "action required", "account suspended", "terminate",
    "24 hours", "48 hours", "unauthorized login", "security alert", "freeze",
    "arrest", "lawsuit", "legal action", "compromised", "final warning", "lockout",
    "blocked", "account blocked", "suspended today", "penalty"
]

FINANCIAL_SCAM_KEYWORDS = [
    "gift card", "crypto", "bitcoin", "ethereum", "wallet", "wire transfer",
    "western union", "lottery", "prize", "inheritance", "million dollars",
    "beneficiary", "claim your funds", "direct deposit", "invoice attached",
    "electricity bill", "part time job", "daily income", "telegram task"
]

CREDENTIAL_HARVEST_KEYWORDS = [
    "verify password", "update credential", "confirm identity", "ssn",
    "social security", "pin code", "otp", "2fa code", "seed phrase", "secret key",
    "kyc", "verify kyc", "complete kyc", "pan card", "aadhaar", "debit card",
    "cvv", "atm pin", "click here to verify", "update kyc"
]

def analyze_email(subject: str, sender: str, body: str, raw_headers: str = "") -> Dict[str, Any]:
    """
    Analyzes email subject, sender, body, and optional raw headers for phishing,
    social engineering, spoofing, and malicious intent.
    """
    full_text = f"{subject}\n{body}".lower()
    flags: List[Dict[str, Any]] = []
    risk_score = 0

    # 1. Sender Domain Analysis & Spoofing Indicators
    sender_lower = sender.lower()
    sender_domain = ""
    if "@" in sender_lower:
        sender_domain = sender_lower.split("@")[-1].replace(">", "").strip()

    free_webmails = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com"]
    corporate_keywords = ["support", "security", "admin", "billing", "ceo", "director", "bank", "irs", "hr"]

    if any(k in sender_lower for k in corporate_keywords) and any(sender_domain == fw for fw in free_webmails):
        risk_score += 35
        flags.append({
            "severity": "critical",
            "title": "Corporate Impersonation via Public Webmail",
            "desc": f"Sender claims official authority but uses generic public provider ({sender_domain})."
        })

    if "<" in sender and ">" in sender:
        display_name = sender.split("<")[0].lower()
        impersonated_brands = [
            ("paypal", "paypal.com"), ("amazon", "amazon.com"), ("google", "google.com"),
            ("microsoft", "microsoft.com"), ("apple", "apple.com"), ("sbi", "sbi.co.in"),
            ("hdfc", "hdfcbank.com"), ("icici", "icicibank.com"), ("irctc", "irctc.co.in"),
            ("income tax", "incometaxindia.gov.in"), ("uidai", "uidai.gov.in")
        ]
        for brand_name, brand_domain in impersonated_brands:
            if brand_name in display_name and brand_domain not in sender_domain:
                risk_score += 45
                flags.append({
                    "severity": "critical",
                    "title": f"Display Name Deception — {brand_name.upper()} Impersonation",
                    "desc": f"Display name claims to be '{brand_name}', but actual sender domain is '{sender_domain}' — clear impersonation attack."
                })
                break

    # 2. Urgency & Coercion Keywords
    matched_urgency = [kw for kw in URGENCY_KEYWORDS if kw in full_text]
    if matched_urgency:
        risk_score += min(len(matched_urgency) * 12, 35)
        flags.append({
            "severity": "high",
            "title": "Artificial Urgency Triggered",
            "desc": f"Email employs psychological coercion words ({', '.join(matched_urgency[:3])})."
        })

    # 3. Financial Scam & Wire Lures
    matched_financial = [kw for kw in FINANCIAL_SCAM_KEYWORDS if kw in full_text]
    if matched_financial:
        risk_score += min(len(matched_financial) * 15, 40)
        flags.append({
            "severity": "critical",
            "title": "Financial Scam Lure Keywords",
            "desc": f"Detected high-risk financial transfer lexicon ({', '.join(matched_financial[:3])})."
        })

    # 4. Credential Harvesting Signals
    matched_creds = [kw for kw in CREDENTIAL_HARVEST_KEYWORDS if kw in full_text]
    if matched_creds:
        risk_score += min(len(matched_creds) * 18, 45)
        flags.append({
            "severity": "critical",
            "title": "Credential Harvesting Pattern",
            "desc": f"Lure attempts to capture sensitive PII or authentication keys ({', '.join(matched_creds[:3])})."
        })

    # 5. Extract URLs
    urls_found = re.findall(r"https?://[^\s<'\"]+", full_text)
    if len(urls_found) > 0:
        # Baseline: any email with external links is inherently unverified
        risk_score += 20
        flags.append({
            "severity": "medium",
            "title": "External Links Detected",
            "desc": f"Email contains {len(urls_found)} embedded URL(s). Verify all links before clicking — phishing emails rely on disguised hyperlinks."
        })
        if len(urls_found) > 3:
            risk_score += 15
            flags.append({"severity": "high", "title": "High Link Density", "desc": f"Email contains {len(urls_found)} URLs — unusually high link count is a strong phishing signal."})

    # 6. Header Checks
    headers_analyzed = False
    if raw_headers:
        headers_analyzed = True
        raw_lower = raw_headers.lower()
        if "spf=fail" in raw_lower or "spf=softfail" in raw_lower:
            risk_score += 30
            flags.append({"severity": "high", "title": "SPF Authentication Failure", "desc": "Sender server is not authorized to deliver mail for this domain."})
        if "dkim=fail" in raw_lower:
            risk_score += 30
            flags.append({"severity": "high", "title": "DKIM Signature Invalid", "desc": "Message body or headers altered in transit."})
        if "dmarc=fail" in raw_lower:
            risk_score += 25
            flags.append({"severity": "high", "title": "DMARC Alignment Failure", "desc": "Email failed DMARC policy validation."})

    final_score = min(max(risk_score, 0), 100)

    if final_score >= 65:
        category = "MALICIOUS SPEAR-PHISHING / SCAM EMAIL"
        status_color = "red"
        advice = "DO NOT respond, click links, open attachments, or wire funds."
        recs = [
            "Do not click links or open attachments in this message.",
            "Verify the sender's identity through an official secondary channel.",
            "Report phishing attempt to your mail administrator or Cybercell 1930."
        ]
    elif final_score >= 35:
        category = "SUSPICIOUS / SPAM EMAIL"
        status_color = "amber"
        advice = "Marked as untrusted. Verify sender authenticity through secondary communications channel."
        recs = [
            "Avoid entering credentials or sensitive bank data.",
            "Inspect sender header addresses carefully."
        ]
    else:
        category = "LEGITIMATE / CLEAN EMAIL"
        status_color = "emerald"
        advice = "Standard corporate/transactional message characteristics identified."
        recs = [
            "No major phishing red flags identified.",
            "Always maintain standard digital communications hygiene."
        ]

    return {
        "risk_score": final_score,
        "category": category,
        "verdict": category,
        "status_color": status_color,
        "advice": advice,
        "recommendations": recs,
        "flags": flags,
        "links_extracted": urls_found,
        "suspicious_tokens": list(set(matched_urgency + matched_financial + matched_creds)),
        "metrics": {
            "urgency_triggers": len(matched_urgency),
            "financial_triggers": len(matched_financial),
            "credential_triggers": len(matched_creds),
            "total_links": len(urls_found),
            "headers_checked": headers_analyzed
        }
    }
