import re
from typing import Dict, Any, List

SMS_SCAM_PATTERNS = [
    (r"electricity.*disconnect|bijli.*cut|meter.*disconnect", "Electricity Bill Disconnection Scam",
     "Claims electricity will be cut off unless a bill is paid urgently — do NOT comply."),
    (r"courier.*address|parcel.*delivery|fedex.*hold|indiapost.*address|speed.*post.*failed",
     "Postal / Courier Delivery Phishing",
     "Claims parcel address is incomplete to trick user into clicking a phishing link."),
    (r"kyc.*block|account.*suspend|sbi.*update|hdfc.*pan|axis.*kyc|icici.*kyc|pan.*update.*bank",
     "Banking KYC Phishing SMS",
     "Coerces user to update PAN/KYC immediately to prevent account suspension."),
    (r"apk|download.*install|install.*app.*link", "Malicious APK Malware Lure",
     "Prompts victim to download an untrusted Android APK that installs spyware."),
    (r"win.*lakh|lottery.*congrat|job.*daily|earn.*daily|work.*home.*daily.*income|telegram.*task",
     "Lottery / Part-time Job Scam",
     "Promises easy money or lottery rewards to lure victim into an advance-fee scam."),
    (r"otp.*share|share.*otp|otp.*mat.*batao.*isko|otp.*kisi.*mat", "OTP Phishing",
     "Message tries to obtain your OTP through social engineering."),
    (r"aadhaar.*block|aadhaar.*suspend|uid.*block|ration.*card.*expire",
     "Government Document Suspension Scam",
     "Falsely claims your government ID will be deactivated unless you act immediately."),
    (r"income.*tax.*refund|it.*refund.*credit|tds.*return|tax.*refund.*link",
     "Income Tax Refund Scam",
     "Fraudulent income tax refund lure — IT department never sends refunds via SMS links."),
    (r"police|cyber.*crime.*notice|court.*notice.*sms|arrest.*warrant",
     "Cyber Police / Legal Threat Scam",
     "Threatens police action or arrest to coerce payment — a hallmark cyber extortion tactic."),
    (r"customer.*care.*toll.*free|helpline.*number.*bank|sbi.*customer.*care.*\d{10}",
     "Fake Customer Care Helpline",
     "Impersonates bank/government helpline — actual helplines never ask for full credentials over SMS.")
]

VIRTUAL_VOIP_PREFIXES = [
    "+18", "+447", "+234", "+92", "+63", "+855",
    "+216", "+7", "+44", "+1900", "+1800"
]

# Standard Indian mobile number prefixes — 10-digit numbers starting with 6/7/8/9
INDIAN_MOBILE_REGEX = re.compile(r"^[6-9]\d{9}$")

# Patterns that strongly suggest the input is a plain phone number (no context)
PLAIN_NUMBER_PATTERN = re.compile(r"^[\d\s\-\+\(\)]{7,15}$")


def analyze_phone_fraud(content: str) -> Dict[str, Any]:
    """
    Forensic analyzer for Fraud Phone Numbers and Scam SMS.
    Evaluates:
    1. Phone Number Syntax & Telecom VoIP/Virtual Range Check
    2. SMS Phishing Lures (Courier, Electricity, KYC, Malware APK, etc.)
    3. Urgency / Coercive language signals
    4. Malicious link or APK attachment in SMS
    5. Baseline unverified-number risk (no context = moderate risk)
    """
    content = content.strip()
    if not content:
        return {"error": "No phone number or SMS text provided."}

    flags: List[Dict[str, Any]] = []
    risk_score = 0
    phone_details: Dict[str, Any] = {
        "extracted_numbers": [],
        "carrier_estimate": "Standard Mobile",
        "has_malicious_link": False,
        "scam_category": None
    }

    # 1. Extract Phone Numbers
    phone_matches = re.findall(r"(?:\+?\d{1,3}[.\-\s]?)?\(?\d{3}\)?[.\-\s]?\d{3}[.\-\s]?\d{4}\b", content)
    phone_details["extracted_numbers"] = phone_matches

    is_plain_number_only = bool(PLAIN_NUMBER_PATTERN.match(content)) and len(content.split()) <= 3

    for num in phone_matches:
        clean_num = re.sub(r"[^\d+]", "", num)

        # Check VoIP / International high-risk prefix
        for v_pref in VIRTUAL_VOIP_PREFIXES:
            if clean_num.startswith(v_pref):
                phone_details["carrier_estimate"] = "VoIP / Virtual / International Range"
                risk_score += 30
                flags.append({
                    "severity": "high",
                    "title": "VoIP / International Range Detected",
                    "desc": f"Number '{num}' belongs to a virtual/VoIP range frequently used by cyber scammers."
                })
                break

        # Check if it looks like an Indian mobile but with unknown context
        digits_only = re.sub(r"[^\d]", "", clean_num)
        if INDIAN_MOBILE_REGEX.match(digits_only[-10:]) if len(digits_only) >= 10 else False:
            if is_plain_number_only:
                # Plain number submission with no SMS context → moderate unverified risk
                risk_score += 20
                flags.append({
                    "severity": "medium",
                    "title": "Unverified Mobile Number",
                    "desc": (
                        f"Number '{num}' cannot be verified against any whitelist. "
                        "No telecom authority validation available. "
                        "If received an unsolicited call from this number, treat with caution."
                    )
                })

    # If no phone number found but content is short — treat as unstructured plain text input
    if not phone_matches:
        # Try to find partial digit sequences
        digit_groups = re.findall(r"\d{6,}", content)
        if digit_groups:
            risk_score += 15
            flags.append({
                "severity": "low",
                "title": "Partial / Unformatted Number Detected",
                "desc": f"Detected digit sequences ({', '.join(digit_groups)}) that may be phone/account numbers."
            })
        else:
            # Pure text, no numbers — analyze as SMS content
            pass

    # 2. Check SMS Scam Patterns
    content_lower = content.lower()
    scam_hit = False
    for pattern, title, desc in SMS_SCAM_PATTERNS:
        if re.search(pattern, content_lower):
            risk_score += 50
            phone_details["scam_category"] = title
            scam_hit = True
            flags.append({
                "severity": "critical",
                "title": title,
                "desc": desc
            })
            break  # one match is enough to flag critical

    # 3. Malicious Links / APK download in SMS
    if re.search(r"https?://[^\s]+|\.apk\b|bit\.ly|tinyurl|short\.io|rb\.gy|cutt\.ly", content_lower):
        phone_details["has_malicious_link"] = True
        risk_score += 35
        flags.append({
            "severity": "high",
            "title": "Suspicious Link / APK Attachment",
            "desc": "SMS contains an external hyperlink or downloadable file. NEVER click untrusted links in SMS."
        })

    # 4. Urgency / Threats
    urgency_triggers = [
        "tonight at 9", "within 2 hours", "within 24 hours", "immediately", "urgent",
        "last warning", "final notice", "will be blocked", "will be arrested",
        "call now", "action required", "account deactivated"
    ]
    found_urgency = [k for k in urgency_triggers if k in content_lower]
    if found_urgency:
        risk_score += 20
        flags.append({
            "severity": "high",
            "title": "Artificial Urgency / Coercion",
            "desc": f"Message creates panic to bypass rational thinking. Triggers: {', '.join(found_urgency[:3])}"
        })

    # 5. Money / Transfer demands
    money_patterns = [
        "pay", "payment", "transfer", "wallet", "upi", "gpay", "phonpe",
        "paytm", "qr code", "account number", "send money", "recharge"
    ]
    found_money = [k for k in money_patterns if k in content_lower]
    if found_money and not is_plain_number_only:
        risk_score += 15
        flags.append({
            "severity": "medium",
            "title": "Payment / Money Transfer Reference",
            "desc": f"SMS references financial transactions ({', '.join(found_money[:3])}). Verify via official channels only."
        })

    # 6. Baseline for plain number with zero context
    if is_plain_number_only and not scam_hit and not flags:
        risk_score += 15
        flags.append({
            "severity": "low",
            "title": "No Context Available — Cannot Verify",
            "desc": "A standalone number with no associated message context. Risk cannot be fully assessed without call/SMS history."
        })

    risk_score = min(max(risk_score, 0), 100)
    tier = "CRITICAL" if risk_score >= 65 else "MEDIUM" if risk_score >= 30 else "SAFE"
    color = "red" if tier == "CRITICAL" else "amber" if tier == "MEDIUM" else "emerald"

    if tier == "CRITICAL":
        verdict = "CRITICAL SCAM / SMS FRAUD ALERT"
        safe_steps = [
            "DO NOT click any links or call back numbers received in suspicious SMS.",
            "Never share OTPs, passwords, or banking details over phone calls or SMS.",
            "Report scam caller/SMS on Chakshu portal (sancharsaathi.gov.in) or Cybercrime Helpline 1930.",
            "Block the number immediately and inform your bank if financial credentials were shared."
        ]
    elif tier == "MEDIUM":
        verdict = "SUSPICIOUS PHONE / SMS ACTIVITY"
        safe_steps = [
            "Verify caller identity through the official website or known contact number.",
            "Block unknown callers attempting social engineering.",
            "Do not install remote support apps (AnyDesk, TeamViewer) if prompted by caller.",
            "Do not share OTP or card details with anyone claiming to be from a bank or government."
        ]
    else:
        verdict = "LOW RISK — LIMITED FRAUD INDICATORS"
        safe_steps = [
            "No high-confidence scam triggers detected in the provided content.",
            "Always stay vigilant against unknown callers asking for personal or financial information.",
            "Legitimate banks and government agencies never ask for OTPs or passwords via SMS/call."
        ]

    return {
        "risk_score": risk_score,
        "risk_tier": tier,
        "status_color": color,
        "verdict": verdict,
        "phone_details": phone_details,
        "flags": flags,
        "recommendations": safe_steps
    }
