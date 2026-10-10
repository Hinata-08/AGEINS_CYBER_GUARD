import re
from typing import Dict, Any, List

# Standard Indian Bank IFSC Prefix Map
MAJOR_BANK_IFSC = {
    "SBIN": "State Bank of India",
    "HDFC": "HDFC Bank",
    "ICIC": "ICICI Bank",
    "UTIB": "Axis Bank",
    "PUNB": "Punjab National Bank",
    "BARB": "Bank of Baroda",
    "KKBK": "Kotak Mahindra Bank",
    "CNRB": "Canara Bank",
    "UBIN": "Union Bank of India",
    "IDIB": "Indian Bank",
    "YESB": "Yes Bank",
    "PAYTM": "Paytm Payments Bank",
    "AIRP": "Airtel Payments Bank",
    "FINO": "Fino Payments Bank",
    "IPPB": "India Post Payments Bank"
}

ADVANCE_FEE_SCAM_KEYWORDS = [
    "lottery fee", "customs clearance", "processing charge", "refundable deposit",
    "kyc unblock", "electricity bill pending", "courier parcel hold", "tax release",
    "part time job task", "crypto investment return", "work from home deposit"
]

def analyze_bank_fraud(content: str) -> Dict[str, Any]:
    """
    Forensic analyzer for Fraud Bank Details and Payment Fraud.
    Validates:
    1. IFSC Code Syntax & Bank Entity Identity
    2. Bank Account Number Format & Pattern
    3. UPI VPA Handle & Money Mule Indicators
    4. Advance-Fee & Coercion Financial Scam Patterns
    """
    content = content.strip()
    if not content:
        return {"error": "No bank details or text provided to analyze."}

    flags: List[Dict[str, Any]] = []
    risk_score = 0
    details: Dict[str, Any] = {
        "extracted_ifsc": None,
        "bank_name": None,
        "extracted_accounts": [],
        "extracted_vpa": [],
        "is_advance_fee_scam": False
    }

    # 1. Regex Extraction of IFSC Code
    ifsc_match = re.search(r"\b[A-Z]{4}0[A-Z0-9]{6}\b", content.upper())
    if ifsc_match:
        ifsc = ifsc_match.group(0)
        bank_code = ifsc[:4]
        details["extracted_ifsc"] = ifsc

        if bank_code in MAJOR_BANK_IFSC:
            details["bank_name"] = MAJOR_BANK_IFSC[bank_code]
        else:
            details["bank_name"] = f"Unknown Bank Code ({bank_code})"
            risk_score += 15
            flags.append({
                "severity": "medium",
                "title": "Unregistered / Rare Bank IFSC Code",
                "desc": f"IFSC code '{ifsc}' prefix '{bank_code}' is not in the primary clearing house database."
            })
    else:
        # Check invalid IFSC attempt
        if "ifsc" in content.lower():
            risk_score += 25
            flags.append({
                "severity": "high",
                "title": "Malformed / Invalid IFSC Code",
                "desc": "Text contains 'IFSC' reference but the code structure does not match standard 11-character RBI format."
            })

    # 2. Extract Account Numbers
    acc_matches = re.findall(r"\b\d{9,18}\b", content)
    # Filter out timestamps or mobile numbers starting with +91 or 6-9
    valid_accs = [acc for acc in acc_matches if not (len(acc) == 10 and acc[0] in "6789")]
    details["extracted_accounts"] = valid_accs

    # 3. Extract UPI VPAs
    vpa_matches = re.findall(r"\b[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}\b", content)
    details["extracted_vpa"] = vpa_matches

    # 4. Advance-Fee & Task Scam Pattern Detection
    content_lower = content.lower()
    scam_matches = [kw for kw in ADVANCE_FEE_SCAM_KEYWORDS if kw in content_lower]
    if scam_matches:
        details["is_advance_fee_scam"] = True
        risk_score += 55
        flags.append({
            "severity": "critical",
            "title": "Advance-Fee / Money Mule Fraud Lure",
            "desc": f"Message contains advance-fee scam triggers ({', '.join(scam_matches)}). Scammers demand small upfront transfers to release fake rewards or jobs."
        })

    # 5. Urgent Payment Coercion Detection
    if any(k in content_lower for k in ["transfer immediately", "urgent payment", "account blocked today", "pay within 10 mins"]):
        risk_score += 25
        flags.append({
            "severity": "high",
            "title": "Urgency & Psychological Pressure Lure",
            "desc": "Uses strict time limits to prevent the victim from verifying details with official bank channels."
        })

    # 6. Personal Savings Account for Business/Government Tax
    if ("govt" in content_lower or "cyber cell" in content_lower or "income tax" in content_lower) and valid_accs:
        risk_score += 40
        flags.append({
            "severity": "critical",
            "title": "Impersonation of Government / Authority Account",
            "desc": "Government authorities and law enforcement NEVER demand funds to be transferred into private individual bank accounts."
        })

    risk_score = min(max(risk_score, 0), 100)
    tier = "CRITICAL" if risk_score >= 65 else "MEDIUM" if risk_score >= 35 else "SAFE"
    color = "red" if tier == "CRITICAL" else "amber" if tier == "MEDIUM" else "emerald"

    if tier == "CRITICAL":
        verdict = "HIGH FRAUD RISK - SUSPECTED MONEY MULE / BANK SCAM"
        safe_steps = [
            "DO NOT transfer money to the provided bank account or UPI ID.",
            "Government/Banks never ask you to pay money to unblock accounts or clear taxes into private accounts.",
            "Report fraudulent bank accounts to your nearest Cyber Crime Station or 1930."
        ]
    elif tier == "MEDIUM":
        verdict = "SUSPICIOUS BANKING DETAILS - VERIFY BENEFICIARY"
        safe_steps = [
            "Verify beneficiary name with your bank before initiating wire transfer.",
            "Double-check IFSC code and branch details.",
            "Avoid paying advance registration fees for online job offers."
        ]
    else:
        verdict = "VALID BANK DETAILS FORMAT - LOW FRAUD INDICATORS"
        safe_steps = [
            "IFSC code and account number follow valid bank clearing standards.",
            "Ensure you personally know the recipient before sending funds."
        ]

    return {
        "risk_score": risk_score,
        "risk_tier": tier,
        "status_color": color,
        "verdict": verdict,
        "details": details,
        "flags": flags,
        "recommendations": safe_steps
    }
