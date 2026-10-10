import re
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any, List

KNOWN_VPA_DOMAINS = [
    "okaxis", "okhdfcbank", "okicici", "oksbi", "ybl", "ibl", "paytm",
    "apl", "axisbank", "hdfcbank", "icici", "sbi", "barodampay", "pnb"
]

SUSPICIOUS_PAYMENT_KEYWORDS = [
    "refund", "reward", "cashback", "claim", "lottery", "support",
    "customer-care", "verification", "kyc-update", "double-money",
    "gpay-help", "phonepe-gift", "paytm-cash"
]

def analyze_payment_qr(content: str) -> Dict[str, Any]:
    """
    Forensic scanner for Payment QR codes and Fake Payment Scanners.
    Inspects:
    1. UPI Payment URI Syntax & VPA Domain Legitimacy
    2. Deceptive Payment Direction (Collect vs Pay Scam)
    3. Phishing Redirection inside Payment Links
    4. Malicious Auto-Debit / Pre-Approved Mandate Payloads
    """
    content = content.strip()
    if not content:
        return {"error": "No QR payload or payment link provided."}

    flags: List[Dict[str, Any]] = []
    risk_score = 0
    payment_details: Dict[str, Any] = {
        "raw_payload": content[:120],
        "vpa": None,
        "payee_name": None,
        "amount": None,
        "transaction_ref": None,
        "is_upi": False
    }

    # 1. UPI Payment Protocol Check
    if content.lower().startswith("upi://pay"):
        payment_details["is_upi"] = True
        parsed = urlparse(content)
        params = parse_qs(parsed.query)

        vpa = params.get("pa", [""])[0]
        payee = params.get("pn", [""])[0]
        amount = params.get("am", [""])[0]
        txn_ref = params.get("tr", [""])[0] or params.get("mc", [""])[0]

        payment_details["vpa"] = vpa
        payment_details["payee_name"] = payee
        payment_details["amount"] = amount
        payment_details["transaction_ref"] = txn_ref

        # Check VPA handle
        if vpa:
            vpa_lower = vpa.lower()
            handle = vpa_lower.split("@")[-1] if "@" in vpa_lower else ""

            # Check suspicious keywords in VPA prefix
            prefix = vpa_lower.split("@")[0] if "@" in vpa_lower else vpa_lower
            found_keywords = [kw for kw in SUSPICIOUS_PAYMENT_KEYWORDS if kw in prefix]
            if found_keywords:
                risk_score += 45
                flags.append({
                    "severity": "critical",
                    "title": "Fake Refund / Cashback VPA Lure",
                    "desc": f"VPA prefix '{prefix}' contains scam lure keywords ({', '.join(found_keywords)}). Fraudsters use fake 'refund' handle names to trick users into paying."
                })

            # Check handle domain legitimacy
            if handle and handle not in KNOWN_VPA_DOMAINS:
                risk_score += 25
                flags.append({
                    "severity": "high",
                    "title": "Unregistered / High-Risk VPA Domain",
                    "desc": f"VPA domain '@{handle}' is not a standard major Indian bank UPI handle."
                })

        # Amount check
        if amount:
            try:
                amt_val = float(amount)
                if amt_val > 5000:
                    risk_score += 15
                    flags.append({
                        "severity": "medium",
                        "title": "High Transaction Amount Payload",
                        "desc": f"QR payload requests a payment of Rs. {amt_val:,.2f}."
                    })
            except ValueError:
                pass

        # Check if disguised auto-debit / mandate
        if "mode=02" in content or "mode=04" in content or "purpose=" in content:
            risk_score += 30
            flags.append({
                "severity": "high",
                "title": "Embedded Recurring Mandate / Auto-Debit Flag",
                "desc": "QR payload requests pre-authorized recurring auto-debit consent."
            })

    elif content.startswith(("http://", "https://")):
        parsed = urlparse(content)
        host = parsed.hostname or ""

        # Check fake payment gateway domains
        fake_payment_brands = ["gpay", "phonepe", "paytm", "bhim", "razorpay", "paypal", "stripe"]
        host_clean = host.lower().replace("-", "").replace(".", "")

        for brand in fake_payment_brands:
            if brand in host_clean and not any(host.endswith("." + official) or host == official for official in [f"{brand}.com", f"{brand}.in", f"bhimupi.org.in"]):
                risk_score += 60
                flags.append({
                    "severity": "critical",
                    "title": "Fake Payment Gateway / Brand Phishing",
                    "desc": f"Domain '{host}' spoofs official payment brand '{brand}'. Do NOT enter PIN or card details."
                })
                break

        # Check shortener
        if any(short in host for short in ["bit.ly", "tinyurl.com", "is.gd", "t.co", "cutt.ly"]):
            risk_score += 30
            flags.append({
                "severity": "high",
                "title": "Obfuscated Shortened Payment Link",
                "desc": "Uses URL shortener to hide actual payment gateway target."
            })
    else:
        # Check raw text for bank account or money lure
        if any(kw in content.lower() for kw in ["scan to receive", "enter pin to get", "scratch card win", "gpay reward"]):
            risk_score += 55
            flags.append({
                "severity": "critical",
                "title": "Classic 'PIN to Receive' Scam Lure",
                "desc": "No PIN is ever required to RECEIVE money in UPI. If a QR code prompts for PIN, it will DEDUCT money from your bank account."
            })

    risk_score = min(max(risk_score, 0), 100)
    tier = "CRITICAL" if risk_score >= 65 else "MEDIUM" if risk_score >= 35 else "SAFE"
    color = "red" if tier == "CRITICAL" else "amber" if tier == "MEDIUM" else "emerald"

    if tier == "CRITICAL":
        verdict = "CRITICAL FRAUD ALERT - FAKE PAYMENT SCANNER / SCAM QR"
        safe_steps = [
            "DO NOT SCAN OR PAY using this QR code.",
            "Remember: UPI PIN is ONLY required to SEND money, NEVER to receive money.",
            "Report the fraud UPI VPA ID to your bank app or 1930 Cybercrime Helpline."
        ]
    elif tier == "MEDIUM":
        verdict = "SUSPICIOUS PAYMENT QR - VERIFY PAYEE DETAILS"
        safe_steps = [
            "Check the payee name shown on your banking app before confirming.",
            "Verify the payment amount carefully.",
            "Never scan payment QR codes sent by strangers on WhatsApp/OLX."
        ]
    else:
        verdict = "SAFE PAYMENT QR - STANDARD FORMAT MATCH"
        safe_steps = [
            "QR payload uses standard UPI format and verified bank VPA domain.",
            "Always verify payee name on your banking screen."
        ]

    return {
        "risk_score": risk_score,
        "risk_tier": tier,
        "status_color": color,
        "verdict": verdict,
        "payment_details": payment_details,
        "flags": flags,
        "recommendations": safe_steps
    }
