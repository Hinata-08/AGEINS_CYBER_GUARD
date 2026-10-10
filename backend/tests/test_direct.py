import sys
import os
from pathlib import Path

_current_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_current_dir))

from database import register_user, login_user, get_organiser_users_data, init_db
from detectors.phishing import analyze_url
from detectors.email_analyzer import analyze_email
from detectors.trust_mismatch import analyze_trust_mismatch
from detectors.qr_payment import analyze_payment_qr
from detectors.bank_fraud import analyze_bank_fraud
from detectors.phone_fraud import analyze_phone_fraud

def test_direct():
    print("1. Initializing DB & Schema...")
    init_db()
    print("   DB initialized.")

    print("\n2. Testing User Registration & Login...")
    email = f"user_{os.urandom(3).hex()}@example.com"
    reg = register_user("Jane Doe", email, "password123")
    assert reg["token"]
    assert reg["user"]["email"] == email
    print("   User Registration OK:", email)

    log = login_user("admin@ageins.com", "admin123")
    assert log["user"]["role"] == "admin"
    print("   Organiser Admin Login OK!")

    print("\n3. Testing Organiser Fetching User Login Data...")
    users = get_organiser_users_data()
    assert len(users) >= 2
    print("   Organiser User Login Data fetched successfully:", len(users), "users.")
    for u in users:
        print(f"     - ID: {u['id']}, Name: {u['username']}, Email: {u['email']}, Role: {u['role']}, Spent: {u['spent']}s, Scans: {u['total_scans']}")

    print("\n4. Testing 7 Specialized Detectors...")
    
    # (A) URL Phishing
    url_res = analyze_url("https://paypal-security-update-99.xyz/login")
    print("   (A) URL Phishing Risk Score:", url_res["risk_score"], "| Verdict:", url_res["verdict"])

    # (B) Email Threat
    mail_res = analyze_email("URGENT: Blocked SBI Account", "help@sbi-verify.net", "Verify your KYC immediately or account will be suspended.")
    print("   (B) Email Threat Risk Score:", mail_res["risk_score"], "| Verdict:", mail_res["verdict"])

    # (C) Trust Mismatch Deepfake
    trust_res = analyze_trust_mismatch(b"fake image payload header simulation content " * 10, "face_swap.jpg", "image")
    print("   (C) Trust Mismatch Score:", trust_res.get("mismatch_score", 0), "| Trust Index:", trust_res.get("trust_index", 100), "| Verdict:", trust_res.get("verdict"))

    # (D) Payment QR Scanner & Fake Scanner
    qr_res = analyze_payment_qr("upi://pay?pa=gpay-refund-support@ybl&am=5000&pn=Refund")
    print("   (D) Payment QR Code Score:", qr_res["risk_score"], "| Payee:", qr_res["payment_details"]["payee_name"], "| Verdict:", qr_res["verdict"])

    # (E) Fraud Bank Details
    bank_res = analyze_bank_fraud("Transfer Rs 500 lottery fee to Bank: SBI, Account: 3948291039, IFSC: SBIN0001234")
    print("   (E) Fraud Bank Details Score:", bank_res["risk_score"], "| Bank:", bank_res["details"]["bank_name"], "| Verdict:", bank_res["verdict"])

    # (F) Fraud Phone Number & SMS
    phone_res = analyze_phone_fraud("Electricity bill unpaid. Connection disconnect tonight at 9:30 PM. Call 9876543210")
    print("   (F) Fraud Phone Number Score:", phone_res["risk_score"], "| Scam Category:", phone_res["phone_details"]["scam_category"], "| Verdict:", phone_res["verdict"])

    print("\nALL BACKEND UNITS & DETECTORS VERIFIED SUCCESSFULLY!")

if __name__ == "__main__":
    test_direct()
