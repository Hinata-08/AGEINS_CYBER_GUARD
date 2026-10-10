import sys
import os
from pathlib import Path
from fastapi.testclient import TestClient

_current_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_current_dir))

from main import app

client = TestClient(app)

def test_all():
    print("1. Testing Health Endpoint...")
    r = client.get("/api/health")
    assert r.status_code == 200
    print("   Health OK:", r.json())

    print("\n2. Testing User Registration & Login...")
    user_email = f"testuser_{os.urandom(3).hex()}@example.com"
    r = client.post("/api/auth/register", json={"username": "Test User", "email": user_email, "password": "password123"})
    assert r.status_code == 200
    user_data = r.json()
    user_token = user_data["token"]
    print("   User Registration OK:", user_data["user"]["email"])

    print("\n3. Testing Organiser Login...")
    r = client.post("/api/auth/login", json={"email": "admin@ageins.com", "password": "admin123"})
    assert r.status_code == 200
    admin_data = r.json()
    admin_token = admin_data["token"]
    assert admin_data["user"]["role"] == "admin"
    print("   Organiser Admin Login OK!")

    print("\n4. Testing Organiser Security Protection (Regular User Accessing User Login Data -> 403)...")
    r = client.get("/api/admin/users", headers={"Authorization": f"Bearer {user_token}"})
    assert r.status_code == 403
    print("   Security Protection Working! Regular user blocked with 403 Forbidden.")

    print("\n5. Testing Organiser Fetching User Login Data (Admin -> 200)...")
    r = client.get("/api/admin/users", headers={"Authorization": f"Bearer {admin_token}"})
    assert r.status_code == 200
    users_list = r.json()
    assert len(users_list) >= 2
    print("   Organiser User Login Data fetched successfully:", len(users_list), "registered users.")

    print("\n6. Testing 7 Specialized Detection Dashboards...")
    
    # (A) URL Scan
    r = client.post("/api/scan/url", json={"content": "https://paypal-security-update-99.xyz/login"})
    assert r.status_code == 200
    url_res = r.json()
    print("   (A) URL Phishing Scan Score:", url_res["score"], "| Tier:", url_res["risk_level"])

    # (B) Email Scan
    r = client.post("/api/scan/email", json={"content": "URGENT: Your SBI Bank account will be blocked today. Click here to verify KYC immediately."})
    assert r.status_code == 200
    mail_res = r.json()
    print("   (B) Email Threat Scan Score:", mail_res["score"], "| Verdict:", mail_res["result"]["verdict"])

    # (C) Trust Mismatch Deepfake Scan
    r = client.post("/api/scan/trust-mismatch", data={"content": "Sample Deepfake Audio Visual Discrepancy Stream"})
    assert r.status_code == 200
    trust_res = r.json()
    print("   (C) Trust Mismatch Score:", trust_res["score"], "| Verdict:", trust_res["result"]["verdict"])

    # (D) Payment QR Scanner & Fake Scanner Detector
    r = client.post("/api/scan/payment-qr", json={"payload": "upi://pay?pa=paytm-refund-support@ybl&pn=Refund&am=5000"})
    assert r.status_code == 200
    qr_res = r.json()
    print("   (D) Payment QR Code Scanner Score:", qr_res["score"], "| Safe Steps:", qr_res["result"]["recommendations"][0])

    # (E) Fraud Bank Details & Payment Detector
    r = client.post("/api/scan/bank-details", json={"details": "Transfer Rs 500 lottery processing fee to Bank: SBI, Account: 3948291039, IFSC: SBIN0001234"})
    assert r.status_code == 200
    bank_res = r.json()
    print("   (E) Fraud Bank Details Score:", bank_res["score"], "| Flags:", len(bank_res["result"]["flags"]))

    # (F) Fraud Phone Number & SMS Detector
    r = client.post("/api/scan/phone-number", json={"number_or_text": "Electricity bill unpaid. Connection disconnect tonight at 9:30 PM. Call 9876543210"})
    assert r.status_code == 200
    phone_res = r.json()
    print("   (F) Fraud Phone Number / SMS Score:", phone_res["score"], "| Verdict:", phone_res["result"]["verdict"])

    print("\nALL FEATURE TESTS PASSED PERFECTLY! 🎉")

if __name__ == "__main__":
    test_all()
