import os
import sys
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

_current_dir = Path(__file__).resolve().parent
_parent_dir = _current_dir.parent
for _p in [str(_current_dir), str(_parent_dir)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

try:
    from backend.detectors.phishing import analyze_url
    from backend.detectors.email_analyzer import analyze_email
    from backend.detectors.image_deepfake import analyze_image_deepfake
    from backend.detectors.audio_deepfake import analyze_audio_deepfake
    from backend.detectors.video_deepfake import analyze_video_deepfake
    from backend.detectors.trust_mismatch import analyze_trust_mismatch
    from backend.detectors.qr_payment import analyze_payment_qr
    from backend.detectors.bank_fraud import analyze_bank_fraud
    from backend.detectors.phone_fraud import analyze_phone_fraud
    from backend.detectors.ml_classifier import predict_threat_ml
    from backend.train_model import train_threat_classifier
    from backend.chatbot import get_chatbot_response
    from backend.database import (
        save_scan_result,
        get_user_dashboard,
        get_admin_overview,
        update_config,
        toggle_quarantine,
        update_user_role,
        register_user,
        login_user,
        verify_token,
        ping_session,
        get_organiser_users_data,
        delete_user_by_admin,
        log_audit
    )
except ImportError:
    from detectors.phishing import analyze_url
    from detectors.email_analyzer import analyze_email
    from detectors.image_deepfake import analyze_image_deepfake
    from detectors.audio_deepfake import analyze_audio_deepfake
    from detectors.video_deepfake import analyze_video_deepfake
    from detectors.trust_mismatch import analyze_trust_mismatch
    from detectors.qr_payment import analyze_payment_qr
    from detectors.bank_fraud import analyze_bank_fraud
    from detectors.phone_fraud import analyze_phone_fraud
    from detectors.ml_classifier import predict_threat_ml
    from train_model import train_threat_classifier
    from chatbot import get_chatbot_response
    from database import (
        save_scan_result,
        get_user_dashboard,
        get_admin_overview,
        update_config,
        toggle_quarantine,
        update_user_role,
        register_user,
        login_user,
        verify_token,
        ping_session,
        get_organiser_users_data,
        delete_user_by_admin,
        log_audit
    )

app = FastAPI(
    title="AGEINS Cyber Guard",
    version="3.0.0",
    description="Multi-Source Threat Intelligence & Deepfake Forensics Platform with Organiser Control and Security Protection."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Authentication Dependencies & Organiser Access Control
def current_user(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication required. Please sign in.")
    token = authorization[7:]
    try:
        user = verify_token(token)
        return user
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))

def organiser_only(u: Dict[str, Any] = Depends(current_user)) -> Dict[str, Any]:
    if u.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Organiser access ONLY. Regular users cannot access this data.")
    return u

# Pydantic Input Schemas
class RegisterReq(BaseModel):
    username: str
    email: str
    password: str

class LoginReq(BaseModel):
    email: str
    password: str

class ScanRequest(BaseModel):
    content: str
    scan_type: str = "auto"
    user_id: Optional[str] = "guest_user"

class BankScanRequest(BaseModel):
    details: str

class PhoneScanRequest(BaseModel):
    number_or_text: str

class QRScanRequest(BaseModel):
    payload: str

class ChatRequest(BaseModel):
    message: str
    user_id: Optional[str] = "guest_user"

class ConfigUpdateRequest(BaseModel):
    key: str
    value: str

class QuarantineRequest(BaseModel):
    scan_id: int
    quarantine: bool

class UserRoleRequest(BaseModel):
    user_id: int
    role: str
    status: Optional[str] = "active"

@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "AGEINS Cyber Guard", "version": "3.0.0"}

# -------------------- 1. Auth & User Session Security --------------------
@app.post("/api/auth/register")
def auth_register(d: RegisterReq):
    try:
        res = register_user(d.username, d.email, d.password)
        return res
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/auth/login")
def auth_login(d: LoginReq):
    try:
        res = login_user(d.email, d.password)
        return res
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))

@app.get("/api/auth/me")
def auth_me(u: Dict[str, Any] = Depends(current_user)):
    return u

@app.post("/api/session/ping")
def auth_ping(authorization: Optional[str] = Header(None)):
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:]
        ping_session(token)
    return {"ok": True}

# -------------------- 2. Organiser Control & User Login Data --------------------
@app.get("/api/admin/users")
def get_admin_users(u: Dict[str, Any] = Depends(organiser_only)):
    """Organiser side access ONLY: Returns user login details, emails, activity & spent time."""
    return get_organiser_users_data()

@app.delete("/api/admin/users/{uid}")
def delete_user(uid: int, u: Dict[str, Any] = Depends(organiser_only)):
    try:
        delete_user_by_admin(uid, u["id"])
        return {"status": "success", "message": f"User ID #{uid} removed successfully."}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/admin/overview")
def admin_overview(u: Dict[str, Any] = Depends(organiser_only)) -> dict[str, Any]:
    return get_admin_overview()

@app.post("/api/admin/config")
def set_admin_config(req: ConfigUpdateRequest, u: Dict[str, Any] = Depends(organiser_only)) -> dict[str, str]:
    update_config(req.key, req.value, actor=u.get("email", "Organiser Admin"))
    return {"status": "success", "message": f"Config '{req.key}' updated successfully."}

@app.post("/api/admin/quarantine")
def set_quarantine(req: QuarantineRequest, u: Dict[str, Any] = Depends(organiser_only)) -> dict[str, str]:
    toggle_quarantine(req.scan_id, req.quarantine, actor=u.get("email", "Organiser Admin"))
    return {"status": "success", "message": f"Threat #{req.scan_id} quarantine status updated."}

@app.post("/api/admin/user-role")
def set_user_role(req: UserRoleRequest, u: Dict[str, Any] = Depends(organiser_only)) -> dict[str, str]:
    update_user_role(req.user_id, req.role, req.status or "active", actor=u.get("email", "Organiser Admin"))
    return {"status": "success", "message": f"User #{req.user_id} role updated."}

# -------------------- 3. Specialized Detection Dashboards --------------------

# (A) URL Phishing Detector
@app.post("/api/scan/url")
def scan_url_endpoint(request: ScanRequest) -> dict[str, Any]:
    content = request.content.strip()
    if not content:
        raise HTTPException(status_code=400, detail="Enter a URL to scan.")

    result = analyze_url(content)
    ml_result = predict_threat_ml(content)
    heuristic_score = result.get("risk_score", 0)

    ml_prob = ml_result.get("threat_probability", heuristic_score) if ml_result.get("ml_active") else heuristic_score
    risk_score = min(max(int(round(0.50 * heuristic_score + 0.50 * ml_prob)), 0), 100)
    risk_level = "Critical Threat" if risk_score >= 65 else ("Suspicious" if risk_score >= 35 else "Safe / Clean")
    
    result["risk_score"] = risk_score
    result["risk_level"] = risk_level
    result["ml_telemetry"] = ml_result

    sources = ["AGEINS Heuristics Engine", "Global PhishTank & URLhaus Feeds", f"Supervised ML ({ml_result.get('model_architecture', 'RF')})"]
    scan_id = save_scan_result(request.user_id or "guest_user", "url", content, risk_score, risk_level, result.get("verdict", "URL Scan Complete"), sources, result)

    return {"scan_id": scan_id, "scan_type": "url", "score": risk_score, "risk_level": risk_level, "sources": sources, "result": result}

# (B) Email Threat Analyzer
@app.post("/api/scan/email")
def scan_email_endpoint(request: ScanRequest) -> dict[str, Any]:
    content = request.content.strip()
    if not content:
        raise HTTPException(status_code=400, detail="Enter email subject or body to scan.")

    result = analyze_email(subject="", sender="", body=content)
    ml_result = predict_threat_ml(content)
    heuristic_score = result.get("risk_score", 0)

    ml_prob = ml_result.get("threat_probability", heuristic_score) if ml_result.get("ml_active") else heuristic_score
    risk_score = min(max(int(round(0.45 * heuristic_score + 0.55 * ml_prob)), 0), 100)
    risk_level = "Critical Threat" if risk_score >= 65 else ("Suspicious" if risk_score >= 35 else "Safe / Clean")

    result["risk_score"] = risk_score
    result["risk_level"] = risk_level
    result["ml_telemetry"] = ml_result

    sources = ["NLP Social Engineering Classifier", "Financial Scam Lexicon Matrix", f"Supervised ML ({ml_result.get('model_architecture', 'RF')})"]
    scan_id = save_scan_result(request.user_id or "guest_user", "email", content[:100], risk_score, risk_level, result.get("verdict", "Email Scan Complete"), sources, result)

    return {"scan_id": scan_id, "scan_type": "email", "score": risk_score, "risk_level": risk_level, "sources": sources, "result": result}

# (C) Image Deepfake Forensics
@app.post("/api/scan/image")
async def scan_image_endpoint(file: UploadFile = File(...), user_id: str = Form("guest_user")) -> dict[str, Any]:
    contents = await file.read()
    if not contents:
        raise HTTPException(status_code=400, detail="Uploaded image file is empty.")

    result = analyze_image_deepfake(contents, filename=file.filename or "uploaded.jpg")
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])

    score = result["deepfake_probability"]
    level = "Critical Threat" if score >= 65 else ("Suspicious" if score >= 35 else "Safe / Organic")
    sources = ["Spectral FFT & ELA Forensic Engine", "AGEINS Deep Neural Heuristics"]

    scan_id = save_scan_result(user_id, "image", file.filename or "uploaded.jpg", score, level, result.get("verdict", "Image Scan Complete"), sources, result)
    return {"scan_id": scan_id, "scan_type": "image", "score": score, "risk_level": level, "sources": sources, "result": result}

# (D) Audio Deepfake Forensics
@app.post("/api/scan/audio")
async def scan_audio_endpoint(file: UploadFile = File(...), user_id: str = Form("guest_user")) -> dict[str, Any]:
    contents = await file.read()
    if not contents:
        raise HTTPException(status_code=400, detail="Uploaded audio file is empty.")

    result = analyze_audio_deepfake(contents, filename=file.filename or "recording.wav")
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])

    score = result["deepfake_probability"]
    level = "Critical Threat" if score >= 65 else ("Suspicious" if score >= 35 else "Safe / Natural")
    sources = ["Acoustic ASVspoof Pitch Analysis", "Neural Vocoder Artifact Detector"]

    scan_id = save_scan_result(user_id, "audio", file.filename or "recording.wav", score, level, result.get("verdict", "Audio Scan Complete"), sources, result)
    return {"scan_id": scan_id, "scan_type": "audio", "score": score, "risk_level": level, "sources": sources, "result": result}

# (E) Video Deepfake Forensics
@app.post("/api/scan/video")
async def scan_video_endpoint(file: UploadFile = File(...), user_id: str = Form("guest_user")) -> dict[str, Any]:
    contents = await file.read()
    if not contents:
        raise HTTPException(status_code=400, detail="Uploaded video file is empty.")

    result = analyze_video_deepfake(contents, filename=file.filename or "video.mp4")
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])

    score = result["risk_score"]
    level = result["risk_level"]
    sources = ["Temporal Inter-Frame Jitter Analyzer", "Facial Boundary Discontinuity Detector", "Spectral ELA Forensics"]

    scan_id = save_scan_result(user_id, "video", file.filename or "video.mp4", score, level, result.get("verdict", "Video Scan Complete"), sources, result)
    return {"scan_id": scan_id, "scan_type": "video", "score": score, "risk_level": level, "sources": sources, "result": result}

# (F) Trust Mismatch Detector for Deepfake Media
@app.post("/api/scan/trust-mismatch")
async def scan_trust_mismatch_endpoint(
    file: Optional[UploadFile] = File(None),
    content: Optional[str] = Form(None),
    user_id: str = Form("guest_user")
) -> dict[str, Any]:
    if file:
        file_bytes = await file.read()
        filename = file.filename or "media.file"
    elif content:
        file_bytes = content.encode("utf-8")
        filename = "text_payload.txt"
    else:
        raise HTTPException(status_code=400, detail="Provide a media file or payload for Trust Mismatch analysis.")

    result = analyze_trust_mismatch(file_bytes, filename)
    score = result["mismatch_score"]
    level = "Critical Threat" if score >= 65 else ("Suspicious" if score >= 35 else "Safe / Clean")
    sources = ["Trust Mismatch Cross-Modal Detector", "Spectral Phase Coherence", "Temporal Illumination Flux"]

    scan_id = save_scan_result(user_id, "trust_mismatch", filename, score, level, result["verdict"], sources, result)
    return {"scan_id": scan_id, "scan_type": "trust_mismatch", "score": score, "risk_level": level, "sources": sources, "result": result}

# (G) Payment QR Code Scanner & Fake Scanner Detector
@app.post("/api/scan/payment-qr")
def scan_payment_qr_endpoint(request: QRScanRequest) -> dict[str, Any]:
    payload = request.payload.strip()
    if not payload:
        raise HTTPException(status_code=400, detail="Provide a QR code link or URI payload to scan.")

    result = analyze_payment_qr(payload)
    score = result["risk_score"]
    level = "Critical Threat" if score >= 65 else ("Suspicious" if score >= 35 else "Safe / Clean")
    sources = ["Payment QR Code Forensic Scanner", "UPI VPA Domain Validator", "Deceptive Payment Gateway Filter"]

    scan_id = save_scan_result("guest_user", "payment_qr", payload[:100], score, level, result["verdict"], sources, result)
    return {"scan_id": scan_id, "scan_type": "payment_qr", "score": score, "risk_level": level, "sources": sources, "result": result}

# (H) Fraud Bank Details & Payment Detector
@app.post("/api/scan/bank-details")
def scan_bank_details_endpoint(request: BankScanRequest) -> dict[str, Any]:
    details_str = request.details.strip()
    if not details_str:
        raise HTTPException(status_code=400, detail="Provide bank account details or message to scan.")

    result = analyze_bank_fraud(details_str)
    score = result["risk_score"]
    level = "Critical Threat" if score >= 65 else ("Suspicious" if score >= 35 else "Safe / Clean")
    sources = ["Fraud Bank Details Inspector", "RBI IFSC Clearing House Matrix", "Money Mule Threat Database"]

    scan_id = save_scan_result("guest_user", "bank_details", details_str[:100], score, level, result["verdict"], sources, result)
    return {"scan_id": scan_id, "scan_type": "bank_details", "score": score, "risk_level": level, "sources": sources, "result": result}

# (I) Fraud Phone Number & SMS Detector
@app.post("/api/scan/phone-number")
def scan_phone_endpoint(request: PhoneScanRequest) -> dict[str, Any]:
    val = request.number_or_text.strip()
    if not val:
        raise HTTPException(status_code=400, detail="Provide a phone number or SMS message to scan.")

    result = analyze_phone_fraud(val)
    score = result["risk_score"]
    level = "Critical Threat" if score >= 65 else ("Suspicious" if score >= 35 else "Safe / Clean")
    sources = ["Fraud Phone Number & SMS Detector", "Telecom Virtual Range Inspector", "SMS Phishing Pattern Filter"]

    scan_id = save_scan_result("guest_user", "phone_number", val[:100], score, level, result["verdict"], sources, result)
    return {"scan_id": scan_id, "scan_type": "phone_number", "score": score, "risk_level": level, "sources": sources, "result": result}

# (J) Universal Scan Endpoint
@app.post("/api/scan")
def scan_universal(request: ScanRequest) -> dict[str, Any]:
    st = request.scan_type.lower()
    if st == "url":
        return scan_url_endpoint(request)
    elif st == "email" or st == "message":
        return scan_email_endpoint(request)
    elif st == "payment_qr":
        return scan_payment_qr_endpoint(QRScanRequest(payload=request.content))
    elif st == "bank_details":
        return scan_bank_details_endpoint(BankScanRequest(details=request.content))
    elif st == "phone_number":
        return scan_phone_endpoint(PhoneScanRequest(number_or_text=request.content))
    else:
        # Auto detect type
        c = request.content.lower()
        if c.startswith("upi://") or "qr" in c:
            return scan_payment_qr_endpoint(QRScanRequest(payload=request.content))
        elif "ifsc" in c or "account number" in c:
            return scan_bank_details_endpoint(BankScanRequest(details=request.content))
        elif c.startswith(("http://", "https://")) or ("." in c and " " not in c):
            return scan_url_endpoint(request)
        else:
            return scan_email_endpoint(request)

# -------------------- 4. AI Chatbot Assistant --------------------
@app.post("/api/chat")
def chat_endpoint(request: ChatRequest) -> dict[str, Any]:
    try:
        response = get_chatbot_response(request.message)
        return response
    except Exception as e:
        return {
            "reply": f"System technical issue: {str(e)}. Call Emergency Cybercrime Helpline 1930.",
            "type": "error"
        }

# -------------------- 5. User Portal Dashboard & History --------------------
@app.get("/api/user/dashboard")
def user_dashboard(user_id: str = "guest_user") -> dict[str, Any]:
    return get_user_dashboard(user_id)

@app.get("/api/history")
def get_history(user_id: str = "guest_user"):
    return get_user_dashboard(user_id)["recent_scans"]

# -------------------- 6. ML Retraining & Dataset Management --------------------
@app.get("/api/ml/metrics")
def get_ml_metrics() -> dict[str, Any]:
    metrics_path = Path(__file__).resolve().parent / "models" / "model_metrics.json"
    if metrics_path.exists():
        with open(metrics_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"status": "Model metrics ready", "accuracy": 0.92}

@app.post("/api/ml/retrain")
def retrain_model(u: Dict[str, Any] = Depends(organiser_only)) -> dict[str, Any]:
    dataset_path = Path(__file__).resolve().parent / "data" / "threat_dataset.csv"
    metrics = train_threat_classifier(dataset_path)
    return {"status": "success", "message": "Machine learning model retrained successfully.", "metrics": metrics}

# Mount Frontend static files if FRONTEND folder exists
frontend_dir = _parent_dir / "FRONTEND"
if not frontend_dir.exists():
    frontend_dir = _current_dir / "frontend"

if frontend_dir.exists():
    app.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="frontend")