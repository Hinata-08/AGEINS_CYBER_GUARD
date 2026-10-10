import re
from typing import Dict, Any, List
try:
    from backend.detectors.phishing import analyze_url
    from backend.detectors.email_analyzer import analyze_email
except ImportError:
    from detectors.phishing import analyze_url
    from detectors.email_analyzer import analyze_email

SYSTEM_KNOWLEDGE = {
    "emergency": {
        "keywords": ["scam ho gaya", "fraud ho gaya", "paise kat gaye", "cheated", "hacked", "money debited", "unauthorized transaction", "lost money", "police report"],
        "reply": """🚨 **Emergency Cyber Security Action Protocol (तत्काल कदम)**:
1. **Immediate Banking Freeze**: Apne bank customer care ko call karke affected debit/credit card ya netbanking/UPI ko turant block karwayen.
2. **National Cyber Crime Helpline (India)**: Dial **1930** immediately ya visit karein [cybercrime.gov.in](https://cybercrime.gov.in) par official complaint darj karein. Golden hours (pehle 2-3 ghante) me call karne se paise recover hone ke chances sabse zyada hote hain.
3. **Evidence Preserve Karein**: Fraud message, payment screenshot, transaction UTR ID, caller phone number aur phishing URL ka screenshot save karke rakhein.
4. **Passcodes Change Karein**: Apne email aur banking passwords ko kisi clean device se turant reset karein aur 2FA (Two-Factor Authentication) activate karein."""
    },
    "digital_arrest": {
        "keywords": ["digital arrest", "police call", "cbi", "ed officer", "customs arrest", "skype call police"],
        "reply": """⚠️ **Digital Arrest Scam Alert**:
Indian Law Enforcement (Police, CBI, ED, Customs, Supreme Court) **kabhi bhi video call ya phone par 'Digital Arrest' nahi karti**. Yeh 100% fraud racket hai!
- **Karein**: Call turant disconnect karein aur bilkul na darein.
- **Na karein**: Kisi bhi verification account me paise transfer na karein.
- **Report**: Dial **1930** ya local police cyber cell ko report karein."""
    },
    "deepfake_info": {
        "keywords": ["deepfake", "synthetic video", "ai voice clone", "fake voice", "voice cloning", "image deepfake", "video deepfake"],
        "reply": """🎭 **Deepfake & AI Synthetic Media Detection**:
AGEINS platform 3 forensic engines use karta hai deepfake identify karne ke liye:
1. **Image Deepfakes**: **Error Level Analysis (ELA)** aur **2D FFT Frequency Spectrum** se generative model (diffusion/GAN) ke upsampling checkerboard patterns aur synthetic noise detect karta hai.
2. **Voice Cloning / Audio**: Neural vocoder (HiFi-GAN/VITS) ke over-smoothed pitch micro-tremors aur unnatural zero-silence acoustic room noise detect karta hai.
3. **Video Deepfakes**: Inter-frame temporal jitter, face-boundary warping, aur facial blending compression discrepancies check karta hai.
💡 *Tip: Aap hamare 'Threat Detection' section me image, audio ya video upload karke full forensic spectrum analysis dekh sakte hain!*"""
    },
    "phishing_info": {
        "keywords": ["phishing kya hai", "what is phishing", "link safe", "fake link", "typosquatting", "url check"],
        "reply": """🎣 **Phishing & Malicious Link Protection**:
Phishing ek aisi technique hai jisme attackers fake websites bana kar aapke banking credentials, passwords ya personal information churane ki koshish karte hain.
- **Pehchanne ke tarike**:
  - Domain spelling check karein (e.g. `paypa1.com` instead of `paypal.com` - Typosquatting).
  - Suspicious TLDs jaise `.xyz`, `.top`, `.buzz`, `.tk`.
  - HTTP vs HTTPS (unencrypted connection).
  - Unsolicited lottery, KYC update, ya electric bill disconnection ki fake warnings.
💡 *Aap koi bhi link chat me paste karke 'Check link: <url>' likh sakte hain ya Scanner me daal sakte hain.*"""
    },
    "privacy_protection": {
        "keywords": ["data protect", "privacy", "data safe", "data leak", "anonymity", "security of data"],
        "reply": """🛡️ **AGEINS Data Protection & Privacy Architecture**:
Aapka data AGEINS par fully protected rehta hai:
1. **Zero-Knowledge Forensics**: Scanned files & messages ko analyze karne ke baad memory se turant flush kar diya jata hai.
2. **SHA-256 Hashing**: Scanned content ko plain text me store nahi kiya jata; cryptographic hashes use hote hain.
3. **Role-Based Access Control (RBAC)**: Administrator, Analyst aur User data isolated rehta hai.
4. **Client-Side Privacy Shield**: User sensitive PII (Phone numbers, PAN/Card numbers) scan se pehle mask kar sakta hai."""
    }
}

def get_chatbot_response(user_message: str) -> Dict[str, Any]:
    msg = user_message.strip()
    msg_lower = msg.lower()

    if not msg:
        return {
            "reply": "Namaste! Main AGEINS Cyber AI Assistant hoon. Aap mujhse Cyber threats, Phishing links, Deepfake videos/audios, ya Scam prevention ke baare me koi bhi sawal pooch sakte hain.",
            "type": "greeting",
            "suggested_actions": ["Check a suspicious link", "How to identify deepfakes", "Report cyber crime", "What is phishing?"]
        }

    # 1. Direct URL Scan Query inside Chatbot
    url_match = re.search(r'(https?://[^\s]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?)', msg)
    if "check" in msg_lower or "scan" in msg_lower or "link" in msg_lower or "url" in msg_lower or (url_match and len(msg.split()) <= 4):
        target_candidate = url_match.group(0) if url_match else msg
        if "." in target_candidate and not " " in target_candidate.strip():
            url_res = analyze_url(target_candidate)
            risk = url_res.get("risk_score", 0)
            level = url_res.get("risk_level", "Unknown")
            verdict = url_res.get("verdict", "")
            advice = url_res.get("recommendation", "")
            
            reply_text = f"🔍 **AGEINS Instant Threat Scan Result** for `{target_candidate}`:\n\n"
            reply_text += f"- **Threat Score**: `{risk}%` ({level})\n"
            reply_text += f"- **Verdict**: {verdict}\n"
            reply_text += f"- **Guidance**: {advice}\n\n"
            if url_res.get("flags"):
                reply_text += "**Detected Threat Signals**:\n"
                for f in url_res["flags"][:3]:
                    reply_text += f"• **{f.get('title')}**: {f.get('desc')}\n"
            
            return {
                "reply": reply_text,
                "type": "scan_result",
                "score": risk,
                "risk_level": level,
                "suggested_actions": ["Scan another URL", "Test Deepfake Detector", "How to block this domain?"]
            }

    # 2. Check for Knowledge Base Topics
    for category, item in SYSTEM_KNOWLEDGE.items():
        if any(kw in msg_lower for kw in item["keywords"]):
            return {
                "reply": item["reply"],
                "type": category,
                "suggested_actions": ["Emergency helpline 1930", "Test image deepfake", "Scan suspicious message", "Data privacy policy"]
            }

    # 3. Message / Email Scam Check
    if any(k in msg_lower for k in ["kyc", "lottery", "prize", "winner", "reward", "urgent account", "electricity bill", "part time job", "telegram task"]):
        email_res = analyze_email(subject="", sender="", body=msg)
        risk = email_res.get("risk_score", 0)
        return {
            "reply": f"""⚠️ **Fraud & Social Engineering Analysis**:
- **Risk Score**: `{risk}%` ({email_res.get('risk_level', 'Warning')})
- **Verdict**: {email_res.get('verdict', 'Suspicious Message')}
- **Advice**: {email_res.get('advice', 'Do not reply or share sensitive credentials.')}

**Kyu suspicious hai?**
Is message me urgency, financial lures ya impersonation ke indicators detect hue hain. Kabhi bhi kisi unknown sender ke link par click na karein aur OTP share na karein.""",
            "type": "message_scan",
            "score": risk,
            "suggested_actions": ["Report to 1930", "Scan another message", "Learn scam indicators"]
        }

    # 4. General Cyber Security Assistant Response
    return {
        "reply": f"""Main aapki cyber security me poori madad karne ke liye taiyar hoon! 
Aapke sawal: *"{msg}"* ke sandarbh me:

Aap AGEINS me yeh sab check kar sakte hain:
1. **Phishing & Fraud URLs**: Kisi bhi suspicious website link ka risk score check karein.
2. **Deepfake Media (Image, Audio, Video)**: AI-generated fake media forensic inspection ELA aur FFT spectrum ke sath.
3. **Scam Messages & Emails**: Urgent lottery, bank KYC fraud, aur social engineering messages ki checking.
4. **Data Privacy Protection**: Zero-knowledge and encrypted threat telemetry.

Agar aapke sath koi online dhokhadhadi hui hai, to **1930** cyber crime helpline par call karein.""",
        "type": "general_help",
        "suggested_actions": ["Scan a URL", "Deepfake detection guide", "Check an SMS message", "Admin dashboard access"]
    }
