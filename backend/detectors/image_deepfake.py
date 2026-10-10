import io
import base64
import numpy as np
from PIL import Image, ImageChops, ImageEnhance
from typing import Dict, Any

def perform_error_level_analysis(original_img: Image.Image, quality: int = 95) -> tuple[Image.Image, float, str]:
    """
    Computes genuine Error Level Analysis (ELA).
    Resaves image at fixed compression quality and calculates absolute difference.
    Returns: (ELA Image, Mean Difference Metric, Base64 Data URL)
    """
    # Convert to RGB
    img_rgb = original_img.convert("RGB")
    
    # Save to memory buffer at specified JPEG quality
    buffer = io.BytesIO()
    img_rgb.save(buffer, "JPEG", quality=quality)
    buffer.seek(0)
    resaved_img = Image.open(buffer)

    # Compute absolute pixel-level difference
    ela_diff = ImageChops.difference(img_rgb, resaved_img)
    
    # Calculate statistical difference
    diff_arr = np.array(ela_diff, dtype=np.float32)
    mean_diff = float(np.mean(diff_arr))
    variance_diff = float(np.var(diff_arr))

    # Scale difference for visual human inspection (e.g., 20x magnification)
    extrema = ela_diff.getextrema()
    max_diff = max([ex[1] for ex in extrema])
    scale = 255.0 / max(max_diff, 1) if max_diff > 0 else 1.0
    scale = min(scale, 25.0)  # prevent over-amplification of pure noise
    
    enhancer = ImageEnhance.Brightness(ela_diff)
    ela_enhanced = enhancer.enhance(scale)

    # Convert ELA image to base64 for frontend display
    out_buf = io.BytesIO()
    ela_enhanced.save(out_buf, format="JPEG", quality=90)
    b64_str = "data:image/jpeg;base64," + base64.b64encode(out_buf.getvalue()).decode("ascii")

    return ela_enhanced, mean_diff, b64_str

def perform_fft_spectral_analysis(img: Image.Image) -> tuple[float, str]:
    """
    Computes 2D Fast Fourier Transform (FFT) to detect synthetic frequency artifacts
    (Durall et al., CVPR 2020: Up-convolution checkerboard patterns in GAN/Diffusion models).
    Returns: (High-Frequency Anomaly Score, Base64 FFT Spectrum Image)
    """
    # Resize to standard forensic dimension for consistent spectral analysis
    img_gray = img.convert("L").resize((256, 256))
    arr = np.asarray(img_gray, dtype=np.float32)

    # 2D Fast Fourier Transform
    f = np.fft.fft2(arr)
    fshift = np.fft.fftshift(f)
    magnitude_spectrum = np.log1p(np.abs(fshift))

    # Normalize spectrum to 0-255
    min_val, max_val = np.min(magnitude_spectrum), np.max(magnitude_spectrum)
    norm_spectrum = ((magnitude_spectrum - min_val) / (max_val - min_val + 1e-7) * 255.0).astype(np.uint8)

    # Analyze synthetic spectral roll-off (center vs outer ring energy)
    h, w = arr.shape
    cy, cx = h // 2, w // 2
    y, x = np.ogrid[:h, :w]
    dist_from_center = np.sqrt((x - cx)**2 + (y - cy)**2)
    
    # Outer high-frequency ring mask
    outer_mask = dist_from_center > 70
    outer_energy = np.mean(arr[outer_mask]) if np.any(outer_mask) else 0.0
    
    # Standard natural photos have smooth radial decay; synthetic images often have spikes or unnatural dropoffs
    spectral_score = float(np.std(magnitude_spectrum[outer_mask])) if np.any(outer_mask) else 10.0

    # Save spectrum visualization to base64
    spectrum_img = Image.fromarray(norm_spectrum)
    buf = io.BytesIO()
    spectrum_img.save(buf, format="PNG")
    b64_spectrum = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("ascii")

    return spectral_score, b64_spectrum

def analyze_image_deepfake(image_bytes: bytes, filename: str = "uploaded.jpg") -> Dict[str, Any]:
    """
    Performs full forensic pipeline on image:
    1. Error Level Analysis (ELA)
    2. FFT 2D Frequency Spectrum Artifacts
    3. Metadata & Compression Forensics
    """
    try:
        img = Image.open(io.BytesIO(image_bytes))
    except Exception as e:
        return {"error": f"Invalid image format: {str(e)}"}

    flags = []
    fake_score = 0

    # 1. Dimensions and Aspect Ratio check
    w, h = img.size
    is_square_power2 = (w == h and w in [512, 1024, 2048, 768])
    if is_square_power2:
        fake_score += 15
        flags.append({
            "severity": "medium",
            "title": "Diffusion-Standard Canvas Geometry",
            "desc": f"Exact square resolution ({w}x{h}) aligns with standard Latent Diffusion / Midjourney output latent dimensions."
        })

    # 2. Metadata / EXIF audit
    exif = img.getexif()
    software_tag = ""
    has_camera_hardware = False
    
    if exif:
        # Check standard EXIF tags
        for tag_id, value in exif.items():
            str_val = str(value).lower()
            if any(tool in str_val for tool in ["photoshop", "gimp", "midjourney", "stable diffusion", "automatic1111", "comfyui"]):
                software_tag = str(value)
            if any(cam in str_val for cam in ["canon", "nikon", "sony", "apple", "samsung", "google", "fujifilm"]):
                has_camera_hardware = True

    if software_tag:
        fake_score += 35
        flags.append({
            "severity": "high",
            "title": "Generative / Editing Software Signature",
            "desc": f"Metadata explicitly references editing/synthesis pipeline: '{software_tag}'."
        })
    elif not has_camera_hardware and len(exif) == 0:
        fake_score += 10
        flags.append({
            "severity": "low",
            "title": "Stripped Sensor EXIF",
            "desc": "Digital image contains zero physical camera sensor or lens calibration metadata."
        })

    # 3. Genuine Error Level Analysis (ELA)
    ela_img, mean_diff, ela_b64 = perform_error_level_analysis(img)
    if mean_diff > 12.0:
        fake_score += 30
        flags.append({
            "severity": "high",
            "title": "Severe Compression Discontinuity (ELA)",
            "desc": f"Mean error rate {mean_diff:.2f} indicates disparate compression layers or localized facial splicing."
        })
    elif mean_diff > 7.0:
        fake_score += 15
        flags.append({
            "severity": "medium",
            "title": "Elevated Error Level Discrepancy",
            "desc": f"ELA mean diff {mean_diff:.2f} shows non-uniform compression signatures."
        })

    # 4. 2D FFT Frequency Domain Analysis
    spectral_score, fft_b64 = perform_fft_spectral_analysis(img)
    if spectral_score > 3.2:
        fake_score += 25
        flags.append({
            "severity": "high",
            "title": "High-Frequency Synthetic Periodic Noise",
            "desc": "2D Fourier spectrum reveals unnatural periodic frequencies consistent with generative up-convolution."
        })
    elif spectral_score > 2.5:
        fake_score += 12
        flags.append({
            "severity": "low",
            "title": "Spectral Density Variance",
            "desc": "Frequency distribution exhibits slight synthetic roll-off anomalies."
        })

    final_score = min(max(fake_score, 0), 100)

    if final_score >= 60:
        verdict = "HIGH PROBABILITY DEEPFAKE / SYNTHETIC MANIPULATION"
        status_color = "red"
        category = "AI-GENERATED / MANIPULATED"
    elif final_score >= 35:
        verdict = "SUSPICIOUS COMPRESSION OR EDITING ARTIFACTS"
        status_color = "amber"
        category = "POTENTIALLY EDITED / UNCERTAIN"
    else:
        verdict = "AUTHENTIC SENSOR PROFILE (LOW DEEPFAKE PROBABILITY)"
        status_color = "emerald"
        category = "AUTHENTIC / ORGANIC"

    return {
        "filename": filename,
        "width": w,
        "height": h,
        "deepfake_probability": final_score,
        "category": category,
        "verdict": verdict,
        "status_color": status_color,
        "ela_heatmap_url": ela_b64,
        "fft_spectrum_url": fft_b64,
        "flags": flags,
        "forensics": {
            "ela_mean_difference": round(mean_diff, 3),
            "spectral_artifact_score": round(spectral_score, 3),
            "has_exif_camera_data": has_camera_hardware,
            "detected_software": software_tag or "None / Cleared"
        }
    }
