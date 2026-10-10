import os
import sys
import argparse
import json
import csv
from pathlib import Path
import numpy as np

# Setup paths
CURRENT_DIR = Path(__file__).resolve().parent
DATA_DIR = CURRENT_DIR / "data"
MODELS_DIR = CURRENT_DIR / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_DATASET = DATA_DIR / "threat_dataset.csv"
MODEL_FILE = MODELS_DIR / "threat_classifier.joblib"
METRICS_FILE = MODELS_DIR / "model_metrics.json"

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import joblib

def load_dataset(csv_path: Path):
    texts = []
    labels = []
    categories = []

    with open(csv_path, mode="r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            txt = row.get("text", "").strip()
            lbl = row.get("label", "").strip()
            cat = row.get("category", "unknown").strip()
            if txt and lbl in ["0", "1"]:
                texts.append(txt)
                labels.append(int(lbl))
                categories.append(cat)

    return texts, np.array(labels), categories

def train_threat_classifier(dataset_path: Path = DEFAULT_DATASET):
    print("=" * 65)
    print("AGEINS Cyber Security - Machine Learning Model Training Engine")
    print("BPUT Hackathon PS-9: AI-Powered Phishing & Impersonation Defense")
    print("=" * 65)
    print(f"[1/5] Loading training dataset from: {dataset_path}")

    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset not found at {dataset_path}")

    texts, labels, categories = load_dataset(dataset_path)
    print(f"      Total Samples: {len(texts)} (Threats: {sum(labels)}, Legitimate: {len(labels) - sum(labels)})")

    if len(texts) < 10:
        raise ValueError("Dataset is too small (minimum 10 samples required).")

    # Split dataset
    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.20, random_state=42, stratify=labels
    )
    print(f"[2/5] Stratified Split: {len(X_train)} Train samples, {len(X_test)} Test samples")

    # Compare Candidate ML Models
    print("[3/5] Benchmarking Classifiers with Character + Subword TF-IDF...")
    tfidf = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        max_features=3500,
        sublinear_tf=True
    )

    candidates = {
        "Random Forest Classifier": RandomForestClassifier(n_estimators=150, max_depth=20, random_state=42, n_jobs=-1),
        "Calibrated Logistic Regression": LogisticRegression(C=5.0, max_iter=500, random_state=42)
    }

    best_name = None
    best_pipeline = None
    best_cv = -1.0

    for name, clf in candidates.items():
        pipe = Pipeline([("tfidf", tfidf), ("classifier", clf)])
        cv_scores = cross_val_score(pipe, texts, labels, cv=5)
        cv_mean = float(np.mean(cv_scores))
        print(f"      Candidate: {name:32} | 5-Fold Cross-Val Accuracy: {cv_mean * 100:.2f}%")

        if cv_mean > best_cv:
            best_cv = cv_mean
            best_name = name
            best_pipeline = pipe

    print(f"\n[4/5] Selected Best Model: {best_name} (Cross-Validation: {best_cv * 100:.2f}%)")

    # Train winning pipeline on train split
    best_pipeline.fit(X_train, y_train)

    # Evaluate on held-out test split
    y_pred = best_pipeline.predict(X_test)
    y_prob = best_pipeline.predict_proba(X_test)[:, 1]

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    conf_mat = confusion_matrix(y_test, y_pred).tolist()

    print("\n" + "=" * 65)
    print("FINAL MODEL EVALUATION METRICS (Report for Hackathon Presentation)")
    print("=" * 65)
    print(f"Architecture:            {best_name}")
    print(f"Test Accuracy:           {acc * 100:.2f}%")
    print(f"Cross-Validation Score:  {best_cv * 100:.2f}%")
    print(f"Precision Score:         {prec * 100:.2f}%")
    print(f"Recall (Sensitivity):    {rec * 100:.2f}%")
    print(f"F1-Score (Harmonic Mean):{f1 * 100:.2f}%")
    print(f"Confusion Matrix:        {conf_mat}")
    print("=" * 65)

    # Save trained pipeline and metrics
    print(f"\n[5/5] Exporting model weights to: {MODEL_FILE}")
    joblib.dump(best_pipeline, MODEL_FILE)

    metrics = {
        "model_architecture": best_name,
        "feature_extractor": "Char-WB TF-IDF (N-gram 3-5, 3500 Features)",
        "accuracy": round(acc, 4),
        "cross_val_accuracy": round(best_cv, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "confusion_matrix": conf_mat,
        "total_dataset_size": len(texts),
        "training_samples": len(X_train),
        "test_samples": len(X_test),
        "dataset_source": str(dataset_path.name)
    }

    with open(METRICS_FILE, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=4)

    print(f"      Metrics successfully saved to: {METRICS_FILE}")
    print("\nSUCCESS: Machine Learning Model training completed successfully!\n")
    return metrics

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train AGEINS Cyber Security Threat ML Model")
    parser.add_argument("--csv", type=str, default=str(DEFAULT_DATASET), help="Path to custom training CSV dataset")
    args = parser.parse_args()

    train_threat_classifier(Path(args.csv))
