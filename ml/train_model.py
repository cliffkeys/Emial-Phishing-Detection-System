import os
import json
from pathlib import Path
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report

try:
    from ml.preprocessing import clean_email_text
except ImportError:
    from preprocessing import clean_email_text



def train_spam_classifier(data_path: str = None, models_dir: str = None):
    """
    Trains the TF-IDF + Classifier Machine Learning Pipeline for spam detection.
    Saves trained vectorizer, model, and metrics JSON to models directory.
    """
    base_dir = Path(__file__).resolve().parent.parent
    if data_path is None:
        data_path = base_dir / "data" / "sample_emails.csv"
    if models_dir is None:
        models_dir = base_dir / "models"
    else:
        models_dir = Path(models_dir)

    models_dir.mkdir(parents=True, exist_ok=True)

    print("=================================================================")
    print(" MAILSHIELD ML PIPELINE: SPAM & PHISHING CLASSIFIER TRAINING")
    print("=================================================================")
    print(f"[*] Loading dataset from: {data_path}")

    if not os.path.exists(data_path):
        raise FileNotFoundError(f"Dataset not found at {data_path}")

    df = pd.read_csv(data_path)
    print(f"[+] Loaded {len(df)} total samples.")
    print("[+] Class distribution:")
    print(df["label"].value_counts())

    # Map labels: ham -> 0 (Legitimate), spam/phishing -> 1 (Spam/Malicious)
    # Both spam and phishing are categorized as malicious/unwanted in the binary text classifier,
    # with dedicated phishing rules resolving the distinction in the Hybrid Risk Engine.
    df["binary_label"] = df["label"].apply(lambda x: 0 if str(x).strip().lower() == "ham" else 1)

    # Combine subject + body for full contextual NLP features
    df["full_text"] = df["subject"].fillna("") + " " + df["body"].fillna("")
    print("[*] Preprocessing and normalizing text...")
    df["cleaned_text"] = df["full_text"].apply(clean_email_text)

    X = df["cleaned_text"]
    y = df["binary_label"]

    # Stratified Train/Test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    print(f"[+] Split: {len(X_train)} training samples, {len(X_test)} test samples.")

    # TF-IDF Feature Extraction with unigrams and bigrams
    print("[*] Vectorizing with TF-IDF (n-gram (1,2), sublinear TF scaling)...")
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=2500,
        sublinear_tf=True,
        min_df=1
    )
    X_train_tfidf = vectorizer.fit_transform(X_train)
    X_test_tfidf = vectorizer.transform(X_test)

    # Classifier: Multinomial Naive Bayes with Laplace smoothing
    print("[*] Training Multinomial Naive Bayes Classifier...")
    model = MultinomialNB(alpha=0.1)
    model.fit(X_train_tfidf, y_train)

    # Evaluation
    y_pred = model.predict(X_test_tfidf)
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred).tolist()

    print("\n-----------------------------------------------------------------")
    print(" MODEL PERFORMANCE METRICS (TEST SET)")
    print("-----------------------------------------------------------------")
    print(f" Accuracy : {acc * 100:.2f}%")
    print(f" Precision: {prec * 100:.2f}%")
    print(f" Recall   : {rec * 100:.2f}%")
    print(f" F1-Score : {f1 * 100:.2f}%")
    print(f" Confusion Matrix (TN, FP / FN, TP):\n {cm}")
    print("-----------------------------------------------------------------")

    # Serialize artifacts
    vec_path = models_dir / "spam_vectorizer.pkl"
    model_path = models_dir / "spam_classifier.pkl"
    metrics_path = models_dir / "evaluation_metrics.json"

    print(f"[*] Saving vectorizer artifact to: {vec_path}")
    joblib.dump(vectorizer, vec_path)

    print(f"[*] Saving model artifact to: {model_path}")
    joblib.dump(model, model_path)

    metrics_payload = {
        "model_type": "Multinomial Naive Bayes + TF-IDF (1,2 n-grams)",
        "train_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "total_samples": int(len(df)),
        "vocabulary_size": int(len(vectorizer.vocabulary_)),
        "accuracy": round(float(acc), 4),
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1_score": round(float(f1), 4),
        "confusion_matrix": cm,
        "classes": ["Legitimate (Ham)", "Spam / Malicious"],
    }

    with open(metrics_path, "w") as f:
        json.dump(metrics_payload, f, indent=4)
    print(f"[+] Saved evaluation metrics to: {metrics_path}")
    print("[✔] Machine Learning training complete successfully!")
    return metrics_payload


if __name__ == "__main__":
    train_spam_classifier()
