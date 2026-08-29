import os
import json
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, Any, Optional
import joblib

from .preprocessing import clean_email_text


@dataclass
class MLPredictionResult:
    """Result of Machine Learning Spam/Ham prediction."""
    is_spam: bool = False
    spam_probability: float = 0.0  # 0.0 to 100.0 %
    ham_probability: float = 100.0  # 0.0 to 100.0 %
    confidence: float = 0.0  # Confidence percentage
    is_model_loaded: bool = False
    status_message: str = "Model loaded successfully."


class ModelManager:
    """
    Manages loading, caching, inference, and performance reporting of the ML spam classifier.
    """
    _instance: Optional["ModelManager"] = None
    
    def __init__(self, models_dir: Optional[Path] = None):
        if models_dir is None:
            self.models_dir = Path(__file__).resolve().parent.parent / "models"
        else:
            self.models_dir = Path(models_dir)
        
        self.vectorizer_path = self.models_dir / "spam_vectorizer.pkl"
        self.classifier_path = self.models_dir / "spam_classifier.pkl"
        self.metrics_path = self.models_dir / "evaluation_metrics.json"

        self.vectorizer = None
        self.classifier = None
        self.is_loaded = False
        self.load_error = None

        self.load_model()

    @classmethod
    def get_instance(cls, models_dir: Optional[Path] = None) -> "ModelManager":
        if cls._instance is None:
            cls._instance = ModelManager(models_dir)
        return cls._instance

    def load_model(self) -> bool:
        """Loads vectorizer and model from disk."""
        if not self.vectorizer_path.exists() or not self.classifier_path.exists():
            self.is_loaded = False
            self.load_error = (
                "ML model artifacts not found. Please run 'python ml/train_model.py' to train and serialize the model."
            )
            return False

        try:
            self.vectorizer = joblib.load(self.vectorizer_path)
            self.classifier = joblib.load(self.classifier_path)
            self.is_loaded = True
            self.load_error = None
            return True
        except Exception as e:
            self.is_loaded = False
            self.load_error = f"Failed to load ML artifacts: {str(e)}"
            return False

    def predict(self, text: str) -> MLPredictionResult:
        """
        Runs inference on the provided email text.
        Returns an MLPredictionResult with exact probabilities and confidence.
        """
        if not self.is_loaded:
            # Try reloading in case it was just trained
            if not self.load_model():
                return MLPredictionResult(
                    is_spam=False,
                    spam_probability=0.0,
                    ham_probability=100.0,
                    confidence=0.0,
                    is_model_loaded=False,
                    status_message=self.load_error or "ML model is not loaded.",
                )

        cleaned = clean_email_text(text)
        if not cleaned:
            # Empty text default
            return MLPredictionResult(
                is_spam=False,
                spam_probability=0.0,
                ham_probability=100.0,
                confidence=50.0,
                is_model_loaded=True,
                status_message="Empty email text provided.",
            )

        try:
            vec = self.vectorizer.transform([cleaned])
            probs = self.classifier.predict_proba(vec)[0]  # [P(ham), P(spam)]
            
            ham_prob = float(probs[0]) * 100.0
            spam_prob = float(probs[1]) * 100.0
            is_spam = spam_prob >= 50.0
            
            # Confidence is the gap from 50% scaled to 100% or max class probability
            confidence = max(ham_prob, spam_prob)

            return MLPredictionResult(
                is_spam=is_spam,
                spam_probability=round(spam_prob, 2),
                ham_probability=round(ham_prob, 2),
                confidence=round(confidence, 2),
                is_model_loaded=True,
                status_message="Inference completed successfully.",
            )
        except Exception as e:
            return MLPredictionResult(
                is_spam=False,
                spam_probability=0.0,
                ham_probability=100.0,
                confidence=0.0,
                is_model_loaded=False,
                status_message=f"Inference error: {str(e)}",
            )

    def get_metrics(self) -> Dict[str, Any]:
        """Returns loaded evaluation metrics for model performance display."""
        if self.metrics_path.exists():
            try:
                with open(self.metrics_path, "r") as f:
                    return json.load(f)
            except Exception:
                pass
        return {
            "model_type": "Multinomial Naive Bayes + TF-IDF (Not trained)",
            "accuracy": 0.0,
            "precision": 0.0,
            "recall": 0.0,
            "f1_score": 0.0,
            "status": "Run 'python ml/train_model.py' to generate metrics.",
        }
