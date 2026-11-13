"""Local demonstration predictor; it does not call Vertex AI or enforce policy."""

from pathlib import Path

import joblib

from .features import extract_features


class ShadowRiskPredictor:
    def __init__(self, model_path="shadow-core-risk-demo.joblib"):
        path = Path(model_path)
        if not path.exists():
            raise FileNotFoundError(f"Train the demo model first: {path}")
        self.model = joblib.load(path)

    def predict_risk(self, eventos):
        features = extract_features(eventos)
        columns = ["frida_hooks", "magisk_signals", "fft_peak", "markov_anomaly", "event_rate"]
        score = float(self.model.predict_proba([[features[name] for name in columns]])[0][1])
        return {"risk_score": score, "features": features, "note": "demo prediction; not a security decision"}
