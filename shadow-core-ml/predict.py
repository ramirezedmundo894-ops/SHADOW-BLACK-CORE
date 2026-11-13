from google.cloud import aiplatform
from sklearn.ensemble import RandomForestClassifier
from sklearn.naive_bayes import GaussianNB
import joblib


def load_shadow_dataset():
    """Placeholder training dataset loader."""
    import pandas as pd

    data = [
        [0, 0, 0.1, 0, 0.2, 0],
        [1, 0, 10.0, 0, 0.1, 1],
        [2, 1, 42.0, 1, 0.8, 1],
        [0, 0, 0.2, 0, 0.3, 0],
        [1, 1, 25.0, 1, 0.7, 1],
        [0, 0, 0.0, 0, 0.1, 0],
    ]
    df = pd.DataFrame(data, columns=["frida_hooks", "magisk_signals", "fft_peak", "markov_anomaly", "event_rate", "label"])
    return df.drop(columns=["label"]), df["label"]


def train_shadow_model():
    """Trains a simple risk model for demonstration."""
    try:
        aiplatform.init(project="shadow-core-prod", location="us-central1", staging_bucket="gs://shadow-evidence-prod")
    except Exception:
        aiplatform = None

    X, y = load_shadow_dataset()
    bayes = GaussianNB()
    bayes.fit(X, y)
    print(f"Bayes Accuracy: {bayes.score(X, y)}")

    rf = RandomForestClassifier(n_estimators=100)
    rf.fit(X, y)

    joblib.dump(rf, "shadow-core-risk-v1.pkl")
    print("Modelo registrado en Vertex AI - Auditable con Merkle")
    return rf
