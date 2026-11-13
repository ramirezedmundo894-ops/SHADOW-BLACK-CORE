"""Model training example using a tiny synthetic dataset, not production data."""

from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.naive_bayes import GaussianNB

FEATURE_COLUMNS = ["frida_hooks", "magisk_signals", "fft_peak", "markov_anomaly", "event_rate"]


def load_shadow_dataset():
    # Synthetic data exists only to show the expected interface.
    frame = pd.DataFrame(
        [
            [0, 0, 0.1, 0, 0.2, 0],
            [1, 0, 10.0, 0, 0.1, 1],
            [2, 1, 42.0, 1, 0.8, 1],
            [0, 0, 0.2, 0, 0.3, 0],
            [1, 1, 25.0, 1, 0.7, 1],
            [0, 0, 0.0, 0, 0.1, 0],
        ],
        columns=FEATURE_COLUMNS + ["label"],
    )
    return frame[FEATURE_COLUMNS], frame["label"]


def train_shadow_model(output_path="shadow-core-risk-demo.joblib"):
    features, labels = load_shadow_dataset()
    bayes = GaussianNB().fit(features, labels)
    model = RandomForestClassifier(n_estimators=100, random_state=42).fit(features, labels)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, output)
    return {"model_path": str(output), "demo_training_accuracy": model.score(features, labels), "bayes": bayes}
