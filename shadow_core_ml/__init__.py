"""Feature extraction demonstration; validate features before real ML use."""

import numpy as np
from scipy.fft import fft


def extract_features(eventos):
    features = {
        "frida_hooks": sum(1 for event in eventos if event.get("type") == "frida_hook"),
        "magisk_signals": sum(1 for event in eventos if event.get("type") == "magisk"),
        "jwt_failures": sum(1 for event in eventos if event.get("type") == "jwt_fail"),
    }
    timestamps = [float(event["ts"]) for event in eventos if event.get("ts") is not None]
    if len(timestamps) > 10:
        fft_values = np.abs(fft(np.diff(timestamps)))
        features["fft_peak"] = float(np.max(fft_values)) if len(fft_values) else 0.0
        features["fft_beaconing"] = int(features["fft_peak"] > 50)
    else:
        features["fft_peak"] = 0.0
        features["fft_beaconing"] = 0
    sequence = [event.get("type") for event in eventos]
    features["markov_anomaly"] = sum(
        1 for left, right in zip(sequence, sequence[1:]) if left == "hook" and right == "exfil"
    )
    features["event_rate"] = (
        len(timestamps) / max(1.0, timestamps[-1] - timestamps[0]) if len(timestamps) > 1 else float(len(timestamps))
    )
    return features
