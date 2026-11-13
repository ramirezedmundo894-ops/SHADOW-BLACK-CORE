import numpy as np
from scipy.fft import fft


def extract_features(eventos):
    """Eventos de la app -> Features para Vertex AI."""
    features = {}

    features["frida_hooks"] = sum(1 for e in eventos if e.get("type") == "frida_hook")
    features["magisk_signals"] = sum(1 for e in eventos if e.get("type") == "magisk")
    features["jwt_failures"] = sum(1 for e in eventos if e.get("type") == "jwt_fail")

    timestamps = [float(e.get("ts", 0)) for e in eventos]
    if len(timestamps) > 10:
        intervals = np.diff(timestamps)
        fft_vals = np.abs(fft(intervals))
        features["fft_peak"] = float(np.max(fft_vals)) if len(fft_vals) else 0.0
        features["fft_beaconing"] = 1 if features["fft_peak"] > 50 else 0
    else:
        features["fft_peak"] = 0.0
        features["fft_beaconing"] = 0

    secuencia = [e.get("type") for e in eventos]
    transiciones_raras = sum(
        1 for i in range(len(secuencia) - 1) if secuencia[i] == "hook" and secuencia[i + 1] == "exfil"
    )
    features["markov_anomaly"] = transiciones_raras

    if len(timestamps) > 1:
        features["event_rate"] = len(eventos) / max(1, (timestamps[-1] - timestamps[0]))
    else:
        features["event_rate"] = float(len(eventos))

    return features
