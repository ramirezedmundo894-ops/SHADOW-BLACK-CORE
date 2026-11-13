import joblib


class ShadowRiskPredictor:
    def __init__(self):
        self.model = joblib.load("shadow-core-risk-v1.pkl")

    def predict_risk(self, eventos):
        from shadow-core-ml.features import extract_features

        feats = extract_features(eventos)
        drift = self.check_adwin(feats["event_rate"])

        prob_ataque = self.model.predict_proba(
            [[feats["frida_hooks"], feats["magisk_signals"], feats["fft_peak"], feats["markov_anomaly"], feats["event_rate"]]]
        )[0][1]

        if prob_ataque > 0.9:
            decision = {"action": "KILL_SESSION", "jwt_ttl": 0, "pomp": "CRITICAL"}
        elif prob_ataque > 0.6:
            decision = {"action": "ROTATE_JWT_20S", "jwt_ttl": 20, "pomp": "HIGH"}
        elif prob_ataque > 0.3:
            decision = {"action": "CHALLENGE", "jwt_ttl": 300, "pomp": "MEDIUM"}
        else:
            decision = {"action": "ALLOW", "jwt_ttl": 900, "pomp": "LOW"}

        decision["risk_score"] = float(prob_ataque)
        decision["fft_beaconing"] = feats["fft_beaconing"]
        decision["markov_anomaly"] = feats["markov_anomaly"]
        decision["adwin_drift"] = drift
        return decision

    @staticmethod
    def check_adwin(rate):
        return rate > 0.6
