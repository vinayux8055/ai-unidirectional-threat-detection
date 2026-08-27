from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RiskAssessment:
    probability: float
    score: int
    level: str

    def to_dict(self) -> dict:
        return {
            "probability": round(self.probability, 6),
            "score": self.score,
            "level": self.level,
        }


def assess_risk(threat_probability: float) -> RiskAssessment:
    probability = max(0.0, min(1.0, float(threat_probability)))
    score = int(round(probability * 100))
    if score <= 25:
        level = "LOW"
    elif score <= 50:
        level = "MEDIUM"
    elif score <= 75:
        level = "HIGH"
    else:
        level = "CRITICAL"
    return RiskAssessment(probability=probability, score=score, level=level)

