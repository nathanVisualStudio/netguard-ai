from __future__ import annotations

import random
from functools import lru_cache

from .knowledge import SERVICES, VULN_RISK_FLOOR

FEATURES = [
    "n_open", "max_risk", "mean_risk", "n_cleartext", "n_remote_admin", "n_database",
    "n_file_sharing", "n_exposed_api", "n_vuln_critical", "n_vuln_high", "n_vuln_medium",
]
LEVELS = ["low", "medium", "high", "critical"]
MIDPOINTS = [12.0, 40.0, 60.0, 85.0]
THRESHOLDS = [30, 50, 70]

WEIGHTS = {
    "max_risk": 6.0, "n_cleartext": 3.0, "n_remote_admin": 3.0, "n_database": 5.0,
    "n_file_sharing": 5.0, "n_exposed_api": 12.0, "n_vuln_critical": 15.0,
    "n_vuln_high": 8.0, "n_vuln_medium": 3.0,
}
FACTOR_LABELS = {
    "max_risk": "Most dangerous exposed service",
    "n_cleartext": "Clear-text protocols",
    "n_remote_admin": "Remote administration services",
    "n_database": "Exposed databases / data stores",
    "n_file_sharing": "File-sharing services",
    "n_exposed_api": "Unauthenticated management API",
    "n_vuln_critical": "Critical known vulnerabilities",
    "n_vuln_high": "High-severity known vulnerabilities",
    "n_vuln_medium": "Medium-severity known vulnerabilities",
}


def level_from_score(score: float) -> str:
    for lvl, t in zip(LEVELS, THRESHOLDS):
        if score < t:
            return lvl
    return LEVELS[-1]


def extract_features(ports: list[dict]) -> dict[str, float]:
    risks = [p["risk"] for p in ports]
    count = lambda cat: sum(1 for p in ports if p["category"] == cat)
    vuln = lambda sev: sum(1 for p in ports if p.get("vuln") == sev)
    return {
        "n_open": len(ports),
        "max_risk": max(risks, default=0),
        "mean_risk": sum(risks) / len(risks) if risks else 0.0,
        "n_cleartext": count("cleartext"),
        "n_remote_admin": count("remote_admin"),
        "n_database": count("database"),
        "n_file_sharing": count("file_sharing"),
        "n_exposed_api": count("exposed_api"),
        "n_vuln_critical": vuln("critical"),
        "n_vuln_high": vuln("high"),
        "n_vuln_medium": vuln("medium"),
    }


def rule_score(f: dict[str, float]) -> float:
    s = sum(WEIGHTS[k] * f[k] for k in WEIGHTS) + 0.8 * min(f["n_open"], 30)
    return max(0.0, min(100.0, s))


def key_factors(f: dict[str, float], top: int = 4) -> list[dict]:
    contribs = [(k, WEIGHTS[k] * f[k]) for k in WEIGHTS if f[k] > 0]
    contribs.sort(key=lambda kv: kv[1], reverse=True)
    return [{"factor": FACTOR_LABELS[k], "impact": round(v, 1)} for k, v in contribs[:top]]


def synthetic_dataset(n: int = 6000, seed: int = 42):
    rng = random.Random(seed)
    catalog = [(p, v[1], v[2]) for p, v in SERVICES.items()]
    X, y = [], []
    for _ in range(n):
        k = rng.choice([0, 1, 1, 2, 2, 3, 3, 4, 5, 6, 8, 10, 14])
        ports = []
        for _p, cat, risk in rng.sample(catalog, k=min(k, len(catalog))):
            vuln = rng.choices([None, "medium", "high", "critical"], [0.8, 0.1, 0.06, 0.04])[0]
            eff = max(risk, VULN_RISK_FLOOR.get(vuln, 0))
            ports.append({"risk": eff, "category": cat, "vuln": vuln})
        if rng.random() < 0.3:
            ports += [{"risk": 3, "category": "other", "vuln": None}] * rng.randint(1, 4)
        f = extract_features(ports)
        score = rule_score(f) + rng.gauss(0, 4)
        X.append([f[c] for c in FEATURES])
        y.append(LEVELS.index(level_from_score(score)))
    return X, y


@lru_cache(maxsize=1)
def _model():
    try:
        from sklearn.ensemble import RandomForestClassifier
    except ImportError:
        return None
    X, y = synthetic_dataset()
    clf = RandomForestClassifier(n_estimators=150, min_samples_leaf=3, random_state=42, n_jobs=1)
    clf.fit(X, y)
    return clf


def predict(f: dict[str, float]) -> dict:
    clf = _model()
    if clf is None:
        score = rule_score(f)
        probs = {lvl: (1.0 if lvl == level_from_score(score) else 0.0) for lvl in LEVELS}
        engine = "expert-rules"
    else:
        raw = clf.predict_proba([[f[c] for c in FEATURES]])[0]
        probs = {LEVELS[int(c)]: 0.0 for c in range(4)}
        for cls, p in zip(clf.classes_, raw):
            probs[LEVELS[int(cls)]] = float(p)
        score = sum(probs[lvl] * m for lvl, m in zip(LEVELS, MIDPOINTS))
        engine = "random-forest"
    return {
        "level": level_from_score(score),
        "score": round(score),
        "probabilities": {k: round(v, 3) for k, v in probs.items()},
        "factors": key_factors(f),
        "engine": engine,
    }
