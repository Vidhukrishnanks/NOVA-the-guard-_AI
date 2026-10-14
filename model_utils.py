"""
Model building, loading, prediction and per-URL explanation.

Explanations are computed from the trained model itself:
  * Logistic Regression -> coefficient x feature value (log-odds contributions)
  * Decision Tree / Random Forest -> decision-path contributions
    (how much each split moved the predicted malicious probability)
Nothing is invented: only features the model actually used are reported.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler
from sklearn.tree import DecisionTreeClassifier

from feature_extraction import FEATURE_DESCRIPTIONS, MODEL_FEATURES, extract_features, normalize_url

MODEL_FILENAME = "urlguard_model.joblib"
METRICS_FILENAME = "metrics.json"

# Risk bands on the 0-100 model score.
SUSPICIOUS_FROM = 35
MALICIOUS_FROM = 65

MODEL_LABELS = {
    "logreg": "Logistic Regression (URL features + character n-grams)",
    "tree": "Decision Tree (URL features)",
    "forest": "Random Forest (URL features)",
}


# --------------------------------------------------------------------------- #
# Feature frame
# --------------------------------------------------------------------------- #
def build_frame(urls) -> pd.DataFrame:
    """Turn a list of URL strings into the DataFrame every pipeline expects."""
    urls = list(urls)
    feats = [extract_features(u) for u in urls]
    df = pd.DataFrame(feats, columns=MODEL_FEATURES).astype(float)
    df.insert(0, "url_norm", [normalize_url(u) for u in urls])
    return df


# --------------------------------------------------------------------------- #
# Model definitions
# --------------------------------------------------------------------------- #
def make_models(seed: int = 42) -> dict[str, Pipeline]:
    numeric = Pipeline([
        ("log", FunctionTransformer(np.log1p, feature_names_out="one-to-one")),
        ("scale", StandardScaler()),
    ])
    logreg = Pipeline([
        ("prep", ColumnTransformer([
            ("ngrams", TfidfVectorizer(analyzer="char", ngram_range=(3, 5), min_df=3,
                                       max_features=50000, sublinear_tf=True,
                                       dtype=np.float32), "url_norm"),
            ("num", numeric, MODEL_FEATURES),
        ])),
        ("clf", LogisticRegression(max_iter=3000, C=4.0, class_weight="balanced",
                                   solver="liblinear", random_state=seed)),
    ])
    passthrough = ColumnTransformer([("num", "passthrough", MODEL_FEATURES)])
    tree = Pipeline([
        ("prep", passthrough),
        ("clf", DecisionTreeClassifier(max_depth=14, min_samples_leaf=5,
                                       class_weight="balanced", random_state=seed)),
    ])
    forest = Pipeline([
        ("prep", ColumnTransformer([("num", "passthrough", MODEL_FEATURES)])),
        ("clf", RandomForestClassifier(n_estimators=150, max_depth=22, min_samples_leaf=2,
                                       class_weight="balanced_subsample", n_jobs=-1,
                                       random_state=seed)),
    ])
    return {"logreg": logreg, "tree": tree, "forest": forest}


# --------------------------------------------------------------------------- #
# Explanations
# --------------------------------------------------------------------------- #
def _clean_name(raw: str) -> tuple[str, str]:
    """'num__url_length' -> ('feature','url_length'); 'ngrams__kyc' -> ('ngram','kyc')."""
    group, _, name = raw.partition("__")
    return ("ngram", name) if group == "ngrams" else ("feature", name)


def _explain_linear(pipe: Pipeline, frame: pd.DataFrame, top_k: int = 6) -> list[dict]:
    prep, clf = pipe.named_steps["prep"], pipe.named_steps["clf"]
    x = prep.transform(frame)
    row = x.tocsr()[0] if hasattr(x, "tocsr") else np.asarray(x)[0]
    names = prep.get_feature_names_out()
    coef = clf.coef_[0]
    if hasattr(row, "indices"):
        idx, vals = row.indices, row.data
    else:
        idx = np.nonzero(row)[0]
        vals = row[idx]
    contribs = []
    for i, v in zip(idx, vals):
        c = float(coef[i] * v)
        if abs(c) < 1e-4:
            continue
        kind, name = _clean_name(names[i])
        contribs.append({"kind": kind, "name": name, "contribution": c})
    typical = {}
    try:
        scale = prep.named_transformers_["num"].named_steps["scale"]
        typical = {f: float(np.expm1(m)) for f, m in zip(MODEL_FEATURES, scale.mean_)}
    except (KeyError, AttributeError):
        pass
    return _rank(contribs, frame, top_k, unit="log-odds", typical=typical)


def _explain_tree_estimator(est, x_row: np.ndarray, n_features: int) -> np.ndarray:
    t = est.tree_
    vals = t.value[:, 0, :]
    probs = vals[:, 1] / np.clip(vals.sum(axis=1), 1e-12, None)
    contrib = np.zeros(n_features)
    node = 0
    while t.children_left[node] != -1:
        f = t.feature[node]
        nxt = t.children_left[node] if x_row[f] <= t.threshold[node] else t.children_right[node]
        contrib[f] += probs[nxt] - probs[node]
        node = nxt
    return contrib


def _explain_tree(pipe: Pipeline, frame: pd.DataFrame, top_k: int = 6) -> list[dict]:
    prep, clf = pipe.named_steps["prep"], pipe.named_steps["clf"]
    x = np.asarray(prep.transform(frame), dtype=np.float32)[0]
    estimators = clf.estimators_ if hasattr(clf, "estimators_") else [clf]
    total = np.zeros(len(MODEL_FEATURES))
    for est in estimators:
        total += _explain_tree_estimator(est, x, len(MODEL_FEATURES))
    total /= len(estimators)
    contribs = [{"kind": "feature", "name": MODEL_FEATURES[i], "contribution": float(c)}
                for i, c in enumerate(total) if abs(c) >= 1e-4]
    return _rank(contribs, frame, top_k, unit="probability")


def _rank(contribs: list[dict], frame: pd.DataFrame, top_k: int, unit: str,
          typical: dict | None = None) -> list[dict]:
    """Return the strongest contributions, ranked separately for URL features and
    character n-grams, each tagged 'increases' or 'decreases' (risk)."""
    typical = typical or {}
    for c in contribs:
        c["unit"] = unit
        if c["kind"] == "feature":
            c["label"] = FEATURE_DESCRIPTIONS.get(c["name"], c["name"])
            val = float(frame.iloc[0][c["name"]])
            c["value"] = int(val) if val.is_integer() else round(val, 3)
            if c["name"] in typical:
                t = typical[c["name"]]
                c["typical"] = round(t, 2)
                c["vs_typical"] = "higher" if val > t * 1.05 + 1e-9 else ("lower" if val < t * 0.95 - 1e-9 else "similar")
        else:
            c["label"] = f"Character pattern \u201c{c['name']}\u201d"
            c["value"] = None
    out = []
    for kind, k_up, k_down in (("feature", top_k, 3), ("ngram", 5, 3)):
        items = [c for c in contribs if c["kind"] == kind]
        up = sorted([c for c in items if c["contribution"] > 0], key=lambda c: -c["contribution"])[:k_up]
        down = sorted([c for c in items if c["contribution"] < 0], key=lambda c: c["contribution"])[:k_down]
        for c in up:
            c["direction"] = "increases"
        for c in down:
            c["direction"] = "decreases"
        out += up + down
    return out


# --------------------------------------------------------------------------- #
# Service used by the Flask app
# --------------------------------------------------------------------------- #
class ModelService:
    """Loads the saved model once and serves predictions thread-safely."""

    def __init__(self, model_dir: Path):
        self.model_dir = Path(model_dir)
        self._lock = threading.Lock()
        self.bundle = None
        self.metrics = None
        self.load_error = None
        self.reload()

    def reload(self):
        path = self.model_dir / MODEL_FILENAME
        mpath = self.model_dir / METRICS_FILENAME
        self.bundle, self.metrics, self.load_error = None, None, None
        if not path.exists():
            self.load_error = "No trained model found. Run: python train_model.py"
            return
        try:
            self.bundle = joblib.load(path)
            if mpath.exists():
                self.metrics = json.loads(mpath.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001 - surface any load problem to the UI
            self.load_error = (f"Could not load the model ({type(exc).__name__}). "
                               "It may have been trained with a different scikit-learn "
                               "version. Re-run: python train_model.py")

    @property
    def ready(self) -> bool:
        return self.bundle is not None

    @property
    def info(self) -> dict:
        return self.bundle.get("metadata", {}) if self.bundle else {}

    def predict_many(self, urls: list[str]) -> np.ndarray:
        frame = build_frame(urls)
        with self._lock:
            return self.bundle["pipeline"].predict_proba(frame)[:, 1]

    def predict(self, url: str, explain: bool = True) -> dict:
        if not self.ready:
            raise RuntimeError(self.load_error or "Model not loaded")
        frame = build_frame([url])
        pipe = self.bundle["pipeline"]
        with self._lock:
            proba = float(pipe.predict_proba(frame)[0, 1])
            contributions = []
            if explain:
                if self.bundle["model_key"] == "logreg":
                    contributions = _explain_linear(pipe, frame)
                else:
                    contributions = _explain_tree(pipe, frame)
        score = round(proba * 100, 1)
        return {
            "score": score,
            "model_label": "malicious" if proba >= 0.5 else "legitimate",
            "category": score_to_category(score),
            "features": {k: (int(v) if float(v).is_integer() else round(float(v), 4))
                         for k, v in frame.iloc[0][MODEL_FEATURES].items()},
            "contributions": contributions,
            "model_name": self.bundle.get("model_label"),
        }


def score_to_category(score: float) -> str:
    if score >= MALICIOUS_FROM:
        return "malicious"
    if score >= SUSPICIOUS_FROM:
        return "suspicious"
    return "legitimate"
