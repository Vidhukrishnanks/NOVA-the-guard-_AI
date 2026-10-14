"""
Train, compare and save the URLGuard AI model.

Usage (from the project folder, with the virtual environment active):

    python train_model.py                          # auto: real dataset if present, else synthetic demo
    python train_model.py --data data/malicious_phish.csv
    python train_model.py --data data/malicious_phish.csv --all   # use every row (slow)

What it does
------------
1. Loads a labelled CSV (columns like url + type/label).
2. Cleans it: validates columns, drops missing/blank/overlong rows,
   normalises URLs, removes duplicates and URLs that appear with BOTH labels.
3. Splits into train (70%) / validation (15%) / test (15%) - stratified.
   Duplicates are removed BEFORE splitting so the same URL can never be in
   both train and test (prevents data leakage).
4. Trains Logistic Regression, Decision Tree and Random Forest.
5. Selects the model with the best F1 (malicious class) on VALIDATION data.
6. Reports final metrics for every model on the untouched TEST data.
7. Saves models/urlguard_model.joblib and models/metrics.json.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import train_test_split

from feature_extraction import MAX_URL_LENGTH, MODEL_FEATURES, normalize_url
from model_utils import METRICS_FILENAME, MODEL_FILENAME, MODEL_LABELS, build_frame, make_models

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
REAL_DEFAULT = DATA_DIR / "malicious_phish.csv"
DEMO_DEFAULT = DATA_DIR / "demo_synthetic_urls.csv"

URL_COLUMNS = ["url", "urls", "domain", "link"]
LABEL_COLUMNS = ["type", "label", "class", "result", "status", "target", "is_malicious"]
BENIGN_VALUES = {"benign", "good", "legitimate", "legit", "safe", "0", "false", "clean"}
MALICIOUS_VALUES = {"malicious", "bad", "phishing", "malware", "defacement", "spam",
                    "1", "true", "fraud", "suspicious"}


def log(msg: str):
    print(f"[train] {msg}", flush=True)


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def find_column(columns, candidates, kind):
    lower = {c.lower().strip(): c for c in columns}
    for cand in candidates:
        if cand in lower:
            return lower[cand]
    raise SystemExit(f"Could not find a {kind} column. Found columns: {list(columns)}. "
                     f"Expected one of: {candidates}")


def load_and_clean(path: Path) -> tuple[pd.DataFrame, dict]:
    log(f"Loading {path}")
    try:
        raw = pd.read_csv(path, dtype=str, keep_default_na=False, on_bad_lines="skip",
                          encoding="utf-8", encoding_errors="replace")
    except Exception as exc:
        raise SystemExit(f"Could not read CSV: {exc}")
    url_col = find_column(raw.columns, URL_COLUMNS, "URL")
    label_col = find_column(raw.columns, LABEL_COLUMNS, "label")
    summary = {"rows_raw": int(len(raw)), "url_column": url_col, "label_column": label_col}

    df = raw[[url_col, label_col]].rename(columns={url_col: "url", label_col: "label_raw"})
    df["url"] = df["url"].astype(str).str.strip()
    df["label_raw"] = df["label_raw"].astype(str).str.strip().str.lower()
    summary["original_type_distribution"] = {k: int(v) for k, v in df["label_raw"].value_counts().head(12).items()}

    before = len(df)
    df = df[(df["url"] != "") & (df["label_raw"] != "")]
    summary["dropped_missing"] = int(before - len(df))

    def map_label(v):
        if v in BENIGN_VALUES:
            return 0
        if v in MALICIOUS_VALUES:
            return 1
        return -1

    df["label"] = df["label_raw"].map(map_label)
    unknown = df[df["label"] == -1]
    summary["dropped_unknown_label"] = int(len(unknown))
    if len(unknown):
        log(f"Dropping {len(unknown)} rows with unrecognised labels: {sorted(unknown['label_raw'].unique())[:8]}")
    df = df[df["label"] != -1]

    before = len(df)
    df = df[df["url"].str.len() <= MAX_URL_LENGTH]
    df = df[~df["url"].str.contains(r"[\x00-\x1f\x7f ]", regex=True)]
    summary["dropped_invalid"] = int(before - len(df))

    df["url_norm"] = df["url"].map(normalize_url)
    df = df[df["url_norm"] != ""]

    # Conflicting labels: same normalised URL labelled both ways -> unreliable, drop all.
    label_counts = df.groupby("url_norm")["label"].nunique()
    conflicts = set(label_counts[label_counts > 1].index)
    summary["dropped_conflicting"] = int(df["url_norm"].isin(conflicts).sum())
    df = df[~df["url_norm"].isin(conflicts)]

    before = len(df)
    df = df.drop_duplicates(subset="url_norm")
    summary["dropped_duplicates"] = int(before - len(df))
    summary["rows_clean"] = int(len(df))
    if df["label"].nunique() < 2 or len(df) < 200:
        raise SystemExit("Dataset needs at least 200 clean rows containing BOTH classes.")
    return df.reset_index(drop=True), summary


def evaluate(y_true, proba, threshold=0.5) -> dict:
    pred = (proba >= threshold).astype(int)
    cm = confusion_matrix(y_true, pred, labels=[0, 1])
    return {
        "accuracy": round(float(accuracy_score(y_true, pred)), 4),
        "precision": round(float(precision_score(y_true, pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, pred, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y_true, proba)), 4),
        "confusion_matrix": {"tn": int(cm[0, 0]), "fp": int(cm[0, 1]),
                             "fn": int(cm[1, 0]), "tp": int(cm[1, 1])},
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="Train URLGuard AI models")
    ap.add_argument("--data", help="Path to labelled CSV (default: data/malicious_phish.csv if present, else synthetic demo)")
    ap.add_argument("--max-rows", type=int, default=200_000,
                    help="Stratified sample size for faster training on laptops (default 200000)")
    ap.add_argument("--all", action="store_true", help="Use all rows (ignores --max-rows)")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out-dir", default=str(ROOT / "models"))
    ap.add_argument("--synthetic", action="store_true",
                    help="Force-mark the dataset as synthetic in the saved metadata")
    args = ap.parse_args(argv)

    if args.data:
        data_path = Path(args.data)
    elif REAL_DEFAULT.exists():
        data_path = REAL_DEFAULT
    else:
        data_path = DEMO_DEFAULT
        if not data_path.exists():
            log("No dataset found - generating the SYNTHETIC demo dataset first...")
            subprocess.run([sys.executable, str(ROOT / "generate_demo_data.py")], check=True)
    if not data_path.exists():
        raise SystemExit(f"Dataset not found: {data_path}")
    is_synthetic = args.synthetic or "synthetic" in data_path.name.lower()
    if is_synthetic:
        log("*** SYNTHETIC DEMO DATA: metrics demonstrate the workflow only, NOT real-world performance ***")

    df, summary = load_and_clean(data_path)
    summary["rows_after_cleaning"] = summary["rows_clean"]
    if not args.all and len(df) > args.max_rows:
        df, _ = train_test_split(df, train_size=args.max_rows, stratify=df["label"], random_state=args.seed)
        log(f"Using a stratified sample of {len(df)} rows (use --all for every row)")
    summary["rows_used"] = int(len(df))
    summary["class_distribution"] = {"legitimate": int((df["label"] == 0).sum()),
                                     "malicious": int((df["label"] == 1).sum())}
    log(f"Rows used: {len(df)}  (legitimate={summary['class_distribution']['legitimate']}, "
        f"malicious={summary['class_distribution']['malicious']})")

    train_df, temp_df = train_test_split(df, test_size=0.30, stratify=df["label"], random_state=args.seed)
    val_df, test_df = train_test_split(temp_df, test_size=0.50, stratify=temp_df["label"], random_state=args.seed)
    summary["split"] = {"train": len(train_df), "validation": len(val_df), "test": len(test_df)}

    log("Extracting features (string analysis only - no URL is visited)...")
    t0 = time.time()
    X_train, X_val, X_test = (build_frame(d["url"]) for d in (train_df, val_df, test_df))
    y_train, y_val, y_test = (d["label"].to_numpy() for d in (train_df, val_df, test_df))
    log(f"Features ready in {time.time() - t0:.1f}s")

    results, fitted = {}, {}
    for key, pipe in make_models(args.seed).items():
        log(f"Training {MODEL_LABELS[key]} ...")
        t0 = time.time()
        pipe.fit(X_train, y_train)
        train_secs = time.time() - t0
        val_m = evaluate(y_val, pipe.predict_proba(X_val)[:, 1])
        test_m = evaluate(y_test, pipe.predict_proba(X_test)[:, 1])
        results[key] = {"label": MODEL_LABELS[key], "train_seconds": round(train_secs, 2),
                        "validation": val_m, "test": test_m}
        fitted[key] = pipe
        log(f"  validation F1={val_m['f1']:.4f}  test F1={test_m['f1']:.4f}  ({train_secs:.1f}s)")

    best = max(results, key=lambda k: (results[k]["validation"]["f1"], results[k]["validation"]["roc_auc"]))
    log(f"Selected model: {MODEL_LABELS[best]} (best validation F1)")

    importances = []
    clf = fitted[best].named_steps["clf"]
    if hasattr(clf, "feature_importances_"):
        importances = sorted(zip(MODEL_FEATURES, map(float, clf.feature_importances_)), key=lambda t: -t[1])
    elif hasattr(clf, "coef_"):
        names = fitted[best].named_steps["prep"].get_feature_names_out()
        coefs = clf.coef_[0]
        importances = sorted(((n.split("__", 1)[1], float(c)) for n, c in zip(names, coefs)
                              if n.startswith("num__")), key=lambda t: -abs(t[1]))
    importances = [{"feature": f, "value": round(v, 5)} for f, v in importances[:15]]

    trained_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    version = datetime.now(timezone.utc).strftime("v%Y%m%d-%H%M%S")
    metadata = {
        "model_version": version,
        "trained_at": trained_at,
        "selected_model": best,
        "selected_model_label": MODEL_LABELS[best],
        "selection_rule": "Highest F1 (malicious class) on the validation split",
        "threshold": 0.5,
        "dataset_file": data_path.name,
        "dataset_sha256": sha256_of(data_path),
        "is_synthetic": bool(is_synthetic),
        "features": MODEL_FEATURES,
        "uses_char_ngrams": best == "logreg",
        "sklearn_version": sklearn.__version__,
        "python_version": platform.python_version(),
        "seed": args.seed,
    }
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump({"pipeline": fitted[best], "model_key": best, "model_label": MODEL_LABELS[best],
                 "metadata": metadata}, out_dir / MODEL_FILENAME, compress=3)
    metrics = {"metadata": metadata, "dataset": summary, "models": results,
               "selected": best, "feature_importance": importances}
    (out_dir / METRICS_FILENAME).write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    log(f"Saved model -> {out_dir / MODEL_FILENAME}")
    log(f"Saved metrics -> {out_dir / METRICS_FILENAME}")
    t = results[best]["test"]
    log(f"TEST: accuracy={t['accuracy']} precision={t['precision']} recall={t['recall']} f1={t['f1']}")
    if is_synthetic:
        log("Reminder: these numbers come from SYNTHETIC data.")
    return metrics


if __name__ == "__main__":
    main()
