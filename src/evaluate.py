"""
Evaluation script.
Loads the saved model and evaluates it on a held-out test split.

Run: python -m src.evaluate

DATA SOURCE NOTE
---------------
The project's sample_urls.csv contains only 6 hand-curated URLs used for
development fixtures.  Feature extraction requires live HTTP fetches, so
training/evaluation on the raw CSV is unreliable offline.

When the processed parquet has fewer than 20 labelled samples (as will
normally be the case), this script falls back to the same 200-sample
*synthetic* dataset that train.py uses.

WARNING: Synthetic results do NOT represent real-world detection performance.
They demonstrate that the pipeline is wired correctly, nothing more.
"""

import os
import numpy as np
import pandas as pd
import joblib
import logging

from src.config import PROCESSED_PARQUET, BASELINE_MODEL
from src.ml_helpers import split_data, compute_metrics
from src.logging_config import setup_logging
from src.model import load_model
from src.train import generate_synthetic_data

logger = logging.getLogger(__name__)
setup_logging()

FEATURE_NAMES = [
    "url_length", "dot_count", "at_sign", "is_https", "is_ip",
    "form_count", "password_inputs", "iframe_count", "ext_links", "ext_scripts",
]

MIN_REAL_SAMPLES = 20  # below this threshold, fall back to synthetic


def _load_dataset() -> tuple:
    """
    Load features and labels from the processed parquet if it contains
    enough real samples; otherwise fall back to the synthetic dataset.

    Returns:
        (X, y, source_description)
    """
    if os.path.exists(PROCESSED_PARQUET):
        df = pd.read_parquet(PROCESSED_PARQUET)
        feat_cols = [f"feature_{i+1}" for i in range(10)]
        if len(df) >= MIN_REAL_SAMPLES and all(c in df.columns for c in feat_cols):
            X = df[feat_cols].values
            y = df["label"].values
            return X, y, f"real data from parquet ({len(df)} samples)"

    logger.warning(
        "Processed parquet absent or has too few real samples "
        f"(< {MIN_REAL_SAMPLES}). Falling back to synthetic dataset."
    )
    X, y = generate_synthetic_data(n_samples=200)
    return X, y, "synthetic data (200 samples, Gaussian model - see train.py)"


def evaluate() -> dict:
    """
    Evaluate the saved model and print a structured report.

    Returns:
        dict: metrics dictionary (accuracy, precision, recall, f1, roc_auc, confusion_matrix).
    """
    try:
        model = load_model()
    except FileNotFoundError:
        logger.error(
            f"Model not found at {BASELINE_MODEL}. "
            "Run 'python -m src.train' first."
        )
        return {}

    X, y, source = _load_dataset()

    # Reproducible 80/20 stratified split - same seed as training
    # FIX: split_data returns (X_train, X_test, y_train, y_test); previous code
    # unpacked them in reverse (X_test first), causing silent data leakage.
    X_train, X_test, y_train, y_test = split_data(
        X, y, test_size=0.2, random_state=42
    )

    print()
    print("=" * 62)
    print("EVALUATION REPORT - PHISHING DETECTOR (URL/HTML MODEL)")
    print("=" * 62)
    print()

    if "synthetic" in source:
        print("WARNING - DATA SOURCE: SYNTHETIC")
        print("  Results are computed on procedurally-generated data.")
        print("  The classes are linearly separable by construction, so")
        print("  metrics will be unrealistically high.")
        print("  These numbers do NOT represent real-world performance.")
    else:
        print(f"  Data source: {source}")
    print()

    legit_n = int((y == 0).sum())
    phish_n = int((y == 1).sum())
    print(f"  Total samples  : {len(X)}")
    print(f"  Legitimate (0) : {legit_n}")
    print(f"  Phishing   (1) : {phish_n}")
    print(f"  Train size     : {len(X_train)}")
    print(f"  Test  size     : {len(X_test)}")
    print(f"  Random seed    : 42  (stratified split)")
    print()

    # Degeneracy check: warn if the saved model was trained on very few samples
    root_n = model.estimators_[0].tree_.n_node_samples[0]
    if root_n < 20:
        print(
            f"WARNING - DEGENERATE MODEL: The saved model's bootstrap sample "
            f"size is only {root_n}, indicating it was trained on fewer than "
            f"~5 samples. Model predictions below may be unreliable. "
            f"Run 'python -m src.train' to produce a proper model."
        )
        print()

    y_pred  = model.predict(X_test)
    y_proba = model.predict_proba(X_test)
    metrics = compute_metrics(y_test, y_pred, y_proba)

    from sklearn.metrics import confusion_matrix
    cm = confusion_matrix(y_test, y_pred)
    metrics["confusion_matrix"] = cm.tolist()

    print("-- CONFUSION MATRIX ------------------------------------------------")
    print("               Pred Legit (0)  Pred Phish (1)")
    print(f"  True Legit:  {cm[0, 0]:<14d}  {cm[0, 1]:<14d}")
    print(f"  True Phish:  {cm[1, 0]:<14d}  {cm[1, 1]:<14d}")
    print()

    print("-- SUMMARY METRICS -------------------------------------------------")
    print(f"  Accuracy : {metrics['accuracy']:.4f}")
    print(f"  Precision: {metrics['precision']:.4f}")
    print(f"  Recall   : {metrics['recall']:.4f}")
    print(f"  F1 Score : {metrics['f1']:.4f}")
    if "roc_auc" in metrics:
        print(f"  ROC-AUC  : {metrics['roc_auc']:.4f}")
    print()

    # Feature importances
    importances = model.feature_importances_
    order = np.argsort(importances)[::-1]
    print("-- FEATURE IMPORTANCES ----------------------------------------------")
    for i in order:
        bar = "|" * int(importances[i] * 40)
        print(f"  {FEATURE_NAMES[i]:<20s}  {importances[i]:.4f}  {bar}")
    print()
    print("=" * 62)

    logger.info("Evaluation complete.")
    return metrics


if __name__ == "__main__":
    evaluate()