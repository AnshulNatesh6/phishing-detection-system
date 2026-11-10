"""
Training script.
Processes data, trains RandomForest, saves model.
Run: python -m src.train

DATA SOURCE NOTE
----------------
The project's sample_urls.csv contains only 6 hand-curated URLs used for
development fixtures.  Feature extraction requires live HTTP fetches, so
training on the raw CSV is unreliable offline.  When fewer than
MIN_REAL_SAMPLES survive feature extraction, training automatically falls
back to a 200-sample *synthetic* Gaussian dataset.

WARNING: A model trained on synthetic data has no real-world validity.
         It demonstrates pipeline wiring only.
"""

import os
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
import logging
from src.config import PROCESSED_PARQUET, BASELINE_MODEL
from src.data_processing import process_data
from src.ml_helpers import split_data, compute_metrics
from src.logging_config import setup_logging

logger = logging.getLogger(__name__)
setup_logging()

MIN_REAL_SAMPLES = 20  # fall back to synthetic below this threshold


def generate_synthetic_data(n_samples: int = 200) -> tuple:
    """
    Generate a balanced synthetic dataset for pipeline validation.

    The two classes are separated by design (large mean differences),
    so any classifier will achieve near-perfect metrics on this data.
    Results obtained on synthetic data MUST NOT be reported as evidence
    of real-world phishing detection performance.

    Args:
        n_samples: Total number of samples (split 50/50 per class).

    Returns:
        (X, y): Feature matrix and label vector, shuffled with seed 42.
    """
    np.random.seed(42)
    n_legit = n_samples // 2
    n_phish = n_samples - n_legit

    # Legit: short URLs, HTTPS, few suspicious elements
    X_legit = np.random.normal(
        [30, 2, 0, 1, 0, 1, 0, 1, 3, 0],
        [ 5, 1, 0, 0, 0, 1, 0, 1, 2, 0],
        (n_legit, 10),
    )
    y_legit = np.zeros(n_legit)

    # Phishing: long URLs, no HTTPS, many forms/iframes/scripts
    X_phish = np.random.normal(
        [80, 5, 1, 0, 1, 3, 2, 1, 10, 1],
        [10, 2, 0, 0, 0, 2, 1,  1,  5, 0],
        (n_phish, 10),
    )
    y_phish = np.ones(n_phish)

    X = np.vstack([X_legit, X_phish])
    y = np.hstack([y_legit, y_phish])

    indices = np.arange(len(X))
    np.random.shuffle(indices)
    return X[indices], y[indices]


def train():
    """
    Main training function.

    Attempts to load real feature data from the processed parquet.
    Falls back to synthetic data when fewer than MIN_REAL_SAMPLES real
    samples are available (e.g. because live HTTP fetches timed out
    during feature extraction).
    """
    os.makedirs(os.path.dirname(BASELINE_MODEL), exist_ok=True)

    data_source = "unknown"
    try:
        df = process_data()
        feat_cols = [f"feature_{i+1}" for i in range(10)]
        if len(df) >= MIN_REAL_SAMPLES and all(c in df.columns for c in feat_cols):
            X = df[feat_cols].values
            y = df["label"].values
            data_source = f"real CSV ({len(df)} samples)"
            logger.info(f"Using real data from CSV: {len(df)} samples.")
        else:
            raise ValueError(
                f"Only {len(df)} real samples survived feature extraction "
                f"(minimum required: {MIN_REAL_SAMPLES})."
            )
    except (FileNotFoundError, ValueError) as exc:
        logger.warning(
            f"Falling back to synthetic data. Reason: {exc}"
        )
        X, y = generate_synthetic_data()
        data_source = "synthetic (200 samples, Gaussian - no real-world validity)"
    X_train, X_test, y_train, y_test = split_data(X, y, test_size=0.2, random_state=42)

    print()
    print("=" * 60)
    print("TRAINING - PHISHING DETECTOR (URL/HTML MODEL)")
    print("=" * 60)
    print(f"  Data source  : {data_source}")
    print(f"  Total samples: {len(X)}")
    print(f"  Train / Test : {len(X_train)} / {len(X_test)}")
    if "synthetic" in data_source:
        print()
        print("  WARNING: Model trained on SYNTHETIC data.")
        print("  Reported metrics do NOT reflect real-world performance.")
    print()

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    y_pred  = model.predict(X_test)
    y_proba = model.predict_proba(X_test)
    metrics = compute_metrics(y_test, y_pred, y_proba)

    joblib.dump(model, BASELINE_MODEL)
    logger.info(f"Model saved to {BASELINE_MODEL}")
    print(f"  Model saved  : {BASELINE_MODEL}")
    print("=" * 60)

    return metrics


if __name__ == "__main__":
    train()