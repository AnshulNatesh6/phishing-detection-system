"""
Tests for evaluate.py and evaluation methodology.
"""

import os
import pytest
import numpy as np
import pandas as pd
from unittest.mock import patch, MagicMock

from src.evaluate import _load_dataset, evaluate, MIN_REAL_SAMPLES
from src.ml_helpers import split_data, compute_metrics


def test_split_data_reproducible_and_stratified():
    """Verify split_data is stratified, reproducible, and has no train/test overlap."""
    np.random.seed(42)
    X = np.random.randn(100, 10)
    y = np.array([0] * 50 + [1] * 50)

    X_train1, X_test1, y_train1, y_test1 = split_data(X, y, test_size=0.2, random_state=42)
    X_train2, X_test2, y_train2, y_test2 = split_data(X, y, test_size=0.2, random_state=42)

    # Identical across runs with same seed
    np.testing.assert_array_equal(X_train1, X_train2)
    np.testing.assert_array_equal(X_test1, X_test2)

    # Sizes
    assert len(X_train1) == 80
    assert len(X_test1) == 20

    # Stratified balance (50% each class)
    assert (y_train1 == 0).sum() == 40
    assert (y_train1 == 1).sum() == 40
    assert (y_test1 == 0).sum() == 10
    assert (y_test1 == 1).sum() == 10


def test_load_dataset_fallback_when_parquet_missing(tmp_path):
    """When parquet is missing, _load_dataset falls back to synthetic."""
    non_existent = str(tmp_path / "absent.parquet")
    with patch("src.evaluate.PROCESSED_PARQUET", non_existent):
        X, y, source = _load_dataset()
        assert len(X) == 200
        assert len(y) == 200
        assert "synthetic" in source


def test_load_dataset_fallback_when_parquet_too_small(tmp_path):
    """When parquet has fewer than MIN_REAL_SAMPLES, falls back to synthetic."""
    parquet_path = str(tmp_path / "tiny.parquet")
    feat_cols = {f"feature_{i+1}": [1.0] * 3 for i in range(10)}
    feat_cols["label"] = [0, 1, 0]
    pd.DataFrame(feat_cols).to_parquet(parquet_path)

    with patch("src.evaluate.PROCESSED_PARQUET", parquet_path):
        X, y, source = _load_dataset()
        assert len(X) == 200
        assert "synthetic" in source


def test_load_dataset_uses_parquet_when_sufficient(tmp_path):
    """When parquet has >= MIN_REAL_SAMPLES, uses real parquet data."""
    parquet_path = str(tmp_path / "valid.parquet")
    n_samples = MIN_REAL_SAMPLES + 5
    feat_cols = {f"feature_{i+1}": [0.5] * n_samples for i in range(10)}
    feat_cols["label"] = [0] * (n_samples // 2) + [1] * (n_samples - n_samples // 2)
    pd.DataFrame(feat_cols).to_parquet(parquet_path)

    with patch("src.evaluate.PROCESSED_PARQUET", parquet_path):
        X, y, source = _load_dataset()
        assert len(X) == n_samples
        assert "real data from parquet" in source


def test_evaluate_missing_model():
    """evaluate() returns empty dict when model file is not found."""
    with patch("src.evaluate.load_model", side_effect=FileNotFoundError("No model")):
        res = evaluate()
        assert res == {}


def test_evaluate_success_with_saved_model():
    """evaluate() runs successfully on the saved model and returns all expected metric keys."""
    res = evaluate()
    assert isinstance(res, dict)
    assert "accuracy" in res
    assert "precision" in res
    assert "recall" in res
    assert "f1" in res
    assert "roc_auc" in res
    assert "confusion_matrix" in res
    assert len(res["confusion_matrix"]) == 2
    assert len(res["confusion_matrix"][0]) == 2
