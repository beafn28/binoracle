"""D16: Confidence calibration — tracks prediction accuracy and auto-adjusts thresholds.

State stored in ~/.cache/binoracle/confidence_calibration.json.
Thread-safe via atomic rename. No external dependencies — stdlib only.

Usage:
    from .confidence_calibration import record_prediction, calibrated_threshold

    # After each investigation completes:
    record_prediction(predicted_confidence=0.85, actually_verified=True)

    # Instead of hard-coded threshold:
    threshold = calibrated_threshold(raw_threshold=0.75)
"""
from __future__ import annotations

import json
import math
import os

_STATE_DIR = os.environ.get("BINORACLE_CACHE_DIR") or os.path.join(
    os.path.expanduser("~"), ".cache", "binoracle"
)
_CAL_FILE = os.path.join(_STATE_DIR, "confidence_calibration.json")

_DEFAULT_THRESHOLD = 0.75
_MIN_SAMPLES = 20       # don't adjust until we have enough data
_BUCKET_SIZE = 0.05     # 5% wide buckets: [0.70, 0.75), [0.75, 0.80) …


def _load() -> dict:
    try:
        with open(_CAL_FILE, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def _save(data: dict) -> None:
    try:
        os.makedirs(_STATE_DIR, exist_ok=True)
        tmp = _CAL_FILE + f".tmp-{os.getpid()}"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, _CAL_FILE)
    except Exception:
        pass


def _bucket_key(confidence: float) -> str:
    b = math.floor(confidence / _BUCKET_SIZE) * _BUCKET_SIZE
    return f"{b:.2f}"


def record_prediction(predicted_confidence: float, actually_verified: bool) -> None:
    """Record one prediction outcome for calibration tracking."""
    data = _load()
    buckets: dict = data.setdefault("buckets", {})
    total: dict = data.setdefault("totals", {"predictions": 0, "verified": 0})
    key = _bucket_key(max(0.0, min(1.0, predicted_confidence)))
    b = buckets.setdefault(key, {"predictions": 0, "verified": 0})
    b["predictions"] += 1
    b["verified"] += int(actually_verified)
    total["predictions"] += 1
    total["verified"] += int(actually_verified)
    _save(data)


def calibration_summary() -> dict:
    """Return per-bucket accuracy rates and overall stats."""
    data = _load()
    buckets = data.get("buckets") or {}
    result: dict = {}
    for key, b in sorted(buckets.items()):
        preds = b.get("predictions", 0)
        verf  = b.get("verified", 0)
        result[key] = {
            "predictions": preds,
            "verified": verf,
            "accuracy": round(verf / preds, 3) if preds else None,
        }
    totals = data.get("totals") or {}
    overall = totals.get("predictions", 0)
    return {
        "buckets": result,
        "total_predictions": overall,
        "total_verified": totals.get("verified", 0),
        "overall_accuracy": round(totals.get("verified", 0) / overall, 3) if overall else None,
    }


def calibrated_threshold(raw_threshold: float = _DEFAULT_THRESHOLD) -> float:
    """D16: Return an adjusted threshold based on observed calibration data.

    If confidence=raw_threshold historically verifies > 60% of the time,
    keep the threshold as-is. If it verifies < 30%, raise the threshold
    to reduce false positives. Applies only when _MIN_SAMPLES are available.
    """
    data = _load()
    buckets = data.get("buckets") or {}
    key = _bucket_key(raw_threshold)
    b = buckets.get(key) or {}
    preds = b.get("predictions", 0)
    verf  = b.get("verified", 0)
    if preds < _MIN_SAMPLES:
        return raw_threshold
    accuracy = verf / preds
    if accuracy < 0.30:
        # Raise threshold by one bucket (5%) — the model is overconfident
        return min(raw_threshold + _BUCKET_SIZE, 0.95)
    if accuracy > 0.70 and raw_threshold > 0.65:
        # Allow slightly lower threshold — the model is well-calibrated
        return max(raw_threshold - _BUCKET_SIZE, 0.60)
    return raw_threshold


def calibration_report_lines() -> list[str]:
    """Return a compact multi-line calibration status for engine logs."""
    summary = calibration_summary()
    lines = [f"calibration: {summary['total_predictions']} predictions, "
             f"overall accuracy={summary['overall_accuracy']}"]
    for key, b in summary["buckets"].items():
        acc = b["accuracy"]
        lines.append(
            f"  confidence {key}–{float(key) + _BUCKET_SIZE:.2f}: "
            f"{b['predictions']}x, accuracy={acc}"
        )
    return lines
