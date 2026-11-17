"""Offline evaluator for candidate shadow-model probabilities.

This module is deliberately separate from request handling: its output cannot
change SHADOW CORE's deterministic policy or operational decisions.
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, TextIO


class EvaluationInputError(ValueError):
    """A labeled evaluation row is malformed or the dataset is unusable."""


@dataclass(frozen=True)
class BinomialInterval:
    """Wilson score interval for one binomial rate; null when trials are zero."""

    successes: int
    trials: int
    lower: float
    upper: float


@dataclass(frozen=True)
class EvaluationReport:
    sample_count: int
    threshold: float
    confidence_level: float
    confidence_interval_method: str
    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int
    accuracy: float | None
    precision: float | None
    recall: float | None
    specificity: float | None
    false_positive_rate: float | None
    false_negative_rate: float | None
    brier_score: float
    observed_positive_rate: float
    mean_predicted_probability: float
    confidence_intervals: dict[str, BinomialInterval | None]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _wilson_interval(successes: int, trials: int) -> BinomialInterval | None:
    """Return a two-sided 95% Wilson score interval for a binomial rate."""
    if trials == 0:
        return None
    z = 1.959963984540054  # standard-normal 97.5th percentile
    observed_rate = successes / trials
    z_squared = z * z
    denominator = 1 + z_squared / trials
    center = (observed_rate + z_squared / (2 * trials)) / denominator
    margin = z * math.sqrt(
        observed_rate * (1 - observed_rate) / trials
        + z_squared / (4 * trials * trials)
    ) / denominator
    return BinomialInterval(
        successes=successes,
        trials=trials,
        lower=max(0.0, center - margin),
        upper=min(1.0, center + margin),
    )


def _validate_threshold(threshold: float) -> float:
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
        raise EvaluationInputError("threshold must be a finite number from 0 to 1")
    value = float(threshold)
    if not math.isfinite(value) or not 0 <= value <= 1:
        raise EvaluationInputError("threshold must be a finite number from 0 to 1")
    return value


def evaluate_predictions(rows: Iterable[Mapping[str, Any]], *, threshold: float = 0.5) -> EvaluationReport:
    """Compute offline classification metrics from `{label, probability}` rows.

    `label` is the independently reviewed ground truth (true means positive);
    `probability` is the model's estimated probability for that positive label.
    Rows accept no extra fields, keeping identifiers/features out of this
    aggregate-only evaluator. Undefined class-specific rates are returned as
    `None`, never silently represented as zero.
    """
    threshold = _validate_threshold(threshold)
    tp = fp = tn = fn = 0
    squared_error = probability_sum = positive_labels = 0.0
    count = 0

    for index, row in enumerate(rows, start=1):
        if not isinstance(row, Mapping) or set(row) != {"label", "probability"}:
            raise EvaluationInputError(f"row {index} must contain only label and probability")
        label = row["label"]
        probability = row["probability"]
        if not isinstance(label, bool):
            raise EvaluationInputError(f"row {index} label must be a boolean ground-truth value")
        if isinstance(probability, bool) or not isinstance(probability, (int, float)):
            raise EvaluationInputError(f"row {index} probability must be a finite number from 0 to 1")
        probability = float(probability)
        if not math.isfinite(probability) or not 0 <= probability <= 1:
            raise EvaluationInputError(f"row {index} probability must be a finite number from 0 to 1")

        predicted_positive = probability >= threshold
        if label and predicted_positive:
            tp += 1
        elif label:
            fn += 1
        elif predicted_positive:
            fp += 1
        else:
            tn += 1
        positive_labels += int(label)
        probability_sum += probability
        squared_error += (probability - int(label)) ** 2
        count += 1

    if count == 0:
        raise EvaluationInputError("dataset must contain at least one labeled row")

    return EvaluationReport(
        sample_count=count,
        threshold=threshold,
        confidence_level=0.95,
        confidence_interval_method="Wilson score",
        true_positive=tp,
        false_positive=fp,
        true_negative=tn,
        false_negative=fn,
        accuracy=(tp + tn) / count,
        precision=_ratio(tp, tp + fp),
        recall=_ratio(tp, tp + fn),
        specificity=_ratio(tn, tn + fp),
        false_positive_rate=_ratio(fp, fp + tn),
        false_negative_rate=_ratio(fn, fn + tp),
        brier_score=squared_error / count,
        observed_positive_rate=positive_labels / count,
        mean_predicted_probability=probability_sum / count,
        confidence_intervals={
            "accuracy": _wilson_interval(tp + tn, count),
            "precision": _wilson_interval(tp, tp + fp),
            "recall": _wilson_interval(tp, tp + fn),
            "specificity": _wilson_interval(tn, tn + fp),
            "false_positive_rate": _wilson_interval(fp, fp + tn),
            "false_negative_rate": _wilson_interval(fn, fn + tp),
        },
    )


def read_jsonl(stream: TextIO) -> Iterable[Mapping[str, Any]]:
    """Yield strict JSON objects; errors identify line numbers, not row data."""
    for line_number, line in enumerate(stream, start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise EvaluationInputError(f"line {line_number} is not valid JSON") from exc
        if not isinstance(row, dict):
            raise EvaluationInputError(f"line {line_number} must be a JSON object")
        try:
            # Validate row shape and values before yielding, without retaining data.
            _validate_row(row, line_number)
        except EvaluationInputError:
            raise
        yield row


def _validate_row(row: Mapping[str, Any], line_number: int) -> None:
    if set(row) != {"label", "probability"}:
        raise EvaluationInputError(f"line {line_number} must contain only label and probability")
    if not isinstance(row["label"], bool):
        raise EvaluationInputError(f"line {line_number} label must be a boolean ground-truth value")
    probability = row["probability"]
    if isinstance(probability, bool) or not isinstance(probability, (int, float)):
        raise EvaluationInputError(f"line {line_number} probability must be a finite number from 0 to 1")
    if not math.isfinite(float(probability)) or not 0 <= probability <= 1:
        raise EvaluationInputError(f"line {line_number} probability must be a finite number from 0 to 1")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate candidate model probabilities against reviewed labels (offline only).")
    parser.add_argument("dataset", type=Path, help="JSONL with only label and probability per row")
    parser.add_argument("--threshold", type=float, default=0.5, help="offline candidate threshold (default: 0.5)")
    args = parser.parse_args(argv)
    try:
        with args.dataset.open("r", encoding="utf-8") as stream:
            report = evaluate_predictions(read_jsonl(stream), threshold=args.threshold)
    except (OSError, EvaluationInputError) as exc:
        print(f"evaluation failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report.to_dict(), indent=2, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
