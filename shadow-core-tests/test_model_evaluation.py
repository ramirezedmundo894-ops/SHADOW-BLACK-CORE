import io
import json
import math

import pytest

from shadow_core.model_evaluation import (
    EvaluationInputError,
    evaluate_predictions,
    read_jsonl,
)


def test_evaluation_reports_confusion_and_probability_metrics():
    rows = [
        {"label": True, "probability": 0.9},
        {"label": True, "probability": 0.2},
        {"label": False, "probability": 0.8},
        {"label": False, "probability": 0.1},
    ]
    report = evaluate_predictions(rows, threshold=0.5)
    assert (report.true_positive, report.false_positive, report.true_negative, report.false_negative) == (1, 1, 1, 1)
    assert report.accuracy == pytest.approx(0.5)
    assert report.precision == pytest.approx(0.5)
    assert report.recall == pytest.approx(0.5)
    assert report.specificity == pytest.approx(0.5)
    assert report.false_positive_rate == pytest.approx(0.5)
    assert report.false_negative_rate == pytest.approx(0.5)
    assert report.brier_score == pytest.approx(0.325)
    assert report.observed_positive_rate == pytest.approx(0.5)
    assert report.mean_predicted_probability == pytest.approx(0.5)
    assert report.confidence_level == pytest.approx(0.95)
    assert report.confidence_interval_method == "Wilson score"
    recall_interval = report.confidence_intervals["recall"]
    assert recall_interval.successes == 1
    assert recall_interval.trials == 2
    assert 0 <= recall_interval.lower < report.recall < recall_interval.upper <= 1


def test_missing_class_rates_are_none_not_zero():
    report = evaluate_predictions([{"label": True, "probability": 0.7}])
    assert report.specificity is None
    assert report.false_positive_rate is None
    assert report.false_negative_rate == 0.0
    assert report.confidence_intervals["specificity"] is None
    assert report.confidence_intervals["false_positive_rate"] is None
    assert report.confidence_intervals["recall"].trials == 1


@pytest.mark.parametrize("rows", [[], [{"label": 1, "probability": 0.4}],
                                   [{"label": False, "probability": True}],
                                   [{"label": False, "probability": math.nan}],
                                   [{"label": False, "probability": 1.1}],
                                   [{"label": False, "probability": 0.4, "subject": "must-not-be-included"}]])
def test_invalid_or_empty_datasets_are_rejected(rows):
    with pytest.raises(EvaluationInputError):
        evaluate_predictions(rows)


def test_jsonl_reader_rejects_malformed_rows_without_echoing_row_content():
    source = io.StringIO('{"label": false, "probability": 0.2}\n{"subject":"private"}\n')
    iterator = read_jsonl(source)
    assert next(iterator) == {"label": False, "probability": 0.2}
    with pytest.raises(EvaluationInputError, match="line 2") as error:
        next(iterator)
    assert "private" not in str(error.value)


def test_jsonl_reader_rejects_nonfinite_json_number():
    with pytest.raises(EvaluationInputError, match="line 1"):
        list(read_jsonl(io.StringIO('{"label": true, "probability": NaN}\n')))


def test_jsonl_cli_emits_machine_readable_report(tmp_path, capsys):
    from shadow_core.model_evaluation import main

    dataset = tmp_path / "reviewed.jsonl"
    dataset.write_text(json.dumps({"label": True, "probability": 0.9}) + "\n", encoding="utf-8")
    assert main([str(dataset), "--threshold", "0.7"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["sample_count"] == 1
    assert result["true_positive"] == 1
    assert result["threshold"] == pytest.approx(0.7)
    assert result["confidence_interval_method"] == "Wilson score"
    assert result["confidence_intervals"]["recall"]["successes"] == 1
    assert result["confidence_intervals"]["recall"]["trials"] == 1


def test_wilson_intervals_remain_informative_with_one_sample():
    report = evaluate_predictions([{"label": True, "probability": 0.8}])
    recall = report.confidence_intervals["recall"]
    false_negative_rate = report.confidence_intervals["false_negative_rate"]
    assert recall.lower == pytest.approx(0.20654931437723745)
    assert recall.upper == 1.0
    assert false_negative_rate.lower == 0.0
    assert false_negative_rate.upper == pytest.approx(0.7934506856227626)


def test_threshold_must_be_finite_and_bounded():
    for threshold in (True, math.nan, -0.01, 1.01):
        with pytest.raises(EvaluationInputError):
            evaluate_predictions([{"label": False, "probability": 0.2}], threshold=threshold)
