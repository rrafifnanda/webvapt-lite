from webvapt.models import Finding
from webvapt.scorer import score_findings


def test_empty_is_100_A():
    score, grade = score_findings([])
    assert (score, grade) == (100, "A")


def test_high_penalty():
    f = [Finding(check="x", severity="high", url="https://example.com/")]
    score, _ = score_findings(f)
    assert score == 90
