WEIGHTS = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}


def score_findings(findings) -> tuple[int, str]:
    penalty = sum(WEIGHTS.get(f.severity, 0) for f in findings)
    score = max(0, 100 - penalty)
    grade = (
        "A"
        if score >= 90
        else "B"
        if score >= 75
        else "C"
        if score >= 55
        else "D"
        if score >= 30
        else "F"
    )
    return score, grade
