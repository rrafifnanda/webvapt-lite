import json
from pathlib import Path


def write_json(findings, path: str):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps([f.model_dump() for f in findings], indent=2))


def write_md(findings, score: int, grade: str, path: str):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    lines = [f"# webvapt report — {score}/100 ({grade})", ""]
    for f in findings:
        lines.append(f"- [{f.severity}] {f.check} @ {f.url}")
    Path(path).write_text("\n".join(lines) + "\n")
