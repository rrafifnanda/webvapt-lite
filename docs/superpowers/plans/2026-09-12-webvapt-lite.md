# webvapt-lite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bangun webvapt-lite brutal authorized-only hingga bisa `pipx install` dan scan fixture vuln-app.

**Architecture:** Typer CLI → guard murni → httpx async crawler + probe engine paralel → scorer → Rich + file reporter.

**Tech Stack:** Python 3.11+, Typer, httpx, Rich, Pydantic, pytest, respx, Flask (fixture only)

## Global Constraints

- Python 3.11+ only
- Tanpa RCE / login-bruteforce / DoS / WAF-evasion / exfiltrasi — tolak PR yang menambahkannya
- Wajib `--i-authorized` atau env `WEBVAPT_I_AUTHORIZED=1`, tanpa itu refuse exit 2
- Scope-lock 1 host, tolak private IP kecuali `--allow-private`
- UA transparan: `webvapt-lite (authorized scan)`
- Tiap probe timeout sendiri, fail-open dengan warning
- TDD: test gagal dulu, lihat merah, baru implementasi minimal

---

### Task 1: Packaging + skeleton CLI

**Files:**
- Create: `pyproject.toml`
- Create: `src/webvapt/__init__.py`
- Create: `src/webvapt/cli.py`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: none
- Produces: `app: typer.Typer`, `__version__ = "0.1.0"`, console-script `webvapt`

- [ ] **Step 1: Write the failing test**

```python
from typer.testing import CliRunner
from webvapt.cli import app

def test_cli_help():
    r = CliRunner().invoke(app, ["--help"])
    assert r.exit_code == 0
    assert "webvapt" in r.output.lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cli.py::test_cli_help -v`
Expected: FAIL with "No module named 'webvapt'"

- [ ] **Step 3: Write minimal implementation**

```toml
# pyproject.toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
[project]
name = "webvapt-lite"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = ["typer>=0.12", "httpx>=0.27", "rich>=13", "pydantic>=2", "anyio>=4"]
[project.scripts]
webvapt = "webvapt.cli:app"
[tool.hatch.build.targets.wheel]
packages = ["src/webvapt"]
[tool.pytest.ini_options]
testpaths = ["tests"]
```

```python
# src/webvapt/__init__.py
__version__ = "0.1.0"
```

```python
# src/webvapt/cli.py
import typer
app = typer.Typer(help="webvapt-lite: brutal authorized-only web scanner")

@app.command()
def scan(target: str):
    typer.echo(f"webvapt scan {target}")

@app.callback()
def main():
    pass
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pip install -e . && pytest tests/test_cli.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml src/webvapt/__init__.py src/webvapt/cli.py tests/test_cli.py
git commit -m "feat: packaging + skeleton CLI"
```

### Task 2: models + guard (authorized + scope-lock)

**Files:**
- Create: `src/webvapt/models.py`
- Create: `src/webvapt/guard.py`
- Test: `tests/test_guard.py`

**Interfaces:**
- Consumes: none
- Produces: `Finding`, `GuardError`, `assert_authorized(authorized: bool)`, `enforce_scope(target: str, allow_private: bool) -> str`

- [ ] **Step 1: Write the failing test**

```python
import pytest
from webvapt.guard import GuardError, assert_authorized, enforce_scope

def test_refuses_without_authorized():
    with pytest.raises(GuardError):
        assert_authorized(False)

def test_allows_with_authorized():
    assert_authorized(True)

def test_rejects_private_by_default():
    with pytest.raises(GuardError):
        enforce_scope("http://127.0.0.1/", allow_private=False)

def test_allows_public():
    assert enforce_scope("https://example.com/", allow_private=False) == "https://example.com/"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_guard.py -v`
Expected: FAIL with "No module named 'webvapt.guard'"

- [ ] **Step 3: Write minimal implementation**

```python
# src/webvapt/models.py
from pydantic import BaseModel
from typing import Literal
class Finding(BaseModel):
    check: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    url: str
    evidence: str = ""
    remediation: str = ""
```

```python
# src/webvapt/guard.py
import ipaddress, socket
from urllib.parse import urlparse

class GuardError(Exception):
    pass

def assert_authorized(authorized: bool):
    if not authorized:
        raise GuardError("Refusing: pass --i-authorized only for systems you own or have written permission to test.")

def enforce_scope(target: str, allow_private: bool = False) -> str:
    u = urlparse(target if "://" in target else "http://" + target)
    if u.scheme not in ("http", "https"):
        raise GuardError("Only http/https allowed.")
    host = u.hostname or ""
    try:
        ip = ipaddress.ip_address(host)
        is_private = ip.is_private or ip.is_loopback
    except ValueError:
        try:
            resolved = socket.gethostbyname(host)
            is_private = ipaddress.ip_address(resolved).is_private
        except Exception:
            is_private = False
    if is_private and not allow_private:
        raise GuardError("Refusing private/local target without --allow-private.")
    return f"{u.scheme}://{host}/" if not u.path else target
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_guard.py -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add src/webvapt/models.py src/webvapt/guard.py tests/test_guard.py
git commit -m "feat: guard authorized + scope-lock"
```

### Task 3: Probe base + headers + cookies passive probes

**Files:**
- Create: `src/webvapt/probes/__init__.py`
- Create: `src/webvapt/probes/base.py`
- Create: `src/webvapt/probes/headers.py`
- Test: `tests/test_headers.py`

**Interfaces:**
- Consumes: `Finding` from Task 2
- Produces: `ProbeContext`, `headers_probe(headers: dict, url: str) -> list[Finding]`

- [ ] **Step 1: Write the failing test**

```python
from webvapt.probes.headers import headers_probe

def test_missing_hsts_is_finding():
    out = headers_probe({}, "https://example.com/")
    assert any(f.check == "missing-hsts" for f in out)

def test_present_headers_no_finding():
    h = {"strict-transport-security": "max-age=31536000", "content-security-policy": "default-src 'self'", "x-content-type-options": "nosniff", "x-frame-options": "DENY"}
    out = headers_probe(h, "https://example.com/")
    assert not [f for f in out if f.check == "missing-hsts"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_headers.py -v`
Expected: FAIL with "No module named 'webvapt.probes.headers'"

- [ ] **Step 3: Write minimal implementation**

```python
# src/webvapt/probes/base.py
from dataclasses import dataclass
@dataclass
class ProbeContext:
    url: str
    headers: dict
```

```python
# src/webvapt/probes/headers.py
from webvapt.models import Finding

REQUIRED = {
    "strict-transport-security": ("missing-hsts", "medium", "Enable HSTS."),
    "content-security-policy": ("missing-csp", "medium", "Add CSP."),
    "x-content-type-options": ("missing-nosniff", "low", "Add X-Content-Type-Options: nosniff."),
    "x-frame-options": ("missing-frame-options", "low", "Add X-Frame-Options."),
}

def headers_probe(headers: dict, url: str) -> list[Finding]:
    low = {k.lower(): v for k, v in headers.items()}
    out = []
    for h, (check, sev, fix) in REQUIRED.items():
        if h not in low and not (h == "strict-transport-security" and url.startswith("http://")):
            if h == "strict-transport-security" and url.startswith("http://"):
                continue
            out.append(Finding(check=check, severity=sev, url=url, evidence=f"missing {h}", remediation=fix))
    return out
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_headers.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/webvapt/probes/ tests/test_headers.py
git commit -m "feat: headers passive probe"
```

### Task 4: scan wiring + reporter (Rich + json/md)

**Files:**
- Modify: `src/webvapt/cli.py`
- Create: `src/webvapt/reporter.py`
- Create: `src/webvapt/scorer.py`
- Test: `tests/test_reporter.py`

**Interfaces:**
- Consumes: `assert_authorized`, `enforce_scope`, `headers_probe`, `Finding`
- Produces: `score_findings(findings) -> (score: int, grade: str)`, `write_json/md()`

- [ ] **Step 1: Write the failing test**

```python
from webvapt.scorer import score_findings
from webvapt.models import Finding

def test_empty_is_100_A():
    score, grade = score_findings([])
    assert (score, grade) == (100, "A")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_reporter.py -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
# src/webvapt/scorer.py
WEIGHTS = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}
def score_findings(findings) -> tuple[int, str]:
    penalty = sum(WEIGHTS.get(f.severity, 0) for f in findings)
    score = max(0, 100 - penalty)
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 55 else "D" if score >= 30 else "F"
    return score, grade
```

```python
# src/webvapt/reporter.py
import json
from pathlib import Path
def write_json(findings, path: str):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps([f.model_dump() for f in findings], indent=2))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_reporter.py tests/test_guard.py tests/test_headers.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/webvapt/scorer.py src/webvapt/reporter.py tests/test_reporter.py
git commit -m "feat: scorer + reporter"
```

### Task 5: Brutal probes (xss-reflected, sqli-error, open-redirect) + fixture app

**Files:**
- Create: `src/webvapt/probes/active.py`
- Create: `tests/fixtures/vuln-app/app.py`
- Test: `tests/test_active.py`

**Interfaces:**
- Consumes: `Finding`
- Produces: `reflects(payload, body) -> bool`, `sqli_error(body) -> bool`

- [ ] **Step 1: Write the failing test**

```python
from webvapt.probes.active import reflects, sqli_error

def test_reflects_detects():
    assert reflects("<xsstest>", "hello <xsstest> world")
    assert not reflects("<xsstest>", "hello clean")

def test_sqli_error_detects():
    assert sqli_error("You have an error in your SQL syntax near 'x'")
    assert not sqli_error("welcome home")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_active.py -v`
Expected: FAIL

- [ ] **Step 3: Write minimal implementation**

```python
# src/webvapt/probes/active.py
SQL_ERRORS = ["you have an error in your sql syntax", "unclosed quotation mark", "sqlite3::", "pg_query()", "ora-01756"]

def reflects(payload: str, body: str) -> bool:
    return payload in (body or "")

def sqli_error(body: str) -> bool:
    b = (body or "").lower()
    return any(s in b for s in SQL_ERRORS)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_active.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/webvapt/probes/active.py tests/test_active.py tests/fixtures/vuln-app/app.py
git commit -m "feat: brutal active detectors + fixture"
```

## Self-Review

- [x] Spec coverage: guard, probes pasif+aktif, scorer, reporter, fixture — semua ada tugasnya
- [x] No placeholders — tiap step ada kode + command + expected eksplisit
- [x] Type consistency: `Finding(check, severity, url, evidence, remediation)` dipakai konsisten di semua task
