# webvapt-lite — Brutal Authorized-Only Web Scanner — Design

> Status: approved by user (brutal authorized-only, tanpa RCE/DoS/credential-brute/WAF-evasion)

**Goal:** CLI Python async untuk audit web menyeluruh dengan sekali perintah, menghasilkan skor 0-100 + report siap tempel.

**Architecture:** CLI (Typer) → ScopeGuard → Crawler → Probe Engine (async paralel) → Scorer → Reporter. Evidence store simpan raw req/res untuk audit.

**Tech Stack:** Python 3.11+, Typer, httpx (async), Rich, Pydantic, anyio, pytest + respx.

## Boundaries (disepakati)

Brutal = thorough & agresif saat authorized:
- concurrency tinggi (default 10, brutal 20-50), crawl depth 3, wordlist dirs besar
- probe pasif: headers, SSL, cookies, CORS, tech-fingerprint
- probe aktif non-destruktif: dirs, param-discovery, xss-reflected, sqli-error, lfi, ssrf-canary, open-redirect, jwt-weak lokal

Tetap EXCLUDE (demi GitHub + UU ITE):
- RCE / reverse shell / eksekusi exploit
- credential bruteforce login, DoS/flood, WAF-evasion/stealth, exfiltrasi data
- SSRF hanya deteksi via canary, tanpa baca metadata cloud

Guardrails wajib:
- `--i-authorized` atau env `WEBVAPT_I_AUTHORIZED=1`, tanpa itu refuse
- scope-lock 1 target, tolak private IP/range kecuali `--allow-private`
- rate-limit default, UA transparan `webvapt-lite (authorized scan)`
- LEGAL NOTICE ID/EN + SECURITY.md authorized-only

## Components

- `cli.py`: parsing arg, profile quick/standard/brutal, output json/sarif/md/html, exit-code non-zero jika High/Critical
- `guard.py`: `assert_authorized(), enforce_scope(target)` — pure function, gampang di-test
- `models.py`: `Finding(severity, check, url, evidence, remediation)`, `Target`
- `crawl/`: AsyncClient, same-host only, kumpulkan URL+form+param
- `probes/base.py`: interface `async run(ctx) -> list[Finding]`, tiap probe isolated + timeout sendiri
- `scorer.py`: bobot Critical 25, High 10, Medium 4, Low 1 → 0-100 + grade A-F
- `reporter.py`: Rich table + file writer, tidak campur logika scan

## Data flow

`scan <target> --brutal --i-authorized` → guard → crawl → probes paralel → dedup → score → terminal + `output/scan-<ts>.json/md/html` + evidence raw.

## Error handling

Timeout per-probe, retry 1x, fail-open (modul gagal → warning, scan lanjut). Semua failure tercatat di report, bukan crash.

## Testing (evidence path)

- unit per-probe dengan respx mock
- integrasi lawan `tests/fixtures/vuln-app/` (Flask mini dengan XSS/SQLi sengaja)
- guard 100% coverage (kasus tolak paling penting)
- target coverage 80%+ core/guard, CI pytest + ruff

## OSS-kit

MIT, README + GIF 30 detik + contoh skor, CONTRIBUTING panduan nambah probe, PyPI/pipx, GitHub Action contoh, SARIF buat code-scanning.

## Roadmap

- M1: CLI + guard + 5 probe pasif + reporter
- M2: crawler + 7 probe aktif + scorer + brutal profile
- M3: SARIF/HTML, GH Action, PyPI, docs + demo

## Self-review

- [x] No TBD/TODO — semua modul konkret
- [x] Konsisten: guard → crawler → probes → scorer → reporter, tidak ada kontradiksi
- [x] Scope single spec, tidak melebar ke network scanner / SAST
- [x] Brutal didefinisikan eksplisit (apa masuk / apa exclude), tidak ambigu
