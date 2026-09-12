# webvapt-lite

Brutal **authorized-only** web scanner (Python CLI). Satu perintah → skor 0-100 + report siap tempel.

> ⚠️ Hanya untuk sistem milikmu / ada izin tertulis. Tanpa `--i-authorized`, tool menolak jalan. Lihat `SECURITY.md`.

## Install

```bash
pipx install webvapt-lite
# atau
pip install -e .
```

## Pakai

```bash
webvapt scan https://example.com --i-authorized
webvapt scan https://example.com --i-authorized --output-json out.json --output-md out.md
WEBVAPT_I_AUTHORIZED=1 webvapt scan https://example.com --i-authorized
```

Tanpa izin → exit 2. Target private/local ditolak kecuali `--allow-private`.

## Yang dicek (M1+M2 awal)

- Pasif: HSTS, CSP, nosniff, frame-options (+ skor)
- Aktif non-destruktif: detektor XSS reflected + SQLi error (lihat `tests/fixtures/vuln-app/`)

## Batasan brutal (disengaja)

No RCE, no login-bruteforce, no DoS, no WAF-evasion, no exfiltrasi. SSRF hanya canary bila ditambah nanti.

## Dev

```bash
python -m venv .venv && .venv/bin/pip install -e . pytest respx flask
.venv/bin/python -m pytest -q
```
