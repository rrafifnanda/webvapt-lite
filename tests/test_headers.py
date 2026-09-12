from webvapt.probes.headers import headers_probe


def test_missing_hsts_is_finding():
    out = headers_probe({}, "https://example.com/")
    assert any(f.check == "missing-hsts" for f in out)


def test_present_headers_no_finding():
    h = {
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
    }
    out = headers_probe(h, "https://example.com/")
    assert not [f for f in out if f.check == "missing-hsts"]
