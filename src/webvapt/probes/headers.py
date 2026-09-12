from webvapt.models import Finding

REQUIRED = {
    "strict-transport-security": ("missing-hsts", "medium", "Enable HSTS."),
    "content-security-policy": ("missing-csp", "medium", "Add CSP."),
    "x-content-type-options": ("missing-nosniff", "low", "Add X-Content-Type-Options: nosniff."),
    "x-frame-options": ("missing-frame-options", "low", "Add X-Frame-Options."),
}


def headers_probe(headers: dict, url: str) -> list[Finding]:
    low = {k.lower(): v for k, v in headers.items()}
    out: list[Finding] = []
    for h, (check, sev, fix) in REQUIRED.items():
        if h in low:
            continue
        if h == "strict-transport-security" and url.startswith("http://"):
            continue
        out.append(
            Finding(check=check, severity=sev, url=url, evidence=f"missing {h}", remediation=fix)
        )
    return out
