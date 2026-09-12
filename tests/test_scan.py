import respx
from typer.testing import CliRunner

from webvapt.cli import app


def test_scan_refuses_without_auth():
    r = CliRunner().invoke(app, ["scan", "https://example.com/"])
    assert r.exit_code == 2
    assert "authorized" in r.output.lower()


@respx.mock
def test_scan_passive_ok():
    respx.get("https://example.com/").mock(
        return_value=__import__("httpx").Response(
            200,
            headers={
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": "default-src 'self'",
                "x-content-type-options": "nosniff",
                "x-frame-options": "DENY",
            },
            text="hi",
        )
    )
    r = CliRunner().invoke(app, ["scan", "https://example.com/", "--i-authorized"])
    assert r.exit_code == 0
    assert "100/100" in r.output or "grade a" in r.output.lower()
