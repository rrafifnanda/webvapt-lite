from typer.testing import CliRunner
from webvapt.cli import app


def test_cli_help():
    r = CliRunner().invoke(app, ["--help"])
    assert r.exit_code == 0
    assert "webvapt" in r.output.lower()
