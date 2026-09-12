import os

import httpx
import typer
from rich.console import Console
from rich.table import Table

from webvapt.guard import GuardError, assert_authorized, enforce_scope
from webvapt.probes.headers import headers_probe
from webvapt.reporter import write_json, write_md
from webvapt.scorer import score_findings

app = typer.Typer(help="webvapt-lite: brutal authorized-only web scanner")
console = Console()
UA = "webvapt-lite (authorized scan)"


@app.command()
def scan(
    target: str,
    i_authorized: bool = typer.Option(False, "--i-authorized"),
    allow_private: bool = typer.Option(False, "--allow-private"),
    output_json: str = typer.Option("", "--output-json"),
    output_md: str = typer.Option("", "--output-md"),
):
    try:
        authorized = i_authorized or os.getenv("WEBVAPT_I_AUTHORIZED") == "1"
        assert_authorized(authorized)
        url = enforce_scope(target, allow_private=allow_private)
    except GuardError as e:
        typer.echo(str(e), err=True)
        raise typer.Exit(2)
    try:
        r = httpx.get(url, headers={"User-Agent": UA}, timeout=15, follow_redirects=True)
        findings = headers_probe(dict(r.headers), str(r.url))
    except Exception as e:
        typer.echo(f"fetch failed: {e}", err=True)
        raise typer.Exit(1)
    score, grade = score_findings(findings)
    table = Table(title=f"webvapt {url} — {score}/100 (grade {grade})")
    table.add_column("severity")
    table.add_column("check")
    if not findings:
        table.add_row("info", "all-pass")
    for f in findings:
        table.add_row(f.severity, f.check)
    console.print(table)
    if output_json:
        write_json(findings, output_json)
    if output_md:
        write_md(findings, score, grade, output_md)


@app.callback()
def main():
    pass


if __name__ == "__main__":
    app()
