import anyio
import os

import httpx
import typer
from rich.console import Console
from rich.table import Table

from webvapt.crawler import extract_links
from webvapt.guard import GuardError, assert_authorized, enforce_scope
from webvapt.models import Finding
from webvapt.probes.active import reflects, sqli_error
from webvapt.probes.dirs import DIRS, is_interesting
from webvapt.probes.headers import headers_probe
from webvapt.reporter import write_json, write_md
from webvapt.scorer import score_findings

app = typer.Typer(help="webvapt-lite: brutal authorized-only web scanner")
console = Console()
UA = "webvapt-lite (authorized scan)"
XSS_CANARY = "<wvptxss>"
SQLI_PROBE = "1'"


async def _brutal_scan(client: httpx.AsyncClient, url: str, concurrency: int) -> list[Finding]:
    out: list[Finding] = []
    sem = anyio.Semaphore(concurrency)

    async def fetch(u: str):
        async with sem:
            try:
                return await client.get(u, timeout=10)
            except Exception:
                return None

    # 1. crawl homepage links (depth 1)
    r0 = await fetch(url)
    pages = [url]
    if r0 and "text/html" in r0.headers.get("content-type", ""):
        pages += extract_links(r0.text, url)[:20]

    # 2. dirs bruteforce
    async def check_dir(d: str):
        u = url.rstrip("/") + "/" + d
        r = await fetch(u)
        if r and is_interesting(r.status_code):
            out.append(
                Finding(
                    check="exposed-path",
                    severity="medium" if r.status_code == 200 else "low",
                    url=u,
                    evidence=f"status {r.status_code}",
                    remediation="Restrict or remove exposed path.",
                )
            )

    async with anyio.create_task_group() as tg:
        for d in DIRS:
            tg.start_soon(check_dir, d)

    # 3. param probes on pages with query strings + known fixture paths
    targets = [p for p in pages if "?" in p]
    targets += [url.rstrip("/") + "/search?q=test", url.rstrip("/") + "/item?id=1"]
    seen: set[str] = set()

    async def probe_params(base: str):
        if base in seen:
            return
        seen.add(base)
        if "?" in base:
            pre, _ = base.split("?", 1)
            xss_u = pre + "?q=" + XSS_CANARY if "search" in base else base
            sqli_u = pre + "?id=" + SQLI_PROBE if "item" in base else base
        else:
            if base.endswith("/search?q=test"):
                xss_u, sqli_u = base.replace("test", XSS_CANARY), ""
            elif base.endswith("/item?id=1"):
                xss_u, sqli_u = "", base.replace("id=1", "id=1%27")
            else:
                return
        if xss_u:
            r = await fetch(xss_u)
            if r and reflects(XSS_CANARY, r.text):
                out.append(
                    Finding(
                        check="xss-reflected",
                        severity="high",
                        url=xss_u,
                        evidence=f"canary reflected from {base}",
                        remediation="Encode output, add CSP.",
                    )
                )
        if sqli_u:
            r = await fetch(sqli_u)
            if r and sqli_error(r.text):
                out.append(
                    Finding(
                        check="sqli-error",
                        severity="critical",
                        url=sqli_u,
                        evidence="SQL error string in response",
                        remediation="Use parameterized queries.",
                    )
                )

    async with anyio.create_task_group() as tg:
        for t in targets[:20]:
            tg.start_soon(probe_params, t)
    return out


@app.command()
def scan(
    target: str,
    i_authorized: bool = typer.Option(False, "--i-authorized"),
    allow_private: bool = typer.Option(False, "--allow-private"),
    brutal: bool = typer.Option(False, "--brutal"),
    concurrency: int = typer.Option(10, "--concurrency"),
    output_json: str = typer.Option("", "--output-json"),
    output_md: str = typer.Option("", "--output-md"),
):
    try:
        authorized = i_authorized or os.getenv("WEBVAPT_I_AUTHORIZED") == "1"
        assert_authorized(authorized)
        url = enforce_scope(target, allow_private=allow_private)
        if brutal:
            concurrency = max(concurrency, 20)
    except GuardError as e:
        typer.echo(str(e), err=True)
        raise typer.Exit(2)
    try:
        r = httpx.get(url, headers={"User-Agent": UA}, timeout=15, follow_redirects=True)
        findings = headers_probe(dict(r.headers), str(r.url))
        if brutal:
            async def _run():
                async with httpx.AsyncClient(
                    headers={"User-Agent": UA}, follow_redirects=True
                ) as client:
                    return await _brutal_scan(client, url, concurrency)

            findings += anyio.run(_run)
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
