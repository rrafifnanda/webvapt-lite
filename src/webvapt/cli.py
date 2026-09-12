import typer

app = typer.Typer(help="webvapt-lite: brutal authorized-only web scanner")


@app.command()
def scan(target: str):
    typer.echo(f"webvapt scan {target}")


@app.callback()
def main():
    pass


if __name__ == "__main__":
    app()
