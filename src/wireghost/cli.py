"""Wire_Ghost CLI entry point (stub)."""

import typer

app = typer.Typer(name="wireghost", help="Wire_Ghost security scanning toolkit")


@app.callback(invoke_without_command=True)
def main(version: bool = typer.Option(False, "--version", "-V", help="Show version")):
    if version:
        from wireghost import __version__
        typer.echo(f"wireghost {__version__}")
        raise typer.Exit()
