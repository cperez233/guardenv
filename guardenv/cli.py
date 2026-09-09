"""``guardenv`` command line interface.

Exit codes
----------
``0``  clean scan (no findings at or above the failure threshold)
``1``  secrets found
``2``  execution error (bad arguments, unreadable baseline, I/O failure)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from . import __version__
from .baseline import Baseline, BaselineError
from .entropy import DEFAULT_ENTROPY_CONFIG, analyze_token
from .models import ScanSummary, Severity
from .reporters import (
    SEVERITY_STYLE,
    github_annotations,
    render_summary_panel,
    render_table,
    to_json,
    to_sarif,
)
from .rules import RULES, compile_ruleset
from .scanner import DEFAULT_EXCLUDED_DIRS, Scanner, ScanOptions

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

app = typer.Typer(
    name="guardenv",
    help="Detect leaked credentials, tokens and private keys before they reach your remote.",
    add_completion=True,
    rich_markup_mode="rich",
)

# Human output always goes to stderr so that `--json`/`--sarif` on stdout stays
# machine-parseable even without `--output`.
err_console = Console(stderr=True, highlight=False, soft_wrap=False)
out_console = Console(highlight=False, soft_wrap=False)


BANNER = r"""[bold green]
   ____                     _ _____
  / ___|_   _  __ _ _ __ __| | ____|_ ____   __
 | |  _| | | |/ _` | '__/ _` |  _| | '_ \ \ / /
 | |_| | |_| | (_| | | | (_| | |___| | | \ V /
  \____|\__,_|\__,_|_|  \__,_|_____|_| |_|\_/
[/bold green][bright_black]  secret scanner · v{version}[/bright_black]
"""


def _fail(message: str) -> typer.Exit:
    err_console.print(f"[bold red]error[/bold red] {message}")
    return typer.Exit(EXIT_ERROR)


def _parse_severity(value: str, flag: str) -> Severity:
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise _fail(f"{flag}: {exc}") from exc


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False, "--version", "-V", help="Print the GuardEnv version and exit.", is_eager=True
    ),
) -> None:
    """GuardEnv root command."""
    if version:
        out_console.print(f"guardenv {__version__}")
        raise typer.Exit(EXIT_CLEAN)
    if ctx.invoked_subcommand is None:
        out_console.print(ctx.get_help())
        raise typer.Exit(EXIT_CLEAN)


@app.command()
def scan(  # noqa: PLR0915 - a CLI entry point is allowed to be wide
    paths: list[Path] = typer.Argument(
        None,
        help="Files or directories to scan. Defaults to the current directory.",
        show_default=False,
    ),
    stdin: bool = typer.Option(False, "--stdin", help="Read the document to scan from stdin."),
    stdin_name: str = typer.Option("<stdin>", "--stdin-name", help="Path label to attach to stdin findings."),
    as_json: bool = typer.Option(False, "--json", help="Emit the GuardEnv JSON report."),
    as_sarif: bool = typer.Option(False, "--sarif", help="Emit SARIF 2.1.0 for GitHub Code Scanning."),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write the machine-readable report to this file."
    ),
    annotate: bool = typer.Option(
        False, "--github-annotations", help="Emit ::error/::warning workflow commands."
    ),
    fail_on: str = typer.Option("MEDIUM", "--fail-on", help="Minimum severity that makes the run exit 1."),
    fail_on_warning: bool = typer.Option(
        False, "--fail-on-warning", help="Exit 1 on any finding, including INFO."
    ),
    min_severity: str = typer.Option(
        "INFO", "--min-severity", help="Drop findings below this severity from the report."
    ),
    entropy_threshold: float | None = typer.Option(
        None,
        "--entropy-threshold",
        "-e",
        min=0.0,
        max=8.0,
        help="Absolute Shannon threshold in bits/char applied to every charset.",
    ),
    no_entropy: bool = typer.Option(False, "--no-entropy", help="Disable the entropy detector."),
    no_rules: bool = typer.Option(False, "--no-rules", help="Disable the regex detector."),
    no_heuristics: bool = typer.Option(
        False, "--no-heuristics", help="Disable benign-shape suppression in the entropy detector."
    ),
    rule: list[str] = typer.Option(None, "--rule", "-r", help="Run only these rule ids (repeatable)."),
    exclude_rule: list[str] = typer.Option(
        None, "--exclude-rule", help="Disable these rule ids (repeatable)."
    ),
    exclude_dir: list[str] = typer.Option(
        None, "--exclude-dir", help="Extra directory names to skip (repeatable)."
    ),
    exclude: list[str] = typer.Option(None, "--exclude", help="Glob of paths to skip (repeatable)."),
    include: list[str] = typer.Option(
        None, "--include", help="Only scan paths matching this glob (repeatable)."
    ),
    max_file_size: int = typer.Option(
        5 * 1024 * 1024, "--max-file-size", help="Skip files larger than this many bytes."
    ),
    workers: int | None = typer.Option(
        None, "--workers", "-j", min=1, help="Worker threads. Defaults to 2x CPU count."
    ),
    follow_symlinks: bool = typer.Option(
        False, "--follow-symlinks", help="Follow symlinked files and directories."
    ),
    no_gitignore: bool = typer.Option(
        False, "--no-gitignore", help="Ignore the repository's .gitignore file."
    ),
    baseline_path: Path | None = typer.Option(
        None, "--baseline", help="Suppress findings recorded in this baseline file."
    ),
    write_baseline: Path | None = typer.Option(
        None, "--write-baseline", help="Write current findings to a baseline file and exit 0."
    ),
    show_secrets: bool = typer.Option(
        False, "--show-secrets", help="Include unredacted secrets in the report. Use with care."
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress the banner and table."),
    no_banner: bool = typer.Option(False, "--no-banner", help="Suppress the ASCII banner only."),
) -> None:
    """Scan files, directories or stdin for exposed credentials."""
    machine_output = as_json or as_sarif
    show_human = not quiet and not machine_output

    if as_json and as_sarif:
        raise _fail("--json and --sarif are mutually exclusive.")
    if output is not None and not machine_output:
        raise _fail("--output requires --json or --sarif.")
    if stdin and paths:
        raise _fail("--stdin cannot be combined with positional paths.")

    fail_threshold = Severity.INFO if fail_on_warning else _parse_severity(fail_on, "--fail-on")
    report_floor = _parse_severity(min_severity, "--min-severity")

    try:
        ruleset = compile_ruleset(include=rule or None, exclude=exclude_rule or None)
    except KeyError as exc:
        raise _fail(str(exc).strip("'")) from exc

    if not ruleset and not no_rules:
        raise _fail("the selected rule filters left no rules enabled.")

    entropy_config = DEFAULT_ENTROPY_CONFIG
    if no_heuristics:
        entropy_config = type(entropy_config)(
            min_length=entropy_config.min_length,
            max_length=entropy_config.max_length,
            hex_threshold=entropy_config.hex_threshold,
            base64_threshold=entropy_config.base64_threshold,
            generic_threshold=entropy_config.generic_threshold,
            min_unique_ratio=entropy_config.min_unique_ratio,
            use_heuristics=False,
        )

    options = ScanOptions(
        rules=ruleset,
        entropy=entropy_config,
        enable_entropy=not no_entropy,
        enable_rules=not no_rules,
        excluded_dirs=DEFAULT_EXCLUDED_DIRS | set(exclude_dir or ()),
        include_globs=tuple(include or ()),
        exclude_globs=tuple(exclude or ()),
        max_file_size=max_file_size,
        follow_symlinks=follow_symlinks,
        respect_gitignore=not no_gitignore,
        min_severity=report_floor,
    ).with_entropy_threshold(entropy_threshold)

    if workers is not None:
        options.workers = workers

    if show_human and not no_banner:
        err_console.print(BANNER.format(version=__version__))

    scanner = Scanner(options)
    targets = paths or [Path.cwd()]

    try:
        if stdin:
            document = sys.stdin.read()
            summary = scanner.scan_text(document, stdin_name)
            target_label = stdin_name
        else:
            summary = scanner.scan_paths(targets)
            target_label = ", ".join(str(p) for p in targets)
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        raise _fail("interrupted by user.") from None
    except OSError as exc:
        raise _fail(f"scan failed: {exc}") from exc

    if write_baseline is not None:
        try:
            Baseline().dump(write_baseline, summary)
        except OSError as exc:
            raise _fail(f"cannot write baseline: {exc}") from exc
        err_console.print(
            f"[green]✓[/green] baseline written to [bold]{write_baseline}[/bold] "
            f"({len(summary.findings)} finding(s) acknowledged)"
        )
        raise typer.Exit(EXIT_CLEAN)

    suppressed = 0
    if baseline_path is not None:
        try:
            baseline = Baseline.load(baseline_path)
        except BaselineError as exc:
            raise _fail(str(exc)) from exc
        summary.findings, suppressed = baseline.filter(summary)

    _emit(
        summary,
        as_json=as_json,
        as_sarif=as_sarif,
        output=output,
        annotate=annotate,
        show_human=show_human,
        show_secrets=show_secrets,
        target_label=target_label,
        suppressed=suppressed,
    )

    raise typer.Exit(EXIT_FINDINGS if summary.has_at_least(fail_threshold) else EXIT_CLEAN)


def _emit(
    summary: ScanSummary,
    *,
    as_json: bool,
    as_sarif: bool,
    output: Path | None,
    annotate: bool,
    show_human: bool,
    show_secrets: bool,
    target_label: str,
    suppressed: int,
) -> None:
    payload: str | None = None
    if as_json:
        payload = to_json(summary, include_secret=show_secrets)
    elif as_sarif:
        payload = to_sarif(summary, tool_version=__version__)

    if payload is not None:
        if output is not None:
            try:
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(payload + "\n", encoding="utf-8")
            except OSError as exc:
                raise _fail(f"cannot write report to {output}: {exc}") from exc
            err_console.print(f"[green]✓[/green] report written to [bold]{output}[/bold]")
        else:
            print(payload)

    if annotate:
        for line in github_annotations(summary):
            print(line)

    if show_human:
        findings = summary.sorted_findings()
        if findings:
            err_console.print(render_table(findings))
            err_console.print()
        err_console.print(render_summary_panel(summary, target=target_label))
        if suppressed:
            err_console.print(f"[bright_black]{suppressed} finding(s) suppressed by baseline.[/bright_black]")
        if summary.errors:
            err_console.print()
            for error in summary.errors[:20]:
                err_console.print(f"[yellow]warn[/yellow] {error.path}: {error.reason}")
            if len(summary.errors) > 20:
                err_console.print(
                    f"[bright_black]... and {len(summary.errors) - 20} more warnings[/bright_black]"
                )


@app.command("rules")
def list_rules(
    as_json: bool = typer.Option(False, "--json", help="Emit the rule matrix as JSON."),
    tag: str | None = typer.Option(None, "--tag", help="Only show rules carrying this tag."),
) -> None:
    """List the built-in detection rules."""
    selected = [r for r in RULES if tag is None or tag in r.tags]
    if not selected:
        raise _fail(f"no rules carry the tag {tag!r}.")

    if as_json:
        print(json.dumps([r.to_dict() for r in selected], indent=2))
        raise typer.Exit(EXIT_CLEAN)

    table = Table(
        title=f"GuardEnv ruleset · {len(selected)} rules",
        header_style="bold bright_white",
        border_style="grey30",
        expand=True,
    )
    table.add_column("SEVERITY", width=10, no_wrap=True)
    table.add_column("ID", style="bright_cyan", no_wrap=True)
    table.add_column("NAME", style="bright_white")
    table.add_column("TAGS", style="bright_black")

    for rule in sorted(selected, key=lambda r: (-r.severity.rank, r.id)):
        table.add_row(
            Text(f" {rule.severity.value} ", style=SEVERITY_STYLE[rule.severity]),
            rule.id,
            rule.name,
            ", ".join(rule.tags),
        )
    out_console.print(table)
    raise typer.Exit(EXIT_CLEAN)


@app.command()
def entropy(
    token: str = typer.Argument(..., help="The string to analyse."),
) -> None:
    """Report the Shannon entropy and classification of a single token."""
    result = analyze_token(token)
    table = Table(show_header=False, border_style="grey30", box=None, padding=(0, 2))
    table.add_row("[bright_black]token[/bright_black]", f"[bright_white]{result.token}[/bright_white]")
    table.add_row("[bright_black]length[/bright_black]", str(len(result.token)))
    table.add_row("[bright_black]charset[/bright_black]", result.charset)
    table.add_row("[bright_black]entropy[/bright_black]", f"{result.entropy:.4f} bits/char")
    table.add_row("[bright_black]normalized[/bright_black]", f"{result.normalized:.4f}")
    table.add_row("[bright_black]threshold[/bright_black]", f"{result.threshold:.2f}")
    verdict = "[bold red]SUSPICIOUS[/bold red]" if result.suspicious else "[bold green]BENIGN[/bold green]"
    table.add_row("[bright_black]verdict[/bright_black]", f"{verdict} ({result.reason})")
    out_console.print(table)
    raise typer.Exit(EXIT_CLEAN)


def run() -> None:
    """Console-script entry point with a top-level safety net."""
    try:
        app()
    except SystemExit:
        raise
    except Exception as exc:  # pragma: no cover - last-resort handler
        err_console.print(f"[bold red]fatal[/bold red] {type(exc).__name__}: {exc}")
        sys.exit(EXIT_ERROR)


if __name__ == "__main__":  # pragma: no cover
    run()
