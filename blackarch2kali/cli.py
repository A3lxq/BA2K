"""Typer command-line interface."""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from .config import load_settings
from .errors import BA2KError, InstallError, UnsafeInputError
from .installers import get_installer
from .installers.base import InstallPlan
from .logging_utils import configure_logging
from .models import InstallOption, Method, ToolRecord
from .plans import category_plan
from .reporting.generate import generate_reports
from .security.command_safety import validate_tool_name
from .services import Services, build_services
from .validators.health import run_health
from .validators.installation import load_profiles, verify_tool

EXIT_OK, EXIT_ERROR, EXIT_USAGE, EXIT_CHECK_FAILED, EXIT_BLOCKED = 0, 1, 2, 3, 4

app = typer.Typer(add_completion=False, no_args_is_help=True, help="BlackArch -> Kali intelligence, compatibility analysis and safe installation planning.")
console = Console()
err = Console(stderr=True)


class State:
    verbose = False
    json = False
    config_dir = Path("config")
    home: Path | None = None
    svc: Services | None = None


def services() -> Services:
    if State.svc is None:
        State.svc = build_services(State.config_dir, State.home)
    return State.svc


@app.callback()
def main(
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Verbose logging.")] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Machine-readable JSON output where supported.")] = False,
    config_dir: Annotated[Path, typer.Option("--config-dir", help="Configuration directory.")] = Path("config"),
    home: Annotated[Path | None, typer.Option("--home", help="State directory (default from settings / BLACKARCH2KALI_HOME).")] = None,
) -> None:
    State.verbose, State.json, State.config_dir, State.home, State.svc = verbose, json_output, config_dir, home, None
    configure_logging(verbose)


def fail(msg: str, code: int = EXIT_ERROR) -> typer.Exit:
    err.print(f"[red]error:[/red] {msg}")
    return typer.Exit(code)


def emit(obj: Any) -> None:
    typer.echo(json.dumps(obj, indent=2, default=str))


def require_tool(name: str) -> ToolRecord:
    try:
        validate_tool_name(name)
    except UnsafeInputError as exc:
        raise fail(str(exc), EXIT_USAGE) from exc
    tool = services().db.load_tools().get(name)
    if tool is None:
        raise fail(f"unknown tool '{name}'. Run `blackarch2kali sync` first or use `search`.", EXIT_USAGE)
    return tool


@app.command()
def init() -> None:
    """Create the state directory and database."""
    svc = services()
    for d in (svc.settings.state_dir, svc.settings.generated_dir):
        d.mkdir(parents=True, exist_ok=True)
    out = {"state_dir": str(svc.settings.state_dir), "database": str(svc.settings.db_path), "platform": svc.platform.distro_id, "arch": svc.platform.deb_arch}
    emit(out) if State.json else console.print(f"Initialised state in [bold]{out['state_dir']}[/bold] (database: {out['database']}).")


@app.command()
def sync(full: Annotated[bool, typer.Option("--full", help="Re-fetch everything.")] = False,
         reports: Annotated[bool, typer.Option("--reports/--no-reports")] = True,
         schedule: Annotated[bool, typer.Option("--schedule", help="Run repeatedly at the configured interval.")] = False) -> None:
    """Synchronize metadata: discovery, analysis, planning data. Never installs anything."""
    svc = services()
    from .synchronization.scheduler import run_loop

    def job() -> dict[str, Any]:
        http = svc.http()
        try:
            with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=err, transient=True) as prog:
                prog.add_task("synchronizing BlackArch / Kali / GitHub metadata...", total=None)
                result = svc.sync_engine(http).run("full" if full else "incremental")
        finally:
            http.close()
        if reports:
            generate_reports(svc.db.load_tools(), svc.db.load_repos(), svc.settings.generated_dir, svc.categories_cfg)
        emit(result.to_dict()) if State.json else console.print(f"sync #{result.run_id} {result.status}: {result.inventory} repos={result.repos_fetched} analyzed={result.tools_analyzed}" + "".join(f"\n  [yellow]warning:[/yellow] {w}" for w in result.warnings))
        return result.to_dict()

    try:
        if schedule:
            run_loop(job, svc.settings.sync.interval_hours)
        else:
            job()
    except BA2KError as exc:
        raise fail(str(exc)) from exc


@app.command()
def update() -> None:
    """Refresh metadata incrementally and regenerate reports (does NOT install or upgrade software)."""
    sync(full=False, reports=True, schedule=False)


@app.command()
def inventory(category: Annotated[str | None, typer.Option(help="Filter by BlackArch group, e.g. blackarch-recon.")] = None,
              risk: Annotated[str | None, typer.Option(help="Filter by risk level.")] = None,
              compat: Annotated[str | None, typer.Option("--compat", help="Filter by compatibility state.")] = None,
              limit: Annotated[int, typer.Option(help="Max rows (0 = all).")] = 50) -> None:
    """List known tools."""
    tools = list(services().db.load_tools().values())
    pk = services().db.load_packages()
    if category:
        tools = [t for t in tools if category in pk[t.tool_name].groups]
    if risk:
        tools = [t for t in tools if t.security_risk == risk.upper()]
    if compat:
        tools = [t for t in tools if t.kali_compatibility == compat.upper()]
    tools.sort(key=lambda t: t.tool_name)
    shown = tools if limit == 0 else tools[:limit]
    if State.json:
        return emit([t.model_dump(mode="json") for t in shown])
    tbl = Table(title=f"{len(shown)} of {len(tools)} tools")
    for c in ("Tool", "Compatibility", "Method", "Maintenance", "Risk"):
        tbl.add_column(c)
    for t in shown:
        tbl.add_row(t.tool_name, t.kali_compatibility, t.preferred_install_method or "-", t.maintenance_status, t.security_risk)
    console.print(tbl)


@app.command()
def search(term: str) -> None:
    """Search names and descriptions (plain case-insensitive match over local metadata)."""
    needle = term.lower()
    hits = [t for t in services().db.load_tools().values() if needle in t.tool_name.lower() or needle in (t.description or "").lower()]
    hits.sort(key=lambda t: (needle != t.tool_name.lower(), t.tool_name))
    if State.json:
        return emit([{"tool": t.tool_name, "description": t.description, "compatibility": t.kali_compatibility} for t in hits])
    for t in hits[:50]:
        console.print(f"{t.tool_name}  [{t.kali_compatibility}]  {t.description or ''}", markup=False)
    if not hits:
        raise typer.Exit(EXIT_USAGE)


@app.command()
def categories() -> None:
    """Official BlackArch groups (authoritative) and research-category mappings."""
    from .categories import official_groups

    svc = services()
    groups = official_groups(svc.db.load_packages())
    tools = svc.db.load_tools()
    mapped = {c: [sum(1 for t in tools.values() if c in t.research_categories), sum(1 for t in tools.values() if c in t.derived_categories)] for c in svc.categories_cfg}
    if State.json:
        return emit({"official_groups": groups, "research_categories": {c: {"official": a, "derived": b} for c, (a, b) in mapped.items()}})
    t1 = Table(title="Official BlackArch groups")
    t1.add_column("Group")
    t1.add_column("Packages", justify="right")
    for g, n in groups.items():
        t1.add_row(g, str(n))
    t2 = Table(title="Research categories (derived = keyword match, NOT official)")
    t2.add_column("Category")
    t2.add_column("Official", justify="right")
    t2.add_column("Derived", justify="right")
    for c, (a, b) in mapped.items():
        t2.add_row(c, str(a), str(b))
    console.print(t1)
    console.print(t2)


@app.command()
def analyze(tool: str) -> None:
    """Full analysis of one tool."""
    rec = require_tool(tool)
    if State.json:
        return emit(rec.model_dump(mode="json"))
    console.print(f"[bold]{rec.tool_name}[/bold] - {rec.description or 'UNKNOWN'}", markup=True, highlight=False)
    for k in ("github_repo", "language", "stars", "latest_release", "license", "maintenance_status", "kali_compatibility", "preferred_install_method", "security_risk", "last_checked"):
        console.print(f"  {k}: {getattr(rec, k)}", markup=False)
    for f in rec.risk_findings:
        console.print(f"  [{f['level']}] {f['dimension']}: {f['message']}", markup=False)
    for n in rec.notes:
        console.print(f"  note: {n}", markup=False)


@app.command()
def compatibility(tool: str) -> None:
    """Compatibility states and ranked installation options."""
    rec = require_tool(tool)
    if State.json:
        return emit({"tool": tool, "compatibility": rec.kali_compatibility, "options": rec.install_options, "notes": rec.notes})
    console.print(f"{tool}: {rec.kali_compatibility}", markup=False)
    for o in rec.install_options:
        flag = f" BLOCKED ({o['blocked_reason']})" if o.get("blocked_reason") else ""
        console.print(f"  {o['score']:>6}  {o['method']:<12} verified={o['verified']}{flag}", markup=False)


def _plan_for(rec: ToolRecord, method: str | None) -> tuple[InstallPlan, InstallOption]:
    svc = services()
    opts = [InstallOption.model_validate(o) for o in rec.install_options]
    if method:
        try:
            m = Method(method.upper())
        except ValueError as exc:
            raise fail(f"unknown method '{method}'", EXIT_USAGE) from exc
        cand = [o for o in opts if o.method is m]
    else:
        cand = [o for o in opts if not o.blocked_reason][:1]
    if not cand:
        raise fail(f"no installable option for {rec.tool_name}" + (f" via {method}" if method else "") + " (see `compatibility`)", EXIT_BLOCKED)
    opt = cand[0]
    if opt.blocked_reason:
        raise fail(f"{opt.method.value} blocked: {opt.blocked_reason}", EXIT_BLOCKED)
    installer = get_installer(opt.method, svc.settings.state_dir)
    return installer.make_plan(rec.tool_name, opt), opt


def _show_plan(plan: InstallPlan) -> None:
    console.print(f"Plan for [bold]{plan.tool}[/bold] via {plan.method.value}  (digest {plan.digest})")
    for s in plan.steps:
        console.print("  $ " + ("sudo " if plan.requires_root else "") + " ".join(s), markup=False)
    for n in plan.notes:
        console.print(f"  note: {n}", markup=False)
    for r in plan.rollback:
        console.print(f"  rollback: {r}", markup=False)
    if not plan.verified:
        console.print("  [yellow]unverified identity evidence: requires --allow-unverified[/yellow]")


@app.command()
def plan(tool: str, method: Annotated[str | None, typer.Option(help="Force a specific method.")] = None) -> None:
    """Show the installation plan and its approval digest (executes nothing)."""
    rec = require_tool(tool)
    p, _ = _plan_for(rec, method)
    emit({**p.model_dump(mode="json"), "digest": p.digest}) if State.json else _show_plan(p)


@app.command()
def install(
    tool: Annotated[str | None, typer.Argument()] = None,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Show what would run (default).")] = False,
    confirm: Annotated[bool, typer.Option("--confirm", help="Explicit approval to execute.")] = False,
    method: Annotated[str | None, typer.Option()] = None,
    category: Annotated[str | None, typer.Option(help="Install a whole research category.")] = None,
    all_tools: Annotated[bool, typer.Option("--all", help="Every installable tool (still needs --confirm).")] = False,
    plan_digest: Annotated[str | None, typer.Option(help="Approve exactly the plan with this digest (non-interactive).")] = None,
    allow_unverified: Annotated[bool, typer.Option("--allow-unverified")] = False,
    include_derived: Annotated[bool, typer.Option("--include-derived")] = False,
) -> None:
    """Install. DRY RUN unless --confirm is given; approval is bound to the plan digest."""
    if dry_run and confirm:
        raise fail("--dry-run and --confirm are mutually exclusive", EXIT_USAGE)
    targets = [t for t in (tool, category, "all" if all_tools else None) if t]
    if len(targets) != 1:
        raise fail("specify exactly one of: <tool>, --category, --all", EXIT_USAGE)
    svc = services()
    records: list[ToolRecord]
    if tool:
        records = [require_tool(tool)]
    else:
        tools = svc.db.load_tools()
        if category:
            if category not in svc.categories_cfg:
                raise fail(f"unknown category '{category}'; see `categories`", EXIT_USAGE)
            names = [e["tool"] for e in category_plan(tools, category, include_derived)["install"]]
            records = [tools[n] for n in names]
        else:
            records = [t for t in sorted(tools.values(), key=lambda x: x.tool_name) if t.preferred_install_method]
    plans: list[tuple[InstallPlan, Any]] = []
    skipped: list[str] = []
    for rec in records:
        try:
            p, _ = _plan_for(rec, method)
            plans.append((p, get_installer(p.method, svc.settings.state_dir)))
        except typer.Exit:
            if tool:
                raise
            skipped.append(rec.tool_name)
        except BA2KError as exc:
            if tool:
                raise fail(str(exc), EXIT_BLOCKED) from exc
            skipped.append(rec.tool_name)
    agg = hashlib.sha256("".join(sorted(p.digest for p, _ in plans)).encode()).hexdigest() if len(plans) != 1 else plans[0][0].digest
    if len(plans) <= 20 or State.verbose:
        for p, _ in plans:
            _show_plan(p)
    console.print(f"{len(plans)} plan(s), {len(skipped)} skipped/blocked. Approval digest: {agg}")
    if not confirm:
        console.print("[green]DRY RUN[/green] - nothing was executed. Re-run with --confirm to execute.")
        return
    if plan_digest and plan_digest != agg:
        raise fail("--plan-digest does not match the plans computed now (metadata changed?); review and re-approve", EXIT_BLOCKED)
    if not plan_digest and not typer.confirm(f"Execute {len(plans)} plan(s) with digest {agg[:16]}...?", default=False):
        raise fail("aborted by user", EXIT_BLOCKED)
    failures = 0
    profiles = load_profiles(svc.config_dir / "verification_profiles.yaml")
    for p, inst in plans:
        try:
            res = inst.execute(p, dry_run=False, approved_digest=p.digest, allow_unverified=allow_unverified)
        except InstallError as exc:
            err.print(f"[red]{p.tool}:[/red] {exc}")
            failures += 1
            continue
        if res.success:
            rep = verify_tool(p.tool, profiles.get(p.tool), extra_bin_dirs=[Path.home() / ".local/bin", Path.home() / "go/bin", Path.home() / ".cargo/bin"])
            console.print(f"{p.tool}: installed; verification {'ok' if rep.ok else 'FAILED'}", markup=False)
            failures += 0 if rep.ok else 1
        else:
            failures += 1
            err.print(f"[red]{p.tool}:[/red] {res.error}\n" + "\n".join(s.stderr[-500:] for s in res.steps if s.stderr))
            for r in p.rollback:
                err.print(f"  rollback: {r}")
    if failures:
        raise typer.Exit(EXIT_CHECK_FAILED)


@app.command()
def verify(tool: str) -> None:
    """Verify an installed tool (passive checks; executes only a profile's version/help probes)."""
    svc = services()
    rec = require_tool(tool)
    profiles = load_profiles(svc.config_dir / "verification_profiles.yaml")
    rep = verify_tool(tool, profiles.get(tool), apt_deps=rec.dependency_resolution.get("apt_packages") if svc.platform.is_debian_family and rec.preferred_install_method == "APT" else None,
                      extra_bin_dirs=[Path.home() / ".local/bin", Path.home() / "go/bin", Path.home() / ".cargo/bin"])
    if State.json:
        emit(rep.__dict__)
    else:
        console.print(f"{tool}: {'OK' if rep.ok else 'FAILED'}  path={rep.binary_path} owner={rep.owner}", markup=False)
        for k, v in rep.checks.items():
            console.print(f"  {k}: {v}", markup=False)
        for r in rep.remediation:
            console.print(f"  fix: {r}", markup=False)
    if not rep.ok:
        raise typer.Exit(EXIT_CHECK_FAILED)


@app.command()
def report(fmt: Annotated[str, typer.Option("--format", help="json | csv | markdown | html | all")] = "all") -> None:
    """Regenerate reports from stored data (no network)."""
    if fmt not in {"json", "csv", "markdown", "html", "all"}:
        raise fail("format must be json, csv, markdown, html or all", EXIT_USAGE)
    svc = services()
    tools = svc.db.load_tools()
    if not tools:
        raise fail("no data; run `blackarch2kali sync` first", EXIT_USAGE)
    files = generate_reports(tools, svc.db.load_repos(), svc.settings.generated_dir, svc.categories_cfg)
    ext = {"json": {".json"}, "csv": {".csv"}, "markdown": {".md"}, "html": {".html"}, "all": None}[fmt]
    shown = [str(f) for f in files if ext is None or f.suffix in ext]
    emit(shown) if State.json else console.print("\n".join(shown), markup=False)


@app.command("security-audit")
def security_audit(fail_on: Annotated[str, typer.Option(help="Exit 3 if any tool is at/above this level (NONE to disable).")] = "NONE") -> None:
    """Summarize risk findings across all tools."""
    from .models import RISK_ORDER, Risk

    tools = services().db.load_tools()
    counts: dict[str, int] = {}
    for t in tools.values():
        counts[t.security_risk] = counts.get(t.security_risk, 0) + 1
    flagged = sorted((t for t in tools.values() if t.security_risk in {"HIGH", "CRITICAL"}), key=lambda t: t.tool_name)
    if State.json:
        emit({"counts": counts, "flagged": [t.tool_name for t in flagged]})
    else:
        console.print(f"risk counts: {counts}", markup=False)
        for t in flagged[:100]:
            console.print(f"  {t.security_risk} {t.tool_name}: " + "; ".join(f["message"] for f in t.risk_findings if f["level"] in {"HIGH", "CRITICAL"})[:200], markup=False)
    if fail_on.upper() != "NONE":
        thr = RISK_ORDER[Risk(fail_on.upper())]
        if any(RISK_ORDER[Risk(t.security_risk)] >= thr for t in tools.values()):
            raise typer.Exit(EXIT_CHECK_FAILED)


@app.command()
def health() -> None:
    """Check framework and host health."""
    svc = services()
    checks = run_health(svc.settings, svc.platform)
    if State.json:
        emit([c.__dict__ for c in checks])
    else:
        for c in checks:
            console.print(f"{'ok  ' if c.ok else 'WARN'} {c.name}: {c.detail}", markup=False)
    if any(not c.ok for c in checks if c.name in {"python>=3.11", "database", "state-dir-writable"}):
        raise typer.Exit(EXIT_CHECK_FAILED)


def run() -> None:  # entry for `python -m blackarch2kali`
    try:
        app()
    except BA2KError as exc:
        err.print(f"[red]error:[/red] {exc}")
        raise SystemExit(EXIT_ERROR) from exc


_ = (load_settings, logging)  # re-exported for tests
