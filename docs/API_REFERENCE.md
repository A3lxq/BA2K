# Python API reference (selected)

```python
from blackarch2kali.collectors.blackarch import parse_db, BlackArchCollector
result = parse_db(db_bytes, source_url)          # ParseResult(packages, duplicates, errors)

from blackarch2kali.collectors.debian import parse_packages
kali = parse_packages(text, "kali", url)         # DebIndex.get(name) -> DebMatch | None (exact)

from blackarch2kali.compatibility.package_mapper import map_package
mapping = map_package(pkg, kali, debian)         # PackageMapping(kali, debian, notes)

from blackarch2kali.compatibility.dependency_resolver import DependencyResolver, compare_versions, find_cycles
res = DependencyResolver(packages, kali, debian, host_arch, aliases).resolve("name")

from blackarch2kali.analysis import AnalysisContext, analyze_package
record = analyze_package(pkg, repo_info_or_None, ctx)   # -> ToolRecord

from blackarch2kali.installers import get_installer
inst = get_installer(Method.APT, work_dir)
plan = inst.make_plan("amass", option)            # validates; plan.digest
inst.execute(plan, dry_run=True)                  # default
inst.execute(plan, dry_run=False, approved_digest=plan.digest)

from blackarch2kali.synchronization.engine import SyncEngine
SyncEngine(db, http, settings, ctx_factory).run("full" | "incremental")

from blackarch2kali.validators.installation import verify_tool, VerificationProfile
```

Key models (`blackarch2kali.models`): `BlackArchPackage`, `RepoInfo`, `DebMatch`, `InstallOption`, `RiskFinding`, `ToolRecord`.
`ToolRecord` fields: tool_name, blackarch_package, category, research_categories, derived_categories, description, github_repo,
official_website, language, stars, forks, open_issues, last_commit, latest_release, license, maintained, maintenance_status,
kali_compatibility, installation_methods, preferred_install_method, dependencies, install_commands, install_options,
verification_command, docker_support, security_risk, risk_findings, source_provenance, last_checked, notes,
replacement_if_dead, upstream_verification, reproducibility, dependency_resolution.

Database: `Database(path)` with `load_packages/upsert_package/mark_removed/package_history`, `save_repo/load_repos`,
`save_tool/load_tools`, `start_run/finish_run/record_change/list_changes`, `set_repo_status/missing_repos`.
