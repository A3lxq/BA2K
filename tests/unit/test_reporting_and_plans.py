import csv
import io
import json

import pytest

from blackarch2kali.categories import research_categories
from blackarch2kali.collectors.blackarch import parse_db
from blackarch2kali.errors import UnsafeInputError
from blackarch2kali.models import ToolRecord
from blackarch2kali.plans import SCRIPT_TEMPLATE, category_plan, category_slug, generate_category_artifacts
from blackarch2kali.reporting import csv_report, markdown
from blackarch2kali.reporting.generate import generate_reports
from blackarch2kali.synchronization.change_detector import diff_inventory, diff_records


def tool(name="t", **kw):
    return ToolRecord(tool_name=name, blackarch_package=name, **kw)


EVIL = '=HYPERLINK("http://evil","x")|<script>alert(1)</script>[l](javascript:x)\n# h'


def test_csv_formula_injection_neutralised():
    out = csv_report.inventory_csv({"t": tool(description=EVIL, notes=["+cmd|' /C calc'!A0"])})
    rows = list(csv.reader(io.StringIO(out)))
    cells = rows[1]
    assert all(not c.startswith(("=", "+", "-", "@")) for c in cells)
    assert "'=HYPERLINK" in cells[rows[0].index("description")]


def test_markdown_escapes_untrusted_text():
    md = markdown.full_inventory({"t": tool(description=EVIL, github_repo=EVIL)}, "now")
    assert "<script>" not in md and "\n# h" not in md
    assert "\\|" in md
    assert markdown.esc("a|b\nc") == "a\\|b c"


def test_all_reports_written_and_unknowns_not_fabricated(tmp_path):
    tools = {"a": tool("a", kali_compatibility="NATIVE_KALI", preferred_install_method="APT", install_commands=[["apt-get", "install", "a"]]),
             "b": tool("b", maintenance_status="ARCHIVED", dependency_resolution={"missing": ["x"]})}
    files = generate_reports(tools, {}, tmp_path, {"Wireless": {"official_groups": ["blackarch-wireless"]}})
    names = {f.name for f in files}
    for n in ("full_inventory.json", "full_inventory.csv", "full_inventory.md", "github_index.json", "compatibility_report.md", "dead_or_legacy_tools.md",
              "security_findings.md", "dependency_report.md", "installation_report.md", "dependency_graph.json", "wireless.json", "install_wireless.sh"):
        assert n in names, n
    inv = json.loads((tmp_path / "reports/full_inventory.json").read_text())
    b = next(t for t in inv["tools"] if t["tool_name"] == "b")
    assert b["stars"] is None and b["github_repo"] is None and b["maintenance_status"] == "ARCHIVED"
    assert "b" in (tmp_path / "reports/dead_or_legacy_tools.md").read_text()


def test_report_refuses_symlink_target(tmp_path):
    (tmp_path / "reports").mkdir()
    victim = tmp_path / "victim.txt"
    victim.write_text("keep")
    (tmp_path / "reports" / "full_inventory.json").symlink_to(victim)
    with pytest.raises(UnsafeInputError):
        generate_reports({"a": tool("a")}, {}, tmp_path)
    assert victim.read_text() == "keep"


def test_category_membership_official_vs_derived(ba_db_bytes):
    pk = parse_db(ba_db_bytes, "u").packages
    cfg = {"Reconnaissance": {"official_groups": ["blackarch-recon"]}, "OSINT": {"keywords": ["dns"]}}
    off, der = research_categories(pk["amass"], cfg)
    assert "Reconnaissance" in off and "Reconnaissance" not in der
    tools = {"x": tool("x", research_categories=["Reconnaissance"]), "y": tool("y", derived_categories=["Reconnaissance"])}
    assert [e["tool"] for e in category_plan(tools, "Reconnaissance")["install"]] == []  # no install cmds -> excluded
    plan = category_plan({"x": tool("x", research_categories=["R"], preferred_install_method="APT", install_commands=[["a"]]), "y": tool("y", derived_categories=["R"], preferred_install_method="APT", install_commands=[["a"]])}, "R")
    assert [e["tool"] for e in plan["install"]] == ["x"]
    plan2 = category_plan({"y": tool("y", derived_categories=["R"], preferred_install_method="APT", install_commands=[["a"]])}, "R", include_derived=True)
    assert plan2["install"][0]["membership"] == "derived" and "NOT" in plan2["note"].upper() or "not official" in plan2["note"]


def test_generated_scripts_contain_no_external_metadata(tmp_path):
    tools = {"evil": tool("evil", research_categories=["Wireless"], description="$(rm -rf /)", install_commands=[["x"]])}
    generate_category_artifacts(tools, {"Wireless": {}}, tmp_path)
    script = (tmp_path / "installers/install_wireless.sh").read_text()
    assert "rm -rf" not in script and "evil" not in script and 'install --category "Wireless"' in script
    assert (tmp_path / "installers/install_wireless.sh").stat().st_mode & 0o100
    with pytest.raises(ValueError):
        generate_category_artifacts(tools, {'Bad"; rm -rf /': {}}, tmp_path)
    assert category_slug("Sniffing and Spoofing") == "sniffing_and_spoofing" and "--confirm" in SCRIPT_TEMPLATE


def test_inventory_diff_added_removed_renamed_changed(ba_db_bytes):
    pk = parse_db(ba_db_bytes, "u").packages
    old = {k: pk[k] for k in ("amass", "arjun", "altdns")}
    new = {k: v.model_copy() for k, v in old.items()}
    del new["altdns"]
    new["amass"] = new["amass"].model_copy(update={"version": "99-1"})
    new["altdns-ng"] = pk["altdns"].model_copy(update={"name": "altdns-ng"})  # same upstream URL -> rename
    new["brandnew"] = pk["amap"].model_copy(update={"name": "brandnew", "url": "https://github.com/x/new"})
    d = diff_inventory(old, new)
    assert d.renamed == [("altdns", "altdns-ng")] and d.added == ["brandnew"] and d.removed == [] and "amass" in d.changed
    gone = diff_inventory(old, {k: v for k, v in old.items() if k != "arjun"})
    assert gone.removed == ["arjun"]


def test_record_diff():
    a, b = tool(security_risk="LOW"), tool(security_risk="HIGH")
    assert diff_records(None, a) == {"new": True} and diff_records(a, b) == {"security_risk": ["LOW", "HIGH"]} and diff_records(a, a) == {}
