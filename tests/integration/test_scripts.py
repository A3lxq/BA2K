import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from blackarch2kali.plans import SCRIPT_TEMPLATE

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
CATEGORY_SCRIPTS = {"install_osint.sh": "OSINT", "install_wireless.sh": "Wireless", "install_exploitation.sh": "Exploitation",
                    "install_forensics.sh": "Forensics", "install_webapp.sh": "Web Application"}
REQUIRED = ["install_all_blackarch_tools.sh", *CATEGORY_SCRIPTS, "dependency_check.sh", "verify_tools.sh", "update_tools.sh", "install.sh", "verify.sh", "update.sh", "backup.sh"]


def env(tmp_path):
    e = {k: v for k, v in os.environ.items() if k in {"HOME", "LANG"}}
    e["PATH"] = f"{Path(sys.executable).parent}:/usr/bin:/bin"
    e["BLACKARCH2KALI_HOME"] = str(tmp_path / "state")
    return e


def run(script, *args, tmp_path, input=None):
    return subprocess.run(["bash", str(SCRIPTS / script), *args], capture_output=True, text=True, cwd=ROOT, env=env(tmp_path), input=input, timeout=60, check=False)


def test_all_scripts_exist_executable_and_valid_bash():
    for name in REQUIRED:
        p = SCRIPTS / name
        assert p.exists() and os.access(p, os.X_OK), name
        assert subprocess.run(["bash", "-n", str(p)], check=False).returncode == 0, name


def test_category_scripts_match_generator_template():
    for name, cat in CATEGORY_SCRIPTS.items():
        assert (SCRIPTS / name).read_text() == SCRIPT_TEMPLATE.format(category=json.dumps(cat)), name


def test_scripts_do_not_duplicate_installation_logic():
    for name in REQUIRED:
        text = re.sub(r"^\s*#.*$", "", (SCRIPTS / name).read_text(), flags=re.M)
        if name in {"install.sh", "verify.sh", "backup.sh"}:
            continue  # bootstrap/dev helpers, not tool installers
        for banned in ("apt-get", "apt install", "pip install", "pipx install", "go install", "cargo install", "npm install", "gem install", "curl", "wget", "sudo"):
            assert banned not in text, (name, banned)
        assert "blackarch2kali" in text


@pytest.mark.parametrize("script", [*CATEGORY_SCRIPTS, "install_all_blackarch_tools.sh"])
def test_install_scripts_default_to_dry_run_and_support_flags(script, tmp_path):
    r = run(script, tmp_path=tmp_path)
    assert r.returncode == 0 and "DRY RUN" in r.stdout, r.stdout + r.stderr
    assert run(script, "--dry-run", tmp_path=tmp_path).returncode == 0
    assert "DRY RUN" not in run(script, "--confirm", tmp_path=tmp_path, input="n\n").stdout  # asks for approval, never silently executes
    assert run(script, "--confirm", tmp_path=tmp_path, input="n\n").returncode == 4
    bad = run(script, "--yolo", tmp_path=tmp_path)
    assert bad.returncode == 2 and "unknown option" in bad.stderr
    assert run(script, "--help", tmp_path=tmp_path).returncode == 0


def test_confirm_flag_cannot_be_smuggled_via_shell_metacharacters(tmp_path):
    marker = tmp_path / "pwned"
    r = run("install_wireless.sh", f"--dry-run;touch {marker}", tmp_path=tmp_path)
    assert r.returncode == 2 and not marker.exists()


def test_helper_scripts(tmp_path):
    assert run("dependency_check.sh", tmp_path=tmp_path).returncode == 0
    assert run("verify_tools.sh", "nonexistent-tool-xyz", tmp_path=tmp_path).returncode != 0
    assert run("verify_tools.sh", tmp_path=tmp_path).returncode in (0, 3)
    sqlite = shutil.which("python3")
    assert sqlite
    run("dependency_check.sh", tmp_path=tmp_path)  # creates the database
    b = run("backup.sh", tmp_path=tmp_path)
    assert b.returncode == 0 and list((tmp_path / "state/backups").glob("*.sqlite"))
