from pathlib import Path

from blackarch2kali.services import build_services, packaged_defaults


def test_packaged_defaults_identical_to_config():
    for f in Path("config").glob("*.yaml"):
        assert (packaged_defaults() / f.name).read_text() == f.read_text(), f"{f.name}: run `make sync-defaults`"


def test_fallback_to_defaults_uses_user_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    monkeypatch.delenv("BLACKARCH2KALI_HOME", raising=False)
    svc = build_services(tmp_path / "no-config-here")
    assert svc.settings.state_dir == tmp_path / "blackarch2kali" / "state"
    assert svc.settings.generated_dir == tmp_path / "blackarch2kali" / "generated"
    assert svc.policy["blocked_risk_levels"] == ["HIGH", "CRITICAL"] and "Wireless" in svc.categories_cfg
