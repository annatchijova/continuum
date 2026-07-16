from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from continuum_web.server import Studio
from continuum_web import server
from continuum_web import narrator


def test_ui_exposes_narration_as_an_unchecked_explicit_consent():
    html = (Path(__file__).parents[1] / "continuum_web/static/index.html").read_text()
    script = (Path(__file__).parents[1] / "continuum_web/static/app.js").read_text()

    assert 'id="narrationConsent" type="checkbox"' in html
    assert 'allow_narration: $("narrationConsent").checked' in script


def test_demo_workspace_is_searchable_and_auditable():
    with TemporaryDirectory() as directory, patch("continuum_web.narrator.enabled", return_value=False):
        root = Path(directory) / "workspace"
        root.mkdir()
        marker = root / "do-not-delete.txt"
        marker.write_text("owner material", encoding="utf-8")
        studio = Studio(root)
        dashboard = studio.demo()

        assert dashboard["total_artifacts"] == 4
        assert dashboard["integrity"] is True
        assert marker.read_text(encoding="utf-8") == "owner material"
        assert studio.workspace.name == "safe-demo"

        result = studio.ask("Where is the apartment deed?")
        assert result["sources"]
        assert "Apartment" in result["answer"] or "apartment" in result["answer"]
        assert result["narration"] is None


def test_capture_requires_an_open_workspace():
    with TemporaryDirectory() as directory:
        studio = Studio(Path(directory) / "new")
        try:
            studio.capture("A title", "A memory", [])
        except ValueError as exc:
            assert "Unlock" in str(exc)
        else:
            raise AssertionError("locked workspaces must reject captures")


def test_narration_requires_explicit_opt_in():
    with TemporaryDirectory() as directory, patch("continuum_web.narrator.enabled") as enabled:
        studio = Studio(Path(directory) / "demo")
        studio.demo()
        studio.ask("Where is the apartment deed?")

        enabled.assert_called_once_with(opted_in=False)


def test_agents_sdk_narrator_is_stateless_and_untraced(monkeypatch):
    captured = {}

    class FakeAgent:
        def __init__(self, **kwargs):
            captured["agent"] = kwargs

    class FakeModelSettings:
        def __init__(self, **kwargs):
            captured["model_settings"] = kwargs

    class FakeRunConfig:
        def __init__(self, **kwargs):
            captured["run_config"] = kwargs

    class FakeRunner:
        @staticmethod
        def run_sync(agent, message, **kwargs):
            captured["message"] = message
            captured["run"] = kwargs
            return SimpleNamespace(final_output="The deed is in the blue folder.")

    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setitem(
        __import__("sys").modules,
        "agents",
        SimpleNamespace(
            Agent=FakeAgent,
            ModelSettings=FakeModelSettings,
            RunConfig=FakeRunConfig,
            Runner=FakeRunner,
        ),
    )

    answer = narrator.narrate("Where is the deed?", "Found one item.", ["blue folder"])

    assert answer == "The deed is in the blue folder."
    assert captured["agent"]["model"] == "gpt-5.6"
    assert captured["model_settings"] == {"store": False}
    assert captured["run_config"] == {"tracing_disabled": True}
    assert captured["run"]["max_turns"] == 1


def test_heir_view_is_read_only():
    with TemporaryDirectory() as directory:
        workspace = Path(directory) / "legacy"
        owner = Studio(workspace)
        owner.create("alex", "a-long-test-passphrase")
        owner.lock()

        heir = Studio(workspace)
        dashboard = heir.unlock_heir("maria", "a-long-test-passphrase")

        assert dashboard["role"] == "heir"
        try:
            heir.capture("A title", "A memory", [])
        except ValueError as exc:
            assert str(exc) == "Heir view is read-only."
        else:
            raise AssertionError("heirs must not be able to capture memories")


def test_heir_guide_is_generated_by_the_core_for_an_heir():
    with TemporaryDirectory() as directory:
        workspace = Path(directory) / "legacy"
        owner = Studio(workspace)
        owner.create("alex", "a-long-test-passphrase")
        owner.capture("The deed", "The property deed is in the blue folder.", ["home"])
        owner.lock()

        heir = Studio(workspace)
        heir.unlock_heir("maria", "a-long-test-passphrase")
        guide = heir.heir_guide()["guide"]

        assert "# Heir Guide" in guide
        assert "the-deed.txt" in guide


def test_integrity_report_requires_both_audit_and_memory_checks():
    with TemporaryDirectory() as directory:
        studio = Studio(Path(directory) / "legacy")
        studio.create("alex", "a-long-test-passphrase")
        studio.capture("The deed", "The property deed is in the blue folder.", ["home"])

        report = studio.integrity_report()

        assert report["valid"] is True
        assert report["audit"]["valid"] is True
        assert "hmac_checked" in report["audit"]
        assert report["memory"] == {"ok": True, "checked": 1, "errors": []}


def test_dashboard_exposes_whether_audit_used_hmac():
    with TemporaryDirectory() as directory:
        studio = Studio(Path(directory) / "legacy")
        dashboard = studio.create("alex", "a-long-test-passphrase")

        assert "hmac_checked" in dashboard


def test_capture_preserves_safe_supported_text_file_extension():
    with TemporaryDirectory() as directory:
        studio = Studio(Path(directory) / "legacy")
        studio.create("alex", "a-long-test-passphrase")

        result = studio.capture(
            "Legal note", "A contract is in the blue folder.", [], filename="contract.MD"
        )

        assert result["record"]["filename"].endswith("-contract.md")


def test_server_refuses_non_loopback_host():
    with pytest.raises(SystemExit) as exc:
        server.main(["--host", "0.0.0.0"])

    assert exc.value.code == 2
