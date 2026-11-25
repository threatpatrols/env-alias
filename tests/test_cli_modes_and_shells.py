"""Tests for v0.9.0 CLI modes (--run, --check, --list) and shell targets (--shell)."""

import getpass
import os
import shutil
import subprocess
import sys
from unittest.mock import patch

import pytest

from env_alias.lib.generator import EnvAliasGenerator, _fish_single_quote
from env_alias.main import entrypoint
from env_alias.models.constants import ShellType


def _run(*argv: str):
    with patch("sys.argv", ["env-alias", *argv]):
        try:
            entrypoint()
        except SystemExit as e:
            return e.code
    return None


# ---------------------------------------------------------------------------
# Feature #8 — Alternative shell targets (--shell bash|zsh|fish)
# ---------------------------------------------------------------------------


class TestShellTargets:
    def test_fish_export_syntax_and_quoting(self, config_file, capsys):
        import json

        hostile = "p'w\\$val\"`semi;line1\nline2"
        f = config_file(f"    FISH_VAR:\n        value: {json.dumps(hostile)}\n")
        code = _run("--shell", "fish", "--generator", str(f))
        assert code is None
        out = capsys.readouterr().out
        assert out == f" set -gx FISH_VAR {_fish_single_quote(hostile)}\n"

    def test_fish_alias_emission(self, tmp_path, capsys):
        d = tmp_path / "we'ird\\dir"
        d.mkdir()
        f = d / "env-fish.yml"
        f.write_text("env-alias:\n    A:\n        value: one\n")

        code = _run("--shell", "fish", "--debug", str(f))
        assert code is None
        out = capsys.readouterr().out.strip()
        assert out.startswith("alias env-fish '")
        assert "--debug" in out
        assert "--shell fish" in out
        assert "| source" in out

    @pytest.mark.skipif(shutil.which("fish") is None, reason="fish shell not installed")
    def test_fish_real_shell_roundtrip(self, config_file):
        hostile = "p'w\\$var\"`semi;line1\nline2"
        f = config_file(f"    FISH_RT:\n        value: {hostile!r}\n")
        gen = EnvAliasGenerator(config_file=f, shell=ShellType.FISH)
        line = gen.build_export("FISH_RT", hostile)
        res = subprocess.run(
            ["fish", "-c", f"{line}\nprintf '%s' $FISH_RT"],
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0, res.stderr
        assert res.stdout == hostile

    def test_zsh_target_matches_posix_format(self, config_file, capsys):
        f = config_file("    ZSH_VAR:\n        value: hello\n")
        code = _run("--shell", "zsh", "--generator", str(f))
        assert code is None
        assert " export \"ZSH_VAR\"='hello'" in capsys.readouterr().out

    def test_invalid_shell_rejected(self, config_file, caplog, capsys):
        f = config_file("    A:\n        value: 1\n")
        code = _run("--shell", "cmd", "--generator", str(f))
        assert code == 1
        assert capsys.readouterr().out == ""
        assert "Invalid '--shell' value" in caplog.text


# ---------------------------------------------------------------------------
# Feature #3 — Ephemeral single-command execution (--run)
# ---------------------------------------------------------------------------


class TestRunMode:
    def test_run_injects_exports_hides_internal_and_leaves_parent_clean(self, tmp_path, config_file):
        out_file = tmp_path / "child_env.txt"
        f = config_file(
            "    INTERNAL_SECRET:\n"
            "        name: null\n"
            "        value: 'hidden-secret'\n"
            "    PUBLIC_VAR:\n"
            "        value: 'env:INTERNAL_SECRET'\n"
        )
        child_script = (
            "import os, pathlib; "
            f"pathlib.Path({str(out_file)!r}).write_text("
            "f\"{os.environ.get('PUBLIC_VAR')}|{os.environ.get('INTERNAL_SECRET')}\")"
        )
        code = _run("--run", str(f), "--", sys.executable, "-c", child_script)
        assert code is None
        assert out_file.read_text() == "hidden-secret|None"
        # Parent os.environ must not retain either variable
        assert "PUBLIC_VAR" not in os.environ
        assert "INTERNAL_SECRET" not in os.environ

    def test_run_propagates_child_exit_code_and_preserves_child_flags(self, config_file):
        f = config_file("    X:\n        value: '1'\n")
        # Pass --version and --generator after -- to prove env-alias doesn't intercept child flags
        code = _run(
            "--run",
            str(f),
            "--",
            sys.executable,
            "-c",
            "import sys; assert '--version' in sys.argv and '--generator' in sys.argv; sys.exit(42)",
            "--version",
            "--generator",
        )
        assert code == 42

    def test_run_multi_file(self, tmp_path, config_file):
        f1 = config_file("    A:\n        value: 'alpha'\n")
        f2 = tmp_path / "second.yml"
        f2.write_text("env-alias:\n    B:\n        value: 'env:A'\n")
        out_file = tmp_path / "out.txt"
        code = _run(
            "--run",
            str(f1),
            str(f2),
            "--",
            sys.executable,
            "-c",
            f"import os, pathlib; pathlib.Path({str(out_file)!r}).write_text(os.environ['A'] + ':' + os.environ['B'])",
        )
        assert code is None
        assert out_file.read_text() == "alpha:alpha"

    def test_run_error_cases(self, config_file, capsys):
        f = config_file("    A:\n        value: '1'\n")
        # Bare --run shows usage on stderr
        assert _run("--run") is None
        assert "Usage:" in capsys.readouterr().err

        # Missing '--' separator
        assert _run("--run", str(f)) == 1
        # Missing files before '--'
        assert _run("--run", "--", sys.executable, "-c", "pass") == 1
        # Missing command after '--'
        assert _run("--run", str(f), "--") == 1
        # Nonexistent command
        assert _run("--run", str(f), "--", "nonexistent-command-xyz-9999") == 1
        # Mutually exclusive mode flags
        assert _run("--run", "--generator", str(f), "--", "true") == 1


# ---------------------------------------------------------------------------
# Feature #4 — Static validation (--check) and inspection (--list)
# ---------------------------------------------------------------------------


class TestCheckAndListModes:
    def test_check_valid_file_does_not_prompt_or_exec(self, tmp_path, monkeypatch, config_file, capsys):
        marker = tmp_path / "should_not_exist"

        def boom(*args, **kwargs):
            raise AssertionError("getpass must not run during --check")

        monkeypatch.setattr(getpass, "getpass", boom)
        f = config_file(
            "    PW:\n"
            "        name: null\n"
            "        source: '<getpass>'\n"
            "    USE_PW:\n"
            "        value: 'env:PW'\n"
            "    CMD_VAR:\n"
            f"        exec: 'touch {marker}'\n"
        )
        code = _run("--check", str(f))
        assert code is None
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "OK:" in captured.err
        assert "3 definitions: 2 exported, 1 internal" in captured.err
        assert not marker.exists()

    def test_check_catches_forward_env_reference_and_empty_env(self, config_file, caplog, capsys):
        f = config_file("    FIRST:\n        value: 'env:SECOND'\n    SECOND:\n        value: 'later'\n")
        code = _run("--check", str(f))
        assert code == 1
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "FAIL:" in captured.err
        assert "before it is defined" in caplog.text

        f_empty = config_file("    BAD:\n        value: 'env:'\n")
        assert _run("--check", str(f_empty)) == 1

    def test_check_warns_on_missing_local_source_and_unset_external_env(self, tmp_path, config_file, caplog, capsys):
        missing = tmp_path / "nope.txt"
        f = config_file(
            f'    LOCAL_MISS:\n        source: "{missing}"\n'
            "    EXT_REF:\n        value: 'env:UNSET_EXTERNAL_VAR_XYZ'\n"
        )
        code = _run("--check", str(f))
        assert code is None  # warnings do not fail --check
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "OK:" in captured.err
        assert "2 warning(s)" in captured.err
        assert "local source file not found" in caplog.text
        assert "not defined earlier" in caplog.text

    def test_check_invalid_schema_exits_1(self, config_file, capsys):
        f = config_file("    BAD:\n        unknown_field: 1\n")
        assert _run("--check", str(f)) == 1
        assert capsys.readouterr().out == ""

    def test_check_supports_globs_and_no_args_usage(self, tmp_path, capsys):
        assert _run("--check") is None
        assert "Usage:" in capsys.readouterr().err

        (tmp_path / "env-a.yml").write_text("env-alias:\n    A:\n        value: one\n")
        (tmp_path / "env-b.yml").write_text("env-alias:\n    B:\n        value: 'env:A'\n")
        code = _run("--check", str(tmp_path / "env-*.yml"))
        assert code is None
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err.count("OK:") == 2

    def test_list_outputs_metadata_to_stderr_without_secret_values(self, tmp_path, monkeypatch, config_file, capsys):
        def boom(*args, **kwargs):
            raise AssertionError("getpass must not run during --list")

        monkeypatch.setattr(getpass, "getpass", boom)
        f = config_file(
            "    HIDDEN_PW:\n"
            "        name: null\n"
            "        source: '<getpass>'\n"
            "        override: false\n"
            "    API_TOKEN:\n"
            "        value: 'super-secret-literal-value'\n"
            "        value_to: '<stderr>'\n"
            "    FROM_JSON:\n"
            "        source: '/tmp/data.json'\n"
            "        parser: json\n"
            "        selector: a.b\n"
        )
        code = _run("--list", str(f))
        assert code is None
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "HIDDEN_PW (internal)" in captured.err
        assert "source=getpass" in captured.err
        assert "override=false" in captured.err
        assert "API_TOKEN" in captured.err
        assert "source=value" in captured.err
        assert "value_to=<stderr>" in captured.err
        assert "FROM_JSON" in captured.err
        assert "parser=json" in captured.err
        assert "super-secret-literal-value" not in captured.err

    def test_list_no_args_and_mutually_exclusive_flags(self, config_file, capsys):
        assert _run("--list") is None
        assert "Usage:" in capsys.readouterr().err

        f = config_file("    A:\n        value: '1'\n")
        assert _run("--check", "--list", str(f)) == 1
