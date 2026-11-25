"""Tests for the alias emitter in main.py (glob handling, path resolution,
duplicate detection) and for the P2 library fixes.

Direct entrypoint()/generator coverage that would have caught the 0.8.0
regressions: dotted explicit-alias filenames, duplicate alias names, directory
glob matches, relative/~ path storage, and usage text on stdout.
"""

import getpass
import shlex
import shutil
import subprocess
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from env_alias.exceptions import EnvAliasException
from env_alias.lib.generator import EnvAliasGenerator
from env_alias.main import entrypoint
from env_alias.models.envalias_definition import EnvAliasDefinition


def _run(*argv: str):
    """Call entrypoint() with the given argv; returns SystemExit code or None."""
    with patch("sys.argv", ["env-alias", *argv]):
        try:
            entrypoint()
        except SystemExit as e:
            return e.code
    return None


# ---------------------------------------------------------------------------
# P1.1 — dotted filenames with an explicit alias name
# ---------------------------------------------------------------------------


def test_explicit_alias_accepts_dotted_filename(tmp_path, capsys):
    """0.7.1 accepted `env-alias myalias prod.env.yml`; that must keep working."""
    f = tmp_path / "prod.env.yml"
    f.write_text("env-alias:\n    VAR:\n        value: val\n")
    code = _run("myalias", str(f))
    assert code is None
    out = capsys.readouterr().out
    assert 'alias "myalias"' in out
    assert str(f) in out


def test_derived_alias_dotted_filename_errors_with_hint(tmp_path, caplog, capsys):
    """A dotted filename with no explicit alias names an invalid derived alias."""
    f = tmp_path / "prod.env.yml"
    f.write_text("env-alias:\n    VAR:\n        value: val\n")
    code = _run(str(f))
    assert code == 1
    assert capsys.readouterr().out == ""
    assert any("explicit alias" in r.getMessage() for r in caplog.records)


# ---------------------------------------------------------------------------
# P1.2 — duplicate alias names
# ---------------------------------------------------------------------------


def test_duplicate_alias_names_raise(tmp_path, caplog, capsys):
    d1 = tmp_path / "one"
    d1.mkdir()
    d2 = tmp_path / "two"
    d2.mkdir()
    for d in (d1, d2):
        (d / "same.yml").write_text("env-alias:\n    VAR:\n        value: val\n")
    code = _run(str(d1 / "same.yml"), str(d2 / "same.yml"))
    assert code == 1
    assert capsys.readouterr().out == ""
    assert any("Duplicate alias name" in r.getMessage() for r in caplog.records)


def test_duplicate_identical_args_are_deduped(tmp_path, capsys):
    f = tmp_path / "same.yml"
    f.write_text("env-alias:\n    VAR:\n        value: val\n")
    code = _run(str(f), str(f))
    assert code is None
    aliases = [line for line in capsys.readouterr().out.splitlines() if line.startswith("alias ")]
    assert len(aliases) == 1


# ---------------------------------------------------------------------------
# P1.3 — glob matches that are not files
# ---------------------------------------------------------------------------


def test_glob_skips_non_file_match(tmp_path, caplog, capsys):
    (tmp_path / "env-one.yml").write_text("env-alias:\n    V1:\n        value: one\n")
    (tmp_path / "env-two.yml").mkdir()  # a directory with a .yml name
    code = _run(str(tmp_path / "env-*.yml"))
    assert code is None
    assert 'alias "env-one"' in capsys.readouterr().out
    assert any("Skipping non-file glob match" in r.getMessage() for r in caplog.records)


def test_multi_file_mixed_zero_match_glob_preserves_other_aliases(tmp_path, caplog, capsys):
    """A zero-match glob in multi-file mode must warn and skip, not drop other args."""
    f1 = tmp_path / "env-a.yml"
    f2 = tmp_path / "env-b.yml"
    f1.write_text("env-alias:\n    A:\n        value: 1\n")
    f2.write_text("env-alias:\n    B:\n        value: 2\n")
    missing = str(tmp_path / "missing-*.yml")

    # 2-arg multi-file mode
    code = _run(str(f1), missing)
    assert code is None
    out = capsys.readouterr().out
    assert 'alias "env-a"=' in out

    # 3-arg multi-file mode with missing glob first
    code = _run(missing, str(f1), str(f2))
    assert code is None
    out = capsys.readouterr().out
    assert 'alias "env-a"=' in out
    assert 'alias "env-b"=' in out
    assert any("No definition files matched glob pattern" in r.getMessage() for r in caplog.records)


# ---------------------------------------------------------------------------
# P1.4 — absolute path resolution
# ---------------------------------------------------------------------------


def test_relative_path_resolved_absolute(tmp_path, monkeypatch, capsys):
    (tmp_path / "rel.yml").write_text("env-alias:\n    V:\n        value: val\n")
    monkeypatch.chdir(tmp_path)
    code = _run("myalias", "rel.yml")
    assert code is None
    expected = f"'{tmp_path / 'rel.yml'}'"
    assert expected in capsys.readouterr().out


def test_tilde_path_expanded(tmp_path, monkeypatch, capsys):
    target = tmp_path / "x.yml"
    target.write_text("env-alias:\n    V:\n        value: val\n")
    monkeypatch.setenv("HOME", str(tmp_path))
    code = _run("myenv", "~/x.yml")
    assert code is None
    assert str(target) in capsys.readouterr().out


def test_trailing_slash_still_emits_clean_alias(tmp_path, capsys):
    f = tmp_path / "env-a.yml"
    f.write_text("env-alias:\n    V:\n        value: val\n")
    code = _run(str(f) + "/")
    assert code is None
    out = capsys.readouterr().out
    assert 'alias "env-a"' in out
    assert str(f) in out


# ---------------------------------------------------------------------------
# P1.5 — usage text must never land on stdout
# ---------------------------------------------------------------------------


def test_generator_usage_goes_to_stderr(capsys):
    code = _run("--generator")
    assert code is None
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Usage:" in captured.err


# ---------------------------------------------------------------------------
# P5.4 #9 — real-shell round-trip for alias paths with quotes and spaces
# ---------------------------------------------------------------------------


def test_shell_roundtrip_alias_paths(tmp_path):
    """eval the emitted alias in bash and verify the generator receives the
    byte-exact path for inputs containing quotes, dollar signs, and spaces."""
    if shutil.which("bash") is None:
        pytest.skip("bash not available")
    bin_path = shutil.which("env-alias")
    if bin_path is None:
        pytest.skip("env-alias not installed")

    log = tmp_path / "args.log"
    fake_bin = tmp_path / "env-alias"
    fake_bin.write_text("#!/bin/sh\nprintf '%s\\n' \"$@\" >> " + shlex.quote(str(log)) + "\n")
    fake_bin.chmod(0o755)

    d = tmp_path / "we'ird dir$"
    d.mkdir()
    f = d / "secrets file.yml"
    f.write_text("env-alias:\n    V:\n        value: val\n")
    path = str(f)

    result = subprocess.run([bin_path, "myenv", path], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    alias_lines = [line for line in result.stdout.splitlines() if line.startswith("alias ")]
    assert len(alias_lines) == 1

    script = f"shopt -s expand_aliases\nexport PATH={shlex.quote(str(tmp_path))}:$PATH\n" + alias_lines[0] + "\nmyenv\n"
    r2 = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert r2.returncode == 0, r2.stderr

    logged = log.read_text().splitlines()
    assert "--generator" in logged
    assert path in logged


# ---------------------------------------------------------------------------
# P2 — library fixes
# ---------------------------------------------------------------------------


def test_local_file_with_http_prefix_loads_locally(tmp_path, monkeypatch, config_file, capsys):
    """`source` starting with 'http' but not a URL scheme must stay local."""
    (tmp_path / "http-data.txt").write_text("v1\n")
    monkeypatch.chdir(tmp_path)
    f = config_file('    HTTP_VAR:\n        source: "http-data.txt"\n        selector: 1\n')
    EnvAliasGenerator(config_file=f).generate()
    assert " export \"HTTP_VAR\"='v1'" in capsys.readouterr().out


def test_invalid_parser_rejected_at_load(tmp_path, config_file):
    data = tmp_path / "d.txt"
    data.write_text("x\n")
    f = config_file(f'    P_VAR:\n        source: "{data}"\n        parser: toml\n        selector: 1\n')
    with pytest.raises(EnvAliasException):
        EnvAliasGenerator(config_file=f).generate()


def test_parser_env_indirection_preserves_case_and_validates(tmp_path, monkeypatch, config_file, capsys):
    """parser: 'env:NAME' must preserve env-var case, accept valid parsers, and reject invalid ones."""
    data = tmp_path / "payload.txt"
    data.write_text('{"k": "v"}\n')

    monkeypatch.setenv("MY_PARSER", "JSON")
    f = config_file(f'    P_OK:\n        source: "{data}"\n        parser: "env:MY_PARSER"\n        selector: k\n')
    EnvAliasGenerator(config_file=f).generate()
    assert " export \"P_OK\"='v'" in capsys.readouterr().out

    monkeypatch.setenv("MY_PARSER", "toml")
    f_bad = config_file(f'    P_BAD:\n        source: "{data}"\n        parser: "env:MY_PARSER"\n        selector: k\n')
    with pytest.raises(EnvAliasException, match="Invalid 'parser' value"):
        EnvAliasGenerator(config_file=f_bad).generate()


def test_empty_value_with_vault_password_file_rejected():
    """value: '' slipped a truthiness check and later KeyError'd source_map."""
    with pytest.raises(ValidationError):
        EnvAliasDefinition(  # pyright: ignore[reportCallIssue]
            name="X", value="", ansible_vault_password="pw", ansible_vault_password_file=True
        )


def test_unicode_digit_selector_rejected(tmp_path, config_file):
    data = tmp_path / "d.txt"
    data.write_text("l1\nl2\n")
    f = config_file(f'    S_VAR:\n        source: "{data}"\n        selector: "²"\n')
    with pytest.raises(EnvAliasException) as exc_info:
        EnvAliasGenerator(config_file=f).generate()
    assert "Selector for plaintext content must be number" in str(exc_info.value)


def test_ini_percent_values_round_trip(tmp_path, config_file, capsys):
    ini = tmp_path / "cfg.ini"
    ini.write_text("[section]\npwd = s3cr3t%123\nescaped = a%%b\n")
    f = config_file(
        f'    INI1:\n        source: "{ini}"\n        parser: ini\n        selector: section.pwd\n'
        f'    INI2:\n        source: "{ini}"\n        parser: ini\n        selector: section.escaped\n'
    )
    EnvAliasGenerator(config_file=f).generate()
    out = capsys.readouterr().out
    assert " export \"INI1\"='s3cr3t%123'" in out
    assert " export \"INI2\"='a%%b'" in out


def test_invalid_name_fails_before_getpass(tmp_path, monkeypatch, config_file, capsys):
    def boom(*args, **kwargs):
        raise AssertionError("getpass must not be called for an invalid name")

    monkeypatch.setattr(getpass, "getpass", boom)
    f = config_file('    BAD-NAME:\n        source: "<getpass>"\n')
    with pytest.raises(EnvAliasException):
        EnvAliasGenerator(config_file=f).generate()
    assert capsys.readouterr().out == ""


def test_internal_only_hyphenated_name_allowed(config_file, capsys):
    f = config_file(
        "    internal-handle:\n        name: null\n        value: x\n    USE:\n        value: 'env:internal-handle'\n"
    )
    EnvAliasGenerator(config_file=f).generate()
    out = capsys.readouterr().out
    assert " export \"USE\"='x'" in out
    assert "internal-handle" not in out
