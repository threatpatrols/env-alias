"""Tests for Feature #7 (SOPS source strategy) and Feature #10 (template composition)."""

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from env_alias.exceptions import EnvAliasException
from env_alias.lib.generator import EnvAliasGenerator
from env_alias.lib.source import EnvAliasSource, _secrets_to_redact
from env_alias.main import entrypoint
from env_alias.models.constants import ContentType, SourceMethod
from env_alias.models.envalias_definition import EnvAliasDefinition


def _run(*argv: str):
    with patch("sys.argv", ["env-alias", *argv]):
        try:
            entrypoint()
        except SystemExit as e:
            return e.code
    return None


# ---------------------------------------------------------------------------
# Feature #7 — SOPS source strategy
# ---------------------------------------------------------------------------


class TestSopsSource:
    def test_sops_decrypts_yaml_and_sniffs_enc_suffixes(self, tmp_path: Path, config_file, capsys):
        for fname in ("secrets.enc.yaml", "secrets.yaml.enc"):
            enc = tmp_path / fname
            enc.write_text("sops-ciphertext")

            f = config_file(
                f'    DB_PASS:\n        source: "{enc}"\n        sops: true\n        selector: db.password\n'
            )
            with (
                patch("env_alias.lib.source.shutil.which", return_value="/usr/bin/sops"),
                patch.object(EnvAliasSource, "_sops_run", return_value=(0, b"db:\n  password: s3cr3t\n", b"")),
            ):
                EnvAliasGenerator(config_file=f).generate()
            assert " export \"DB_PASS\"='s3cr3t'" in capsys.readouterr().out

    def test_sops_decrypts_json_and_dotenv_sops_suffix(self, tmp_path: Path, config_file, capsys):
        json_enc = tmp_path / "app.enc.json"
        json_enc.write_text("cipher")
        env_enc = tmp_path / ".env.sops"
        env_enc.write_text("cipher")

        with (
            patch("env_alias.lib.source.shutil.which", return_value="/usr/bin/sops"),
            patch.object(EnvAliasSource, "_sops_run", return_value=(0, b'{"api": {"key": "k123"}}', b"")),
        ):
            res = EnvAliasSource.sops(json_enc)
            assert res.source_method == SourceMethod.SOPS
            assert res.content_type == ContentType.JSON

        f = config_file(f'    TOKEN:\n        source: "{env_enc}"\n        sops: true\n        selector: TOKEN\n')
        with (
            patch("env_alias.lib.source.shutil.which", return_value="/usr/bin/sops"),
            patch.object(EnvAliasSource, "_sops_run", return_value=(0, b"TOKEN=tok-abc\n", b"")),
        ):
            EnvAliasGenerator(config_file=f).generate()
        assert " export \"TOKEN\"='tok-abc'" in capsys.readouterr().out

    def test_sops_hostile_filename_uses_argv_list(self, tmp_path: Path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        pwn = tmp_path / "sops_pwn"
        hostile = tmp_path / 'sec"; touch sops_pwn; echo ".enc.yaml'
        hostile.write_text("cipher")
        captured: list[list[str]] = []

        def fake_run(command: list[str]) -> tuple[int, bytes, bytes]:
            captured.append(command)
            return (0, b"a: b\n", b"")

        with (
            patch("env_alias.lib.source.shutil.which", return_value="/usr/bin/sops"),
            patch.object(EnvAliasSource, "_sops_run", side_effect=fake_run),
        ):
            EnvAliasSource.sops(hostile)

        assert captured == [["/usr/bin/sops", "--decrypt", str(hostile)]]
        assert not pwn.exists()

    def test_sops_error_paths_and_redaction(self, tmp_path: Path):
        enc = tmp_path / "s.enc.yaml"
        enc.write_text("cipher")

        with (
            patch("env_alias.lib.source.shutil.which", return_value=None),
            pytest.raises(EnvAliasException, match="Unable to locate required binary 'sops'"),
        ):
            EnvAliasSource.sops(enc)

        with (
            patch("env_alias.lib.source.shutil.which", return_value="/usr/bin/sops"),
            pytest.raises(EnvAliasException, match="Unable to locate file"),
        ):
            EnvAliasSource.sops(tmp_path / "missing.enc.yaml")

        _secrets_to_redact["K"] = "my-secret-key"
        try:
            with (
                patch("env_alias.lib.source.shutil.which", return_value="/usr/bin/sops"),
                patch.object(EnvAliasSource, "_sops_run", return_value=(1, b"", b"failed with my-secret-key")),
                pytest.raises(EnvAliasException) as exc_info,
            ):
                EnvAliasSource.sops(enc)
            assert "my-secret-key" not in str(exc_info.value)
            assert "<redacted>" in str(exc_info.value)
        finally:
            _secrets_to_redact.clear()

        with (
            patch("env_alias.lib.source.shutil.which", return_value="/usr/bin/sops"),
            patch.object(EnvAliasSource, "_sops_run", return_value=(0, b"", b"")),
            pytest.raises(EnvAliasException, match="Empty content"),
        ):
            EnvAliasSource.sops(enc)

        with (
            patch("env_alias.lib.source.shutil.which", return_value="/usr/bin/sops"),
            patch.object(EnvAliasSource, "_sops_run", return_value=(0, b"\xff\xfe", b"")),
            pytest.raises(EnvAliasException, match="non-UTF-8"),
        ):
            EnvAliasSource.sops(enc)

    def test_sops_model_validation(self):
        with pytest.raises(ValidationError):
            EnvAliasDefinition(name="X", sops=True, value="v")  # pyright: ignore[reportCallIssue]
        with pytest.raises(ValidationError):
            EnvAliasDefinition(name="X", sops=True, source="a.yaml", keepass_password="pw")  # pyright: ignore[reportCallIssue]
        with pytest.raises(ValidationError):
            EnvAliasDefinition(name="X", sops=True, source="a.yaml", ansible_vault_password="pw")  # pyright: ignore[reportCallIssue]
        with pytest.raises(ValidationError):
            EnvAliasDefinition(name="X", sops=True, source="<getpass>")  # pyright: ignore[reportCallIssue]
        with pytest.raises(ValidationError):
            EnvAliasDefinition(name="X", sops=True, source="https://example.com/a.yaml")  # pyright: ignore[reportCallIssue]

    def test_sops_check_and_list(self, tmp_path: Path, config_file, caplog, capsys):
        enc = tmp_path / "prod.enc.yaml"
        enc.write_text("cipher")
        f = config_file(f'    SECRET:\n        source: "{enc}"\n        sops: true\n        selector: a.b\n')

        with patch("env_alias.lib.generator.shutil.which", return_value=None):
            assert _run("--check", str(f)) is None
        assert "requires 'sops'" in caplog.text
        capsys.readouterr()

        assert _run("--list", str(f)) is None
        err = capsys.readouterr().err
        assert "SECRET" in err
        assert "source=sops" in err


# ---------------------------------------------------------------------------
# Feature #10 — Explicit string composition (template:)
# ---------------------------------------------------------------------------


class TestTemplateAttribute:
    def test_template_composes_earlier_definitions_and_env_vars(self, monkeypatch, config_file, capsys):
        monkeypatch.setenv("EXT_HOST", "db.internal")
        f = config_file(
            "    db-user:\n"
            "        name: null\n"
            "        value: 'alice'\n"
            "    DB_PASS:\n"
            "        name: null\n"
            "        value: 'p@ss!word'\n"
            "    DATABASE_URL:\n"
            "        template: 'postgres://{db-user}:{DB_PASS}@{EXT_HOST}:5432/app'\n"
        )
        EnvAliasGenerator(config_file=f).generate()
        out = capsys.readouterr().out
        assert " export \"DATABASE_URL\"='postgres://alice:p@ss!word@db.internal:5432/app'" in out
        assert "db-user" not in out
        assert "DB_PASS" not in out

    def test_template_literal_braces_and_single_pass_no_reexpansion(self, config_file, capsys):
        f = config_file(
            "    OTHER:\n"
            "        value: 'SHOULD_NOT_APPEAR'\n"
            "    TRICKY:\n"
            "        name: null\n"
            "        value: 'pw-{OTHER}-$HOME'\n"
            "    JSON_BLOB:\n"
            '        template: \'{{"secret": "{TRICKY}"}}\'\n'
            "    LITERAL_VALUE:\n"
            "        value: 'untouched {OTHER}'\n"
        )
        EnvAliasGenerator(config_file=f).generate()
        out = capsys.readouterr().out
        assert ' export "JSON_BLOB"=\'{"secret": "pw-{OTHER}-$HOME"}\'' in out
        assert " export \"LITERAL_VALUE\"='untouched {OTHER}'" in out

        # Verify real bash round-trip on the composed output
        res = subprocess.run(["bash", "-c", f"{out}\nprintf '%s' \"$JSON_BLOB\""], capture_output=True, text=True)
        assert res.returncode == 0, res.stderr
        assert res.stdout == '{"secret": "pw-{OTHER}-$HOME"}'

    def test_template_validation_and_unset_errors(self, config_file):
        # Malformed placeholders rejected at model load time
        for bad in ("{}", "{VAR.__class__}", "{123}", "{unclosed", "stray}"):
            with pytest.raises(ValidationError):
                EnvAliasDefinition(name="X", template=bad)  # pyright: ignore[reportCallIssue]

        # Mutual exclusivity
        with pytest.raises(ValidationError):
            EnvAliasDefinition(name="X", template="a", value="b")  # pyright: ignore[reportCallIssue]
        with pytest.raises(ValidationError):
            EnvAliasDefinition(name="X", template="a", source="f.txt")  # pyright: ignore[reportCallIssue]
        with pytest.raises(ValidationError):
            EnvAliasDefinition(name="X", template="a", exec_="echo hi")  # pyright: ignore[reportCallIssue]
        with pytest.raises(ValidationError):
            EnvAliasDefinition(name="X", template="a", keepass_password="pw")  # pyright: ignore[reportCallIssue]

        # Unset variable fails cleanly at runtime
        f = config_file("    URL:\n        template: 'https://{UNSET_VAR_XYZ}/api'\n")
        with pytest.raises(EnvAliasException, match="references an unset variable"):
            EnvAliasGenerator(config_file=f).generate()

    def test_template_check_and_list(self, config_file, caplog, capsys):
        # Forward reference caught by --check
        f_fwd = config_file("    A:\n        template: 'hello-{B}'\n    B:\n        value: 'world'\n")
        assert _run("--check", str(f_fwd)) == 1
        assert "before it is defined" in caplog.text
        capsys.readouterr()

        # Valid template passes --check and appears in --list without leaking values
        f_ok = config_file(
            "    HOST:\n"
            "        name: null\n"
            "        value: 'secret-host'\n"
            "    URL:\n"
            "        template: 'https://{HOST}/api'\n"
        )
        assert _run("--check", str(f_ok)) is None
        assert "OK:" in capsys.readouterr().err

        assert _run("--list", str(f_ok)) is None
        err = capsys.readouterr().err
        assert "URL" in err
        assert "source=template" in err
        assert "secret-host" not in err
