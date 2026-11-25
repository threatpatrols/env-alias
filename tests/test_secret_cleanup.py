"""Secret cleanup regression tests.

Secret cleanup was a no-op on the Python side
(``os.unsetenv`` does not update ``os.environ``) and is skipped entirely on
error paths (no ``try/finally``). After a failed keepass/vault fetch, the
password stays in ``os.environ`` and is inherited by every later ``exec:``
step; ``ANSIBLE_VAULT_PASSWORD_FILE`` stays set and the temp password script
is never unlinked.

These tests mock ``EnvAliasSource.execute`` and ``shutil.which`` so they run
without keepassxc-cli or ansible-vault installed.
"""

import glob
import logging
import os
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from env_alias.exceptions import EnvAliasException
from env_alias.lib.definitions import EnvAliasDefinitions
from env_alias.lib.generator import EnvAliasGenerator
from env_alias.lib.logger import LoggingFormatterWrapper
from env_alias.lib.source import EnvAliasSource, _secrets_to_redact

PASSWORD = "super-secret-password-12345"


def _make_fake_file(tmp_path: Path) -> Path:
    f = tmp_path / "data.kdbx"
    f.write_text("dummy")
    return f


def _environ_has_value(value: str) -> str | None:
    """Return the key in os.environ whose value equals `value`, or None."""
    for k, v in os.environ.items():
        if v == value:
            return k
    return None


# ---------------------------------------------------------------------------
# keepass
# ---------------------------------------------------------------------------


def test_keepass_success_cleans_password_from_environ(tmp_path: Path) -> None:
    f = _make_fake_file(tmp_path)
    with (
        patch("env_alias.lib.source.shutil.which", return_value="/usr/bin/keepassxc-cli"),
        patch.object(EnvAliasSource, "_keepass_run", return_value=(0, b"secret-value", b"")),
    ):
        EnvAliasSource.keepass(filename=f, password=PASSWORD, selector="group/entry:Attribute")
    assert _environ_has_value(PASSWORD) is None, "password leaked into os.environ after successful keepass fetch"


def test_keepass_failure_cleans_password_from_environ(tmp_path: Path) -> None:
    f = _make_fake_file(tmp_path)
    with (
        patch("env_alias.lib.source.shutil.which", return_value="/usr/bin/keepassxc-cli"),
        patch.object(EnvAliasSource, "_keepass_run", return_value=(1, b"", b"wrong password")),
        pytest.raises(EnvAliasException),
    ):
        EnvAliasSource.keepass(filename=f, password=PASSWORD, selector="group/entry:Attribute")
    assert _environ_has_value(PASSWORD) is None, "password leaked into os.environ after failed keepass fetch"


def test_keepass_hostile_selector_not_executed(tmp_path: Path) -> None:
    """P1-2: a hostile selector is passed as one argv element, never shell-executed."""
    f = _make_fake_file(tmp_path)
    pwn_file = tmp_path / "ea_pwn"
    hostile_attr = f'att"; touch {pwn_file} ; echo "'

    captured: list[list[str]] = []

    def fake_run(command: list[str], password: str) -> tuple[int, bytes, bytes]:
        captured.append(command)
        return (0, b"ok-value", b"")

    with (
        patch("env_alias.lib.source.shutil.which", return_value="/usr/bin/keepassxc-cli"),
        patch.object(EnvAliasSource, "_keepass_run", side_effect=fake_run),
    ):
        EnvAliasSource.keepass(filename=f, password=PASSWORD, selector=f"group/entry:{hostile_attr}")

    # The hostile attribute was delivered as a single argv element...
    assert captured and hostile_attr in captured[0]
    # ...and was NOT executed as a shell command (no side-effect file).
    assert not pwn_file.exists()
    # The password must not touch os.environ.
    assert _environ_has_value(PASSWORD) is None


# ---------------------------------------------------------------------------
# ansible_vault
# ---------------------------------------------------------------------------


def test_ansible_vault_success_cleans_password_and_file(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    f = _make_fake_file(tmp_path)
    captured_env: list[dict[str, str]] = []

    def fake_run(command: list[str], env: dict[str, str]) -> tuple[int, bytes, bytes]:
        captured_env.append(env)
        assert os.path.isfile(env["ANSIBLE_VAULT_PASSWORD_FILE"])
        return (0, b"key: decrypted\n", b"")

    with (
        patch("env_alias.lib.source.shutil.which", return_value="/usr/bin/ansible-vault"),
        patch.object(EnvAliasSource, "_ansible_vault_run", side_effect=fake_run),
    ):
        result = EnvAliasSource.ansible_vault(filename=f, password=PASSWORD)

    assert result.content == "key: decrypted"
    assert _environ_has_value(PASSWORD) is None, "password leaked into os.environ after successful vault decrypt"
    assert "ANSIBLE_VAULT_PASSWORD_FILE" not in os.environ
    assert not os.path.exists(captured_env[0]["ANSIBLE_VAULT_PASSWORD_FILE"])


def test_ansible_vault_preserves_existing_password_file_env(tmp_path: Path, monkeypatch) -> None:
    """ansible_vault() must not clobber a pre-existing ANSIBLE_VAULT_PASSWORD_FILE in os.environ."""
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setenv("ANSIBLE_VAULT_PASSWORD_FILE", "/custom/vault-pass.sh")
    f = _make_fake_file(tmp_path)

    with (
        patch("env_alias.lib.source.shutil.which", return_value="/usr/bin/ansible-vault"),
        patch.object(EnvAliasSource, "_ansible_vault_run", return_value=(0, b"ok\n", b"")),
    ):
        EnvAliasSource.ansible_vault(filename=f, password=PASSWORD)

    assert os.environ.get("ANSIBLE_VAULT_PASSWORD_FILE") == "/custom/vault-pass.sh"


def test_ansible_vault_hostile_filename_not_shell_executed(tmp_path: Path, monkeypatch) -> None:
    """Vault filename with shell metacharacters is passed as one argv element, never via shell=True."""
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.chdir(tmp_path)
    pwn_file = tmp_path / "vault_pwn"
    hostile = tmp_path / 'v"; touch vault_pwn; echo "$HOME".vault'
    hostile.write_text("dummy")

    captured_cmds: list[list[str]] = []

    def fake_run(command: list[str], env: dict[str, str]) -> tuple[int, bytes, bytes]:
        captured_cmds.append(command)
        return (0, b"ok\n", b"")

    with (
        patch("env_alias.lib.source.shutil.which", return_value="/usr/bin/ansible-vault"),
        patch.object(EnvAliasSource, "_ansible_vault_run", side_effect=fake_run),
    ):
        EnvAliasSource.ansible_vault(filename=hostile, password=PASSWORD)

    assert captured_cmds == [["/usr/bin/ansible-vault", "decrypt", "--output", "-", str(hostile)]]
    assert not pwn_file.exists()


def test_ansible_vault_ephemeral_script_preserves_echo_special_password(tmp_path: Path, monkeypatch) -> None:
    """Ephemeral decrypt helper script must use printf so -n and backslashes survive."""
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    f = _make_fake_file(tmp_path)
    tricky_pw = r"-n back\nslash\\end"

    def fake_run(command: list[str], env: dict[str, str]) -> tuple[int, bytes, bytes]:
        proc = subprocess.run(
            [env["ANSIBLE_VAULT_PASSWORD_FILE"]],
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        assert proc.stdout == f"{tricky_pw}\n"
        return (0, b"ok\n", b"")

    with (
        patch("env_alias.lib.source.shutil.which", return_value="/usr/bin/ansible-vault"),
        patch.object(EnvAliasSource, "_ansible_vault_run", side_effect=fake_run),
    ):
        EnvAliasSource.ansible_vault(filename=f, password=tricky_pw)


def test_ansible_vault_failure_cleans_password_and_file(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    f = _make_fake_file(tmp_path)
    with (
        patch("env_alias.lib.source.shutil.which", return_value="/usr/bin/ansible-vault"),
        patch.object(EnvAliasSource, "_ansible_vault_run", return_value=(1, b"", b"wrong password")),
        pytest.raises(EnvAliasException),
    ):
        EnvAliasSource.ansible_vault(filename=f, password=PASSWORD)

    assert _environ_has_value(PASSWORD) is None, "password leaked into os.environ after failed vault decrypt"
    assert "ANSIBLE_VAULT_PASSWORD_FILE" not in os.environ
    leftover = glob.glob(str(tmp_path / "env-alias-vault-*"))
    assert not leftover, f"temp password script left on disk after failed vault decrypt: {leftover}"


# ---------------------------------------------------------------------------
# Redaction, exception wrapping, and logger hygiene
# ---------------------------------------------------------------------------


def test_execute_failure_redacts_stdout_and_stderr(caplog) -> None:
    secret = "super-secret-exec-token"
    _secrets_to_redact["TOK"] = secret
    try:
        with pytest.raises(EnvAliasException) as exc_info:
            EnvAliasSource.execute(f"printf '{secret}-out'; printf '{secret}-err' >&2; exit 1")
        assert secret not in str(exc_info.value)
        assert "<redacted>-err" in str(exc_info.value)
        assert secret not in caplog.text
        assert "<redacted>-out" in caplog.text
    finally:
        _secrets_to_redact.clear()


def test_secrets_registry_cleared_after_generate(config_file, capsys) -> None:
    f = config_file("    MY_SEC:\n        value: 'top-secret-value'\n")
    EnvAliasGenerator(config_file=f).generate()
    capsys.readouterr()
    assert _secrets_to_redact == {}

    f_fail = config_file("    MY_SEC:\n        value: 'top-secret-value'\n    BAD:\n        exec: 'exit 1'\n")
    with pytest.raises(EnvAliasException):
        EnvAliasGenerator(config_file=f_fail).generate()
    assert _secrets_to_redact == {}


def test_binary_files_and_stdin_eof_wrap_as_envalias_exception(tmp_path: Path, monkeypatch) -> None:
    bad_file = tmp_path / "binary.dat"
    bad_file.write_bytes(b"\xff\xfe\x00\x01")
    with pytest.raises(EnvAliasException):
        EnvAliasSource.local(bad_file)
    with pytest.raises(EnvAliasException):
        EnvAliasDefinitions().load_definitions(bad_file)

    monkeypatch.setattr("builtins.input", lambda: (_ for _ in ()).throw(EOFError()))
    with pytest.raises(EnvAliasException, match="Unexpected EOF"):
        EnvAliasSource.stdin("prompt: ")


def test_logger_formatter_respects_colorize_false_and_preserves_record(monkeypatch) -> None:
    fmt_off = LoggingFormatterWrapper(fmt="%(levelname)s: %(message)s", colorize_levelname=False)
    assert fmt_off.colorize_levelname is False

    fmt_on = LoggingFormatterWrapper(fmt="%(levelname)s: %(message)s", colorize_levelname=True)
    record = logging.LogRecord("env-alias", logging.ERROR, __file__, 1, "boom", (), None)
    monkeypatch.setattr("sys.stderr.isatty", lambda: True)
    monkeypatch.delenv("NO_COLOR", raising=False)
    formatted = fmt_on.format(record)
    assert "\x1b[" in formatted
    assert record.levelname == "ERROR"  # not permanently mutated

    monkeypatch.setattr("sys.stderr.isatty", lambda: False)
    plain = fmt_on.format(record)
    assert "\x1b[" not in plain
