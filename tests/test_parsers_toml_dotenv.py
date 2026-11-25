"""Tests for TOML and dotenv (.env) parsers and content-type sniffing."""

import pytest

from env_alias.exceptions import EnvAliasException
from env_alias.lib.generator import EnvAliasGenerator
from env_alias.lib.selector import EnvAliasSelector
from env_alias.lib.source import _sniff_content_type
from env_alias.models.constants import ContentType

# ---------------------------------------------------------------------------
# TOML parser
# ---------------------------------------------------------------------------


class TestTomlParser:
    def test_sniff_toml_extension_and_mime(self):
        assert _sniff_content_type("pyproject.toml") == ContentType.TOML
        assert _sniff_content_type("config.dat", mime="application/toml") == ContentType.TOML

    def test_inferred_toml_file(self, tmp_path, config_file, capsys):
        toml_file = tmp_path / "app.toml"
        toml_file.write_text(
            '[project]\nname = "demo"\nversion = "1.2.3"\nport = 8080\nenabled = true\n'
            'hosts = ["alpha", "beta"]\nrelease_date = 2026-01-15\n'
        )
        f = config_file(
            f'    APP_NAME:\n        source: "{toml_file}"\n        selector: project.name\n'
            f'    APP_PORT:\n        source: "{toml_file}"\n        selector: project.port\n'
            f'    APP_HOST:\n        source: "{toml_file}"\n        selector: "project.hosts[1]"\n'
            f'    APP_DATE:\n        source: "{toml_file}"\n        selector: project.release_date\n'
        )
        EnvAliasGenerator(config_file=f).generate()
        out = capsys.readouterr().out
        assert " export \"APP_NAME\"='demo'" in out
        assert " export \"APP_PORT\"='8080'" in out
        assert " export \"APP_HOST\"='beta'" in out
        assert " export \"APP_DATE\"='2026-01-15'" in out

    def test_explicit_toml_parser_on_arbitrary_extension(self, tmp_path, config_file, capsys):
        data = tmp_path / "settings.conf"
        data.write_text('[db]\nurl = "postgres://localhost/app"\n')
        f = config_file(f'    DB_URL:\n        source: "{data}"\n        parser: toml\n        selector: db.url\n')
        EnvAliasGenerator(config_file=f).generate()
        assert " export \"DB_URL\"='postgres://localhost/app'" in capsys.readouterr().out

    def test_toml_errors(self):
        with pytest.raises(EnvAliasException, match="Selector not provided"):
            EnvAliasSelector.toml_content('a = "b"\n', None)
        with pytest.raises(EnvAliasException, match="Unable to parse"):
            EnvAliasSelector.toml_content("not = [valid toml", "not")
        with pytest.raises(EnvAliasException, match="Unable to find data"):
            EnvAliasSelector.toml_content('[a]\nb = "c"\n', "a.missing")
        with pytest.raises(EnvAliasException, match="Unable to find data"):
            EnvAliasSelector.toml_content('[a]\nb = "c"\n', "a")


# ---------------------------------------------------------------------------
# dotenv (.env) parser
# ---------------------------------------------------------------------------


class TestDotenvParser:
    def test_sniff_dotenv_filenames(self):
        assert _sniff_content_type(".env") == ContentType.DOTENV
        assert _sniff_content_type("/srv/app/.env") == ContentType.DOTENV
        assert _sniff_content_type("/srv/app/.env.local") == ContentType.DOTENV
        assert _sniff_content_type("/srv/app/.env.production") == ContentType.DOTENV
        assert _sniff_content_type("/srv/app/prod.env") == ContentType.DOTENV
        # A directory named .env.d containing a JSON file must still sniff JSON
        assert _sniff_content_type("/srv/.env.d/config.json") == ContentType.JSON

    def test_inferred_dotenv_file_all_syntax_forms(self, tmp_path, config_file, capsys):
        env_file = tmp_path / ".env.local"
        env_file.write_text(
            "# leading comment\n"
            "\n"
            "PLAIN=hello-world\n"
            "WITH_COMMENT=value1 # trailing comment\n"
            "export EXPORTED_KEY=from-export\n"
            "SINGLE_QUOTED='keeps # hash and \\n literal'\n"
            'DOUBLE_QUOTED="line1\\nline2\\t\\"quoted\\" # kept"\n'
            "EMPTY_VAL=\n"
            "OVERRIDE_ME=first\n"
            "OVERRIDE_ME=second\n"
        )
        f = config_file(
            f'    V_PLAIN:\n        source: "{env_file}"\n        selector: PLAIN\n'
            f'    V_COMMENT:\n        source: "{env_file}"\n        selector: WITH_COMMENT\n'
            f'    V_EXPORT:\n        source: "{env_file}"\n        selector: EXPORTED_KEY\n'
            f'    V_SINGLE:\n        source: "{env_file}"\n        selector: SINGLE_QUOTED\n'
            f'    V_DOUBLE:\n        source: "{env_file}"\n        selector: DOUBLE_QUOTED\n'
            f'    V_EMPTY:\n        source: "{env_file}"\n        selector: EMPTY_VAL\n'
            f'    V_OVERRIDE:\n        source: "{env_file}"\n        selector: OVERRIDE_ME\n'
        )
        EnvAliasGenerator(config_file=f).generate()
        out = capsys.readouterr().out
        assert " export \"V_PLAIN\"='hello-world'" in out
        assert " export \"V_COMMENT\"='value1'" in out
        assert " export \"V_EXPORT\"='from-export'" in out
        assert " export \"V_SINGLE\"='keeps # hash and \\n literal'" in out
        assert ' export "V_DOUBLE"=\'line1\nline2\t"quoted" # kept\'' in out
        assert " export \"V_EMPTY\"=''" in out
        assert " export \"V_OVERRIDE\"='second'" in out

    def test_explicit_dotenv_parser(self, tmp_path, config_file, capsys):
        f_src = tmp_path / "vars.txt"
        f_src.write_text("API_KEY=secret=with=equals\n")
        f = config_file(f'    API_KEY:\n        source: "{f_src}"\n        parser: dotenv\n        selector: API_KEY\n')
        EnvAliasGenerator(config_file=f).generate()
        assert " export \"API_KEY\"='secret=with=equals'" in capsys.readouterr().out

    def test_dotenv_errors(self):
        with pytest.raises(EnvAliasException, match="Selector not provided"):
            EnvAliasSelector.dotenv_content("A=1\n", None)
        with pytest.raises(EnvAliasException, match="Unable to locate key"):
            EnvAliasSelector.dotenv_content("A=1\n", "MISSING")
        with pytest.raises(EnvAliasException, match="missing '='"):
            EnvAliasSelector.dotenv_content("NOT_A_PAIR\n", "NOT_A_PAIR")
        with pytest.raises(EnvAliasException, match="empty key"):
            EnvAliasSelector.dotenv_content("=val\n", "A")
        with pytest.raises(EnvAliasException, match="unterminated single quote"):
            EnvAliasSelector.dotenv_content("A='unclosed\n", "A")
        with pytest.raises(EnvAliasException, match="unterminated double quote"):
            EnvAliasSelector.dotenv_content('A="unclosed\n', "A")
