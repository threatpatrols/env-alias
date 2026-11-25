import configparser
import datetime
import json
import re
from collections.abc import Callable
from typing import Any

import yaml

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    import tomli as tomllib  # type: ignore[no-redef]

from ..exceptions import EnvAliasException
from ..models.constants import ParserType


class EnvAliasSelector:
    @staticmethod
    def text_content(content: str, selector: int) -> str:
        lines = content.replace("\r", "").rstrip("\n").split("\n")
        s = int(selector)
        if s < 1 or s > len(lines):
            raise EnvAliasException(f"Text content selector {selector!r} is out of range; text has {len(lines)} lines.")

        return lines[s - 1]

    @staticmethod
    def ini_content(content: str, selector_path: str | None) -> str:
        if not selector_path:
            raise EnvAliasException("Selector not provided; must define a 'selector' for 'ini' parsing.")

        selector_paths = EnvAliasSelector.__parse_selector_path(selector_path).split(".")

        if len(selector_paths) != 2:
            raise EnvAliasException('Selector path for INI content must be in the form "<section>.<option>" only.')

        try:
            # interpolation=None: values routinely contain '%' (passwords) and
            # BasicInterpolation would raise on them. Consequence: '%%' is no
            # longer an escape — it stays a literal '%%'.
            config = configparser.ConfigParser(interpolation=None)
            config.read_string(content)
        except Exception as e:
            raise EnvAliasException("Unable to parse and load the INI content data provided.", detail=e) from e

        selector_section, selector_option = selector_paths

        try:
            return config.get(selector_section, selector_option)
        except Exception as e:
            raise EnvAliasException('Unable to locate "<section>.<option>" in INI content provided.', detail=e) from e

    @staticmethod
    def json_content(content: str, selector_path: str | None) -> str:
        if not selector_path:
            raise EnvAliasException("Selector not provided; must define a 'selector' for 'json' parsing.")

        selector_paths = EnvAliasSelector.__parse_selector_path(selector_path)

        try:
            data = json.loads(content)
        except Exception as e:
            raise EnvAliasException("Unable to parse and load the JSON content data provided.", detail=e) from e

        try:
            return EnvAliasSelector.__data_select(data, selector_paths)
        except Exception as e:
            raise EnvAliasException("Unable to find data at supplied path in JSON content.", detail=e) from e

    @staticmethod
    def yaml_content(content: str, selector_path: str | None) -> str:
        if not selector_path:
            raise EnvAliasException("Selector not provided; must define a 'selector' for 'yaml' parsing.")

        selector_paths = EnvAliasSelector.__parse_selector_path(selector_path)

        try:
            data = yaml.safe_load(content)
        except Exception as e:
            raise EnvAliasException("Unable to parse and load the YAML content data provided.", detail=e) from e

        try:
            return EnvAliasSelector.__data_select(data, selector_paths)
        except Exception as e:
            raise EnvAliasException("Unable to find data at supplied path in YAML content.", detail=e) from e

    @staticmethod
    def toml_content(content: str, selector_path: str | None) -> str:
        if not selector_path:
            raise EnvAliasException("Selector not provided; must define a 'selector' for 'toml' parsing.")

        selector_paths = EnvAliasSelector.__parse_selector_path(selector_path)

        try:
            data = tomllib.loads(content)
        except Exception as e:
            raise EnvAliasException("Unable to parse and load the TOML content data provided.", detail=e) from e

        try:
            return EnvAliasSelector.__data_select(data, selector_paths)
        except Exception as e:
            raise EnvAliasException("Unable to find data at supplied path in TOML content.", detail=e) from e

    @staticmethod
    def dotenv_content(content: str, selector_path: str | None) -> str:
        if not selector_path:
            raise EnvAliasException("Selector not provided; must define a 'selector' for 'dotenv' parsing.")

        parsed = EnvAliasSelector._parse_dotenv(content)
        if selector_path not in parsed:
            raise EnvAliasException(f"Unable to locate key {selector_path!r} in dotenv content provided.")
        return parsed[selector_path]

    @staticmethod
    def _parse_dotenv(content: str) -> dict[str, str]:
        """Parse a .env file into a flat string mapping without third-party deps."""
        result: dict[str, str] = {}
        for line_no, raw_line in enumerate(content.replace("\r\n", "\n").replace("\r", "\n").split("\n"), start=1):
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if stripped.startswith("export ") or stripped.startswith("export\t"):
                stripped = stripped[6:].lstrip()

            if "=" not in stripped:
                raise EnvAliasException(f"Malformed dotenv line {line_no}: missing '=' separator.")

            key, raw_val = stripped.split("=", 1)
            key = key.strip()
            if not key:
                raise EnvAliasException(f"Malformed dotenv line {line_no}: empty key name.")

            val = raw_val.lstrip()
            if not val:
                result[key] = ""
            elif val[0] == "'":
                end_idx = val.find("'", 1)
                if end_idx == -1:
                    raise EnvAliasException(f"Malformed dotenv line {line_no}: unterminated single quote.")
                result[key] = val[1:end_idx]
            elif val[0] == '"':
                chars: list[str] = []
                i = 1
                closed = False
                escape_map = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\"}
                while i < len(val):
                    ch = val[i]
                    if ch == "\\" and i + 1 < len(val):
                        nxt = val[i + 1]
                        chars.append(escape_map.get(nxt, "\\" + nxt))
                        i += 2
                        continue
                    if ch == '"':
                        closed = True
                        break
                    chars.append(ch)
                    i += 1
                if not closed:
                    raise EnvAliasException(f"Malformed dotenv line {line_no}: unterminated double quote.")
                result[key] = "".join(chars)
            else:
                # Strip inline comment preceded by whitespace (e.g. `FOO=bar # comment`)
                comment_match = re.search(r"\s+#", val)
                if comment_match:
                    val = val[: comment_match.start()]
                result[key] = val.strip()

        return result

    @staticmethod
    def __data_select(root: Any, path: str, sep: str = ".") -> str:
        current = root
        for segment in path.split(sep):
            if isinstance(current, list):
                if not (segment.isascii() and segment.isdigit()):
                    raise KeyError(f"List index must be a non-negative integer, got {segment!r}")
                current = current[int(segment)]
            elif isinstance(current, dict):
                if segment in current:
                    current = current[segment]
                elif segment.isascii() and segment.isdigit() and int(segment) in current:
                    current = current[int(segment)]
                else:
                    raise KeyError(segment)
            else:
                raise TypeError(f"Cannot traverse into {type(current).__name__} with {segment!r}")
        if isinstance(current, (datetime.datetime, datetime.date, datetime.time)):
            return current.isoformat()
        if not isinstance(current, (str, int, float, bool)):
            raise EnvAliasException(f"Selection resolved to {type(current).__name__}, but only scalars are supported.")
        return str(current)

    @staticmethod
    def __parse_selector_path(selector_path: str) -> str:
        normalized = selector_path.replace("/", ".").replace("[", ".").replace("]", ".")
        return re.sub(r"\.+", ".", normalized).strip(".")


PARSER_STRATEGIES: dict[ParserType, Callable[[str, str | None], str]] = {
    ParserType.INI: EnvAliasSelector.ini_content,
    ParserType.JSON: EnvAliasSelector.json_content,
    ParserType.YAML: EnvAliasSelector.yaml_content,
    ParserType.YML: EnvAliasSelector.yaml_content,
    ParserType.TOML: EnvAliasSelector.toml_content,
    ParserType.DOTENV: EnvAliasSelector.dotenv_content,
}
