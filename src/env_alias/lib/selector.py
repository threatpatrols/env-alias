import configparser
import json
import re
from collections.abc import Callable
from typing import Any

import yaml

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
}
