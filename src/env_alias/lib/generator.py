import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from .. import DEFINITIONS_ROOT, LOGGER_LEVEL, LOGGER_NAME
from ..exceptions import EnvAliasException
from ..lib.definitions import EnvAliasDefinitions
from ..lib.logger import logger_get
from ..lib.selector import PARSER_STRATEGIES, EnvAliasSelector
from ..lib.source import SOURCE_STRATEGIES, _secrets_to_redact
from ..models.constants import ContentType, ParserType, SelectorType, ShellType, SourceMethod, ValueTo
from ..models.envalias_definition import TEMPLATE_TOKEN_RE, EnvAliasDefinition, extract_template_placeholders
from ..models.sourced_content import SourcedContent

logger = logger_get(name=LOGGER_NAME, loglevel=LOGGER_LEVEL)

_ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

# Map content types to their corresponding parser types for PARSER_STRATEGIES lookup
_CONTENT_TO_PARSER: dict[ContentType, ParserType] = {
    ContentType.JSON: ParserType.JSON,
    ContentType.INI: ParserType.INI,
    ContentType.YAML: ParserType.YAML,
    ContentType.TOML: ParserType.TOML,
    ContentType.DOTENV: ParserType.DOTENV,
    ContentType.TEXT: ParserType.NONE,
}

_ENV_REPLACEMENT_ATTRS = ("value", "source", "parser", "selector", "keepass_password", "ansible_vault_password")


def _redact_secrets(text: str, secrets: dict[str, str]) -> str:
    """Replace secret values with <redacted> in debug output."""
    redacted = text
    for value in secrets.values():
        if value and len(value) > 2:
            redacted = redacted.replace(value, "<redacted>")
    return redacted


def _sh_single_quote(s: str) -> str:
    """POSIX single-quote ``s`` unconditionally.

    Inside single quotes the shell performs no expansion, so this is the only
    quoting mode that safely carries arbitrary secret values (passwords with
    ``"``, ``$``, `` ` ``, ``\\``, newlines, ...) into the user's shell without
    corruption or command injection. A literal single quote is escaped by
    closing the quote, emitting an escaped ``\\'``, and reopening.
    """
    return "'" + s.replace("'", "'\\''") + "'"


def _fish_single_quote(s: str) -> str:
    """Fish shell single-quote ``s`` unconditionally.

    Inside Fish single quotes only ``\\`` and ``'`` are interpreted as escapes;
    everything else (``$``, ``"``, `` ` ``, ``;``, newlines, ...) is literal.
    """
    return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _describe_source(definition: EnvAliasDefinition) -> str:
    """Return a concise source label for a definition without fetching or running anything."""
    if definition.value is not None:
        return "env" if definition.value.startswith("env:") else "value"
    if definition.template is not None:
        return "template"
    for strategy in SOURCE_STRATEGIES:
        if strategy.matches(definition):
            if strategy.name == "local" and definition.source and definition.source.startswith("env:"):
                return "local (env:)"
            return strategy.name
    return "unknown"


class EnvAliasGenerator:
    definitions_files: list[Path]
    values_generated: dict[str, str]
    source_map: dict[str, str]
    shell: ShellType

    def __init__(self, config_file: Path | list[Path], shell: ShellType = ShellType.BASH):
        if isinstance(config_file, Path):
            self.definitions_files = [config_file]
        else:
            self.definitions_files = config_file
        self.values_generated = {}
        self.source_map = {}
        self.shell = shell

    def generate(self) -> None:
        logger.debug("EnvAliasGenerator.generate()")
        _secrets_to_redact.clear()

        try:
            # All-or-nothing output across all files: buffer every export line
            # and flush only after every definition in every file succeeds.
            all_exports: list[str] = []
            for config_file in self.definitions_files:
                for env_name, env_value in self._resolve_from_file(config_file):
                    all_exports.append(self.build_export(env_name=env_name, env_value=env_value))

            for line in all_exports:
                print(line, file=sys.stdout)
        finally:
            _secrets_to_redact.clear()

    def run(self, command: list[str]) -> int:
        """Resolve definitions and run *command* with exported vars injected only into the child env."""
        logger.debug(f"EnvAliasGenerator.run(command={command!r})")
        if not command:
            raise EnvAliasException("A command is required after '--'.")

        base_env = os.environ.copy()
        _secrets_to_redact.clear()
        try:
            exports: list[tuple[str, str]] = []
            for config_file in self.definitions_files:
                exports.extend(self._resolve_from_file(config_file))
        finally:
            os.environ.clear()
            os.environ.update(base_env)
            _secrets_to_redact.clear()

        child_env = {**base_env, **dict(exports)}
        try:
            result = subprocess.run(command, env=child_env)
        except (FileNotFoundError, PermissionError, OSError) as e:
            raise EnvAliasException(f"Unable to execute command {command[0]!r}: {e}", detail=e) from e
        return result.returncode

    def check(self) -> bool:
        """Statically validate definition files without fetching secrets or running commands.

        Writes diagnostics and a summary to stderr. Returns True if all files
        passed with zero errors, False otherwise.
        """
        logger.debug("EnvAliasGenerator.check()")
        all_ok = True
        seen_across_files: set[str] = set()

        for config_file in self.definitions_files:
            try:
                definitions = EnvAliasDefinitions(definitions_root=DEFINITIONS_ROOT).load_definitions(config_file)
            except EnvAliasException:
                all_ok = False
                continue

            if not definitions:
                logger.error(f"{config_file}: Empty or malformed definitions file.")
                all_ok = False
                continue

            file_errors = 0
            file_warnings = 0
            all_file_names = {d.name for d in definitions}
            seen_in_file: set[str] = set()
            defined_so_far = set(seen_across_files)

            for definition in definitions:
                if definition.name in seen_in_file:
                    logger.warning(f"{config_file}: Duplicate definition name {definition.name!r}.")
                    file_warnings += 1
                seen_in_file.add(definition.name)

                for attr_name in _ENV_REPLACEMENT_ATTRS:
                    attr_value = getattr(definition, attr_name)
                    if attr_value and str(attr_value).startswith("env:"):
                        ref_name = str(attr_value)[4:]
                        if not ref_name:
                            logger.error(f"{config_file}: {definition.name!r} has empty 'env:' in {attr_name!r}.")
                            file_errors += 1
                        elif ref_name not in defined_so_far and ref_name in all_file_names:
                            logger.error(
                                f"{config_file}: {definition.name!r} references 'env:{ref_name}' in {attr_name!r} "
                                "before it is defined."
                            )
                            file_errors += 1
                        elif ref_name not in defined_so_far and ref_name not in os.environ:
                            logger.warning(
                                f"{config_file}: {definition.name!r} references 'env:{ref_name}' in {attr_name!r}, "
                                "which is not defined earlier or currently set in the environment."
                            )
                            file_warnings += 1

                if definition.template is not None:
                    for ref_name in extract_template_placeholders(definition.template):
                        if ref_name not in defined_so_far and ref_name in all_file_names:
                            logger.error(
                                f"{config_file}: {definition.name!r} template references '{{{ref_name}}}' "
                                "before it is defined."
                            )
                            file_errors += 1
                        elif ref_name not in defined_so_far and ref_name not in os.environ:
                            logger.warning(
                                f"{config_file}: {definition.name!r} template references '{{{ref_name}}}', "
                                "which is not defined earlier or currently set in the environment."
                            )
                            file_warnings += 1

                if definition.source and definition.keepass_password and shutil.which("keepassxc-cli") is None:
                    logger.warning(
                        f"{config_file}: {definition.name!r} requires 'keepassxc-cli', which is not on PATH."
                    )
                    file_warnings += 1

                if definition.source and definition.ansible_vault_password and shutil.which("ansible-vault") is None:
                    logger.warning(
                        f"{config_file}: {definition.name!r} requires 'ansible-vault', which is not on PATH."
                    )
                    file_warnings += 1

                if definition.sops and shutil.which("sops") is None:
                    logger.warning(f"{config_file}: {definition.name!r} requires 'sops', which is not on PATH.")
                    file_warnings += 1

                if (
                    definition.source
                    and not definition.source.startswith("env:")
                    and definition.source not in ("<stdin>", "<getpass>")
                    and not definition.source.lower().startswith(("http://", "https://"))
                ):
                    src_path = Path(os.path.expanduser(definition.source))
                    if not os.path.isfile(src_path):
                        logger.warning(
                            f"{config_file}: {definition.name!r} local source file not found: {definition.source!r}."
                        )
                        file_warnings += 1

                defined_so_far.add(definition.name)

            seen_across_files.update(defined_so_far)

            exported_count = sum(1 for d in definitions if not d.is_internal_only)
            internal_count = len(definitions) - exported_count
            if file_errors:
                all_ok = False
                print(
                    f"FAIL: {config_file} ({file_errors} error(s), {file_warnings} warning(s))",
                    file=sys.stderr,
                )
            else:
                warn_suffix = f", {file_warnings} warning(s)" if file_warnings else ""
                print(
                    f"OK: {config_file} ({len(definitions)} definitions: "
                    f"{exported_count} exported, {internal_count} internal{warn_suffix})",
                    file=sys.stderr,
                )

        return all_ok

    def list_definitions(self) -> None:
        """Print defined variable names and metadata to stderr without fetching secrets."""
        logger.debug("EnvAliasGenerator.list_definitions()")
        for idx, config_file in enumerate(self.definitions_files):
            definitions = EnvAliasDefinitions(definitions_root=DEFINITIONS_ROOT).load_definitions(config_file)
            if not definitions:
                raise EnvAliasException(f"Empty or malformed {config_file=}")

            if idx > 0:
                print(file=sys.stderr)
            print(f"# {config_file}", file=sys.stderr)
            width = max(len(d.name) + (11 if d.is_internal_only else 0) for d in definitions)
            for definition in definitions:
                label = f"{definition.name} (internal)" if definition.is_internal_only else definition.name
                parts = [f"source={_describe_source(definition)}"]
                if definition.parser:
                    parts.append(f"parser={definition.parser}")
                if definition.override is False:
                    parts.append("override=false")
                if definition.value_to:
                    parts.append(f"value_to={definition.value_to}")
                print(f"  {label:<{width}}  {'  '.join(parts)}", file=sys.stderr)

    def _resolve_from_file(self, config_file: Path) -> list[tuple[str, str]]:
        definitions = EnvAliasDefinitions(definitions_root=DEFINITIONS_ROOT).load_definitions(config_file)
        if not definitions:
            raise EnvAliasException(f"Empty or malformed {config_file=}")

        exports: list[tuple[str, str]] = []

        for definition in definitions:
            is_existing_setting = definition.name in os.environ or definition.name in self.values_generated
            if definition.override is False and is_existing_setting:
                logger.debug(f"Skipping {definition.name!r} because already set and definition.override=False.")
                continue

            value = self.get_definition_value(definition=self.update_env_replacement_attributes(definition))

            if value is not None:  # NB: not just "if value" because value could be a valid empty string
                self.values_generated[definition.name] = value
                _secrets_to_redact[definition.name] = value
                os.environ[definition.name] = str(value)  # exists at this process and sub-process only

                if definition.value_to:
                    if definition.value_to == ValueTo.STDERR:
                        print(value, file=sys.stderr)
                    else:
                        # '<stdout>' is rejected at the model; this guards any
                        # other invalid value defensively.
                        raise EnvAliasException("Unsupported 'value_to' value encountered.")

                if definition.is_internal_only is True:
                    logger.debug(
                        f"Definition for {definition.name!r} defines a 'null' name for env-alias internal "
                        f"only use, skipping generated output."
                    )
                    continue

                exports.append((definition.name, value))

                if definition.ansible_vault_password_file:  # special additional output case
                    exports.append((self.source_map[value], definition.ansible_vault_password or ""))

        return exports

    def build_export(
        self,
        env_name: str,
        env_value: str | None = "",
        output_prefix: str = " ",
        shell: ShellType | None = None,
    ) -> str:
        if not _ENV_NAME_RE.fullmatch(env_name):
            raise EnvAliasException(
                f"Invalid environment variable name {env_name!r}: must match ^[A-Za-z_][A-Za-z0-9_]*$"
            )
        target_shell = shell if shell is not None else getattr(self, "shell", ShellType.BASH)
        value_str = "" if env_value is None else str(env_value)
        if target_shell == ShellType.FISH:
            output = f"{output_prefix}set -gx {env_name} {_fish_single_quote(value_str)}"
        else:
            # Value is POSIX single-quoted unconditionally: double quotes would let
            # the shell expand $, `, \, and a literal " would terminate the string
            # — both corrupting the value and enabling command injection (P0-2).
            # The name is double-quoted to preserve the documented output shape
            # (asserted by ~15 tests and intentional shell-history suppression);
            # it is validated above so the double quotes carry no injection risk.
            output = f'{output_prefix}export "{env_name}"={_sh_single_quote(value_str)}'
        logger.debug(f"output={_redact_secrets(output, self.values_generated)!r}")
        return output

    def render_template(self, template: str) -> str:
        """Render a single-pass ``{VAR}`` template using os.environ and earlier definitions."""

        def _replace(match: re.Match[str]) -> str:
            token = match.group(1)
            var_name = match.group(2)
            if token == "{{":
                return "{"
            if token == "}}":
                return "}"
            if var_name is None:
                raise EnvAliasException(
                    f"Invalid template placeholder {token!r}: use '{{NAME}}' or '{{' / '}}' for literal braces."
                )
            env_value = os.getenv(var_name, None)
            if env_value is None:
                env_value = self.values_generated.get(var_name)
            if env_value is None:
                raise EnvAliasException(f"Template placeholder '{{{var_name}}}' references an unset variable.")
            return env_value

        return TEMPLATE_TOKEN_RE.sub(_replace, template)

    def get_definition_value(self, definition: EnvAliasDefinition) -> str | None:
        logger.debug(f"EnvAliasGenerator.get_definition_value({definition.name=}, ...)")

        if definition.value is not None:
            return definition.value

        if definition.template is not None:
            return self.render_template(definition.template)

        sourced_content = self.get_content_from_source(definition=definition)

        parser = sourced_content.content_type
        if definition.parser:
            try:
                parser = (
                    ParserType(definition.parser.lower()) if isinstance(definition.parser, str) else definition.parser
                )
            except ValueError as e:
                allowed = ", ".join(p.value for p in ParserType)
                raise EnvAliasException(
                    f"Invalid 'parser' value {definition.parser!r}: must be one of {allowed}"
                ) from e

        parser_key = _CONTENT_TO_PARSER.get(parser, ParserType.NONE) if isinstance(parser, ContentType) else parser

        if (
            sourced_content.source_method in (SourceMethod.GETPASS, SourceMethod.STDIN, SourceMethod.KEEPASS)
            or parser == ParserType.NONE
        ):
            return sourced_content.content

        if definition.selector == SelectorType.NONE:
            return None

        parser_fn = PARSER_STRATEGIES.get(parser_key)
        if parser_fn:
            return parser_fn(sourced_content.content, definition.selector)

        selector_str = str(definition.selector) if definition.selector is not None else ""
        if selector_str and not (selector_str.isascii() and selector_str.isdigit()):
            raise EnvAliasException(f"Selector for plaintext content must be number {definition.selector=}")
        elif definition.selector is None:
            definition.selector = "1"

        return EnvAliasSelector.text_content(sourced_content.content, selector=int(definition.selector))

    def get_content_from_source(self, definition: EnvAliasDefinition) -> SourcedContent:
        for strategy in SOURCE_STRATEGIES:
            if strategy.matches(definition):
                sourced_content = strategy.fetch(definition)

                if sourced_content.source_method == SourceMethod.ANSIBLE_VAULT_PASSWORD_FILE:
                    self.source_map[sourced_content.content] = sourced_content.source

                return sourced_content

        raise EnvAliasException(f"Definition for env-alias {definition.name!r} is malformed.")

    def update_env_replacement_attributes(self, definition: EnvAliasDefinition) -> EnvAliasDefinition:
        for attr_name in _ENV_REPLACEMENT_ATTRS:
            attr_value = getattr(definition, attr_name)
            if attr_value and str(attr_value).startswith("env:"):
                setattr(definition, attr_name, self.get_replacement_env_value(attr_value))
        return definition

    def get_replacement_env_value(self, value: str) -> str:
        env_name = value[4:]

        env_value = os.getenv(env_name, None)
        if env_value is None:
            env_value = self.values_generated.get(env_name)

        if env_value is None:
            raise EnvAliasException(f"Definition replacement using {value!r} environment value that is unset.")

        return env_value
