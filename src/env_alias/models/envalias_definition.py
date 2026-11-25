import re
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .constants import ParserType, ValueTo

_EXCEPTION_END = "in an env-alias definition."
_PARSER_CHOICES = ", ".join(p.value for p in ParserType)

# Matches escaped braces ('{{', '}}'), valid variable placeholders ('{NAME}'),
# or any malformed brace sequence ('{...}', stray '{' or '}').
TEMPLATE_TOKEN_RE = re.compile(r"(\{\{|\}\}|\{([A-Za-z_][A-Za-z0-9_-]*)\}|\{[^}]*\}|\{|\})")


def extract_template_placeholders(template: str) -> list[str]:
    """Validate *template* brace syntax and return referenced variable names in order."""
    names: list[str] = []
    for match in TEMPLATE_TOKEN_RE.finditer(template):
        token = match.group(1)
        var_name = match.group(2)
        if token in ("{{", "}}"):
            continue
        if var_name is not None:
            names.append(var_name)
        else:
            raise ValueError(
                f"Invalid template placeholder {token!r}: use '{{NAME}}' with [A-Za-z_][A-Za-z0-9_-]* "
                "or '{{' / '}}' for literal braces."
            )
    return names


class EnvAliasDefinition(BaseModel):
    """Defines how a single environment variable value is generated."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    name: str
    value: str | None = None
    template: str | None = None
    source: str | None = None
    exec_: str | None = Field(None, alias="exec")  # type: ignore[assignment]

    parser: str | None = None
    selector: str | None = None
    value_to: str | None = None

    override: bool = True
    keepass_password: str | None = None
    ansible_vault_password: str | None = None
    ansible_vault_password_file: bool = False
    sops: bool = False

    filename: Path = Field(default=Path("."), exclude=True)
    is_internal_only: bool = False

    @field_validator("selector", mode="before")
    @classmethod
    def coerce_selector(cls, v: object) -> object:
        if v is not None and not isinstance(v, str):
            return str(v)
        return v

    @field_validator("override", "ansible_vault_password_file", "sops", mode="before")
    @classmethod
    def coerce_bool(cls, v: object) -> object:
        if isinstance(v, str):
            if v.lower() in ("true", "yes"):
                return True
            if v.lower() in ("false", "no"):
                return False
        return v

    @field_validator("template")
    @classmethod
    def valid_template(cls, v: str | None) -> str | None:
        if v is not None:
            extract_template_placeholders(v)
        return v

    @field_validator("parser", "value_to")
    @classmethod
    def lowercase(cls, v: str | None) -> str | None:
        if v and not v.startswith("env:"):
            return v.lower()
        return v

    @field_validator("parser")
    @classmethod
    def valid_parser(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if not v:
            return None  # empty string behaves as unset (falsy parser was always ignored)
        if v.startswith("env:"):
            return v
        try:
            ParserType(v)
        except ValueError as e:
            raise ValueError(f"Invalid 'parser' value {v!r}: must be one of {_PARSER_CHOICES}") from e
        return v

    @field_validator("value_to")
    @classmethod
    def valid_value_to(cls, v: str | None) -> str | None:
        # '<stdout>' was removed in env-alias 0.7.0: it wrote raw, unquoted text
        # into the stdout stream that the user's shell sources, so it could never
        # be a safe message — only broken output (and a command-execution risk).
        if v == "<stdout>":
            raise ValueError(
                "'value_to: <stdout>' was removed because it wrote raw, unquoted text into "
                "the stream your shell sources. Use 'value_to: <stderr>' to send a message "
                "to the terminal instead."
            )
        if v and v != ValueTo.STDERR:
            raise ValueError(f"Invalid 'value_to' value, must be '<stderr>' only {_EXCEPTION_END}")
        return v

    @model_validator(mode="after")
    def check_cross_field_constraints(self) -> "EnvAliasDefinition":
        if self.exec_ and self.source:
            raise ValueError(f"Cannot use 'exec' and 'source' {_EXCEPTION_END}")
        if self.exec_ and self.value is not None:
            raise ValueError(f"Cannot use 'exec' and 'value' {_EXCEPTION_END}")
        if self.source and self.value is not None:
            raise ValueError(f"Cannot use 'source' and 'value' {_EXCEPTION_END}")
        if self.template is not None and (self.exec_ or self.source or self.value is not None):
            raise ValueError(f"Cannot combine 'template' with 'source', 'exec' or 'value' {_EXCEPTION_END}")
        if (
            not self.source
            and not self.exec_
            and self.value is None
            and self.template is None
            and not self.ansible_vault_password_file
        ):
            raise ValueError(f"Must have one 'source', 'exec', 'value' or 'template' {_EXCEPTION_END}")
        if self.keepass_password and self.ansible_vault_password:
            raise ValueError(f"Cannot use both 'keepass_password' and 'ansible_vault_password' {_EXCEPTION_END}")
        if self.ansible_vault_password_file and (
            self.exec_
            or self.source
            or self.value is not None
            or self.template is not None
            or self.keepass_password
            or self.sops
        ):
            raise ValueError(
                f"Can only use 'ansible_vault_password_file' with 'ansible_vault_password' {_EXCEPTION_END}"
            )
        if self.ansible_vault_password_file and not self.ansible_vault_password:
            raise ValueError(f"Must use 'ansible_vault_password_file' with 'ansible_vault_password' {_EXCEPTION_END}")
        if self.sops:
            if not self.source:
                raise ValueError(f"Must use 'sops' with 'source' {_EXCEPTION_END}")
            if self.keepass_password or self.ansible_vault_password:
                raise ValueError(
                    f"Cannot combine 'sops' with 'keepass_password' or 'ansible_vault_password' {_EXCEPTION_END}"
                )
            if self.source in ("<stdin>", "<getpass>") or self.source.lower().startswith(("http://", "https://")):
                raise ValueError(f"Cannot use 'sops' with non-file source {self.source!r} {_EXCEPTION_END}")
        if self.template is not None and (self.keepass_password or self.ansible_vault_password):
            raise ValueError(
                f"Cannot combine 'template' with 'keepass_password' or 'ansible_vault_password' {_EXCEPTION_END}"
            )
        return self
