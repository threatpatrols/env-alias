import argparse
import glob
import os
import re
import sys
from pathlib import Path

from . import LOGGER_LEVEL, LOGGER_NAME, __title__, __version__
from .exceptions import EnvAliasException
from .lib.logger import logger_get, logger_setlevel
from .models.constants import ShellType

logger = logger_get(name=LOGGER_NAME, loglevel=LOGGER_LEVEL)

# Alias names (unlike environment variable names) may contain hyphens, e.g.
# ``env-awesome-vars``. Hyphens are safe inside the double-quoted alias-name
# in the emitted ``alias`` statement — the P0-2 injection hardening guarded
# against ``$`\\`` characters, not ``-``.
_ALIAS_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")
# A definition file must carry a .yml/.yaml suffix; any basename is allowed so
# dotted filenames (e.g. ``prod.env.yml``) work with an explicit alias name.
# Alias names derived from a filename stem must still match _ALIAS_NAME_RE.
_DEF_SUFFIX_RE = re.compile(r".+\.ya?ml$", re.IGNORECASE)
_DEF_GLOB_RE = re.compile(r"^.*\.ya?ml$", re.IGNORECASE)


def _has_yaml_suffix(path: str) -> bool:
    """Return True if the basename of *path* ends with .yml/.yaml (any stem)."""
    clean_path = path.rstrip("/\\")
    basename = os.path.basename(clean_path)
    return bool(_DEF_SUFFIX_RE.fullmatch(basename))


def _resolve_definition_files(arg: str) -> list[str]:
    """Resolve a positional argument to one or more definition filenames.

    Globs (*, ?) are expanded; an empty match logs a warning and returns [].
    Static filenames are validated syntactically (must end .yml/.yaml) without
    touching the filesystem. All returned paths are absolute so the emitted
    alias works from any working directory.
    """
    clean_path = arg.rstrip("/\\")
    basename = os.path.basename(clean_path)
    if not basename:
        raise EnvAliasException(f"Definition file path {arg!r} is invalid: must be a YAML file, not a directory.")

    if glob.has_magic(arg):
        if not _DEF_GLOB_RE.fullmatch(basename):
            raise EnvAliasException(f"Definition glob pattern {arg!r} must end with .yml or .yaml")
        matches = sorted(glob.glob(os.path.expanduser(arg)))
        if not matches:
            logger.warning(f"No definition files matched glob pattern: {arg}")
            return []
        files = []
        for f in matches:
            if not os.path.isfile(f):
                logger.warning(f"Skipping non-file glob match: {f}")
                continue
            files.append(os.path.abspath(f))
        return files

    if not _has_yaml_suffix(arg):
        raise EnvAliasException(f"Definition filename {basename!r} must end with .yml or .yaml")

    return [os.path.abspath(os.path.expanduser(arg))]


def _entries_from_files(files: list[str]) -> list[tuple[str, str]]:
    """Build (alias_name, filename) entries, deriving names from file stems."""
    entries: list[tuple[str, str]] = []
    for f in files:
        alias_name = os.path.splitext(os.path.basename(f))[0]
        if not _ALIAS_NAME_RE.fullmatch(alias_name):
            raise EnvAliasException(
                f"Invalid alias name {alias_name!r}: must match ^[A-Za-z_][A-Za-z0-9_-]*$; "
                "for filenames with dots, pass an explicit alias name: env-alias <alias> <definitions.yml>"
            )
        entries.append((alias_name, f))
    return entries


def _is_definition_arg(arg: str) -> bool:
    """Return True if arg looks like a definition file or glob rather than an alias name."""
    return bool(glob.has_magic(arg) or _has_yaml_suffix(arg))


def _fish_single_quote(s: str) -> str:
    """Fish shell single-quote *s* unconditionally."""
    return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _expand_file_args(args: list[str]) -> list[Path]:
    """Expand file paths and globs for --check / --list modes."""
    paths: list[Path] = []
    for arg in args:
        if glob.has_magic(arg):
            paths.extend(Path(f) for f in _resolve_definition_files(arg))
        else:
            paths.append(Path(os.path.expanduser(arg)))
    return paths


def entrypoint() -> None:
    parser = argparse.ArgumentParser(
        description=f"{__title__} v{__version__}",
        epilog="Usage: env-alias [<alias>] [--debug] [--shell bash|zsh|fish] <definitions.[yml|yaml]>",
        add_help=False,
    )
    parser.add_argument("--version", action="version", version=f"{__title__} v{__version__}")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--generator", action="store_true")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--list", action="store_true", dest="list_defs")
    parser.add_argument("--shell", default=ShellType.BASH.value)
    parser.add_argument("args", nargs="*")

    try:
        raw_argv = sys.argv[1:]
        run_command: list[str] | None = None
        if "--" in raw_argv and "--run" in raw_argv[: raw_argv.index("--")]:
            sep_idx = raw_argv.index("--")
            cli_argv = raw_argv[:sep_idx]
            run_command = raw_argv[sep_idx + 1 :]
        else:
            cli_argv = raw_argv

        args = parser.parse_args(cli_argv)

        if args.debug:
            logger_setlevel(LOGGER_NAME, "debug")

        try:
            shell = ShellType(str(args.shell).lower())
        except ValueError as e:
            allowed = ", ".join(s.value for s in ShellType)
            raise EnvAliasException(f"Invalid '--shell' value {args.shell!r}: must be one of {allowed}") from e

        active_modes = sum(bool(flag) for flag in (args.generator, args.run, args.check, args.list_defs))
        if active_modes > 1:
            raise EnvAliasException("Only one of --generator, --run, --check, or --list may be specified.")

        if args.generator:
            if not args.args:
                usage_help(exit_code=0)
            from env_alias.lib.generator import EnvAliasGenerator

            EnvAliasGenerator(config_file=[Path(f) for f in args.args], shell=shell).generate()
            return

        if args.run:
            if not args.args and run_command is None:
                usage_help(exit_code=0)
                return
            if run_command is None:
                raise EnvAliasException("Usage: env-alias --run <definitions.yml>... -- <command> [args...]")
            if not args.args:
                raise EnvAliasException("At least one definitions file is required before '--'.")
            if not run_command:
                raise EnvAliasException("A command is required after '--'.")
            from env_alias.lib.generator import EnvAliasGenerator

            rc = EnvAliasGenerator(config_file=[Path(f) for f in args.args], shell=shell).run(run_command)
            if rc != 0:
                exit(rc)
            return

        if args.check:
            if not args.args:
                usage_help(exit_code=0)
                return
            from env_alias.lib.generator import EnvAliasGenerator

            files = _expand_file_args(args.args)
            if not files:
                return
            ok = EnvAliasGenerator(config_file=files).check()
            if not ok:
                exit(1)
            return

        if args.list_defs:
            if not args.args:
                usage_help(exit_code=0)
                return
            from env_alias.lib.generator import EnvAliasGenerator

            files = _expand_file_args(args.args)
            if not files:
                return
            EnvAliasGenerator(config_file=files).list_definitions()
            return

        if not args.args:
            usage_help(exit_code=0)
            return

        # Process positionals for alias mode. The result is a list of
        # (alias_name, filename) pairs, one entry per alias to emit.
        entries: list[tuple[str, str]] = []

        if len(args.args) == 1:
            files = _resolve_definition_files(args.args[0])
            if not files:
                return
            entries = _entries_from_files(files)

        elif len(args.args) == 2:
            arg0, arg1 = args.args[0], args.args[1]
            if _is_definition_arg(arg0):
                # Multi-file mode: both args are definition files / patterns
                for arg in args.args:
                    files = _resolve_definition_files(arg)
                    if not files:
                        continue
                    entries.extend(_entries_from_files(files))
            else:
                # First arg is explicit alias name
                alias_name = arg0
                if not _ALIAS_NAME_RE.fullmatch(alias_name):
                    raise EnvAliasException(f"Invalid alias name {alias_name!r}: must match ^[A-Za-z_][A-Za-z0-9_-]*$")
                files = _resolve_definition_files(arg1)
                if not files:
                    return
                if len(files) > 1:
                    raise EnvAliasException(
                        f"An explicit alias name may be followed by only one definition file, got {len(files)}."
                    )
                entries = [(alias_name, files[0])]

        elif len(args.args) >= 3:
            arg0 = args.args[0]
            if not _is_definition_arg(arg0) and _ALIAS_NAME_RE.fullmatch(arg0):
                trailing = args.args[1:]
                raise EnvAliasException(
                    f"An explicit alias name may be followed by only one definition file, got {len(trailing)}."
                )
            for arg in args.args:
                files = _resolve_definition_files(arg)
                if not files:
                    continue
                entries.extend(_entries_from_files(files))
        else:
            usage_help(exit_code=0)
            return

        if not entries:
            return

        # Drop exact duplicates (same name and same resolved path), then refuse
        # a repeated name with different paths — that would silently overwrite
        # the earlier alias in the user's shell. Both checks run before any
        # stdout output so emission stays all-or-nothing.
        entries = [e for i, e in enumerate(entries) if e not in entries[:i]]
        seen: dict[str, str] = {}
        for alias_name, filename in entries:
            if alias_name in seen and seen[alias_name] != filename:
                raise EnvAliasException(
                    f"Duplicate alias name {alias_name!r} from {seen[alias_name]!r} and {filename!r}; "
                    "use explicit alias names to disambiguate."
                )
            seen[alias_name] = filename

        # Emit one alias per entry. Each RHS runs the generator against that
        # entry's single definition file only, preserving per-alias lazy loading.
        generator_cmd = "env-alias"
        if args.debug:
            generator_cmd += " --debug"
        if shell == ShellType.FISH:
            generator_cmd += " --shell fish"
            for alias_name, filename in entries:
                fish_file = _fish_single_quote(filename)
                inner_cmd = f"{generator_cmd} --generator {fish_file} | source"
                alias_command = f"alias {alias_name} {_fish_single_quote(inner_cmd)}"
                logger.debug(alias_command)
                print(alias_command)
        else:
            for alias_name, filename in entries:
                quoted_file = "'" + filename.replace("'", "'\\''") + "'"
                rhs = f"source <({generator_cmd} --generator {quoted_file})"

                rhs_dq = rhs.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("`", "\\`")
                alias_command = f'alias "{alias_name}"="{rhs_dq}"'
                logger.debug(alias_command)
                print(alias_command)

    except EnvAliasException:
        print("Exiting", file=sys.stderr)
        exit(1)
    except KeyboardInterrupt:
        print("Exiting", file=sys.stderr)
        exit(130)
    except SystemExit as e:
        if e.code == 0:
            return
        exit(e.code)


def usage_help(exit_code: int | None = None) -> None:
    # stdout is shell code that the user's shell sources/evals — help text must
    # never land there (its "Usage: ... [<alias>]" line even contains `<...>`
    # redirection tokens that a sourcing shell would execute).
    print(file=sys.stderr)
    print(f"{__title__} v{__version__}", file=sys.stderr)
    print(file=sys.stderr)
    print("Usage:", file=sys.stderr)
    print("  env-alias [<alias>] [--debug] [--shell bash|zsh|fish] <definitions.[yml|yaml]>...", file=sys.stderr)
    print("  env-alias --generator [--debug] [--shell bash|zsh|fish] <definitions.[yml|yaml]>...", file=sys.stderr)
    print("  env-alias --run [--debug] <definitions.[yml|yaml]>... -- <command> [args...]", file=sys.stderr)
    print("  env-alias --check <definitions.[yml|yaml]>...", file=sys.stderr)
    print("  env-alias --list <definitions.[yml|yaml]>...", file=sys.stderr)
    print("Docs: https://threatpatrols.github.io/env-alias/", file=sys.stderr)
    print(file=sys.stderr)
    if exit_code is not None:
        exit(exit_code)
