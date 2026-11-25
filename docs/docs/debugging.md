# Debugging & Inspection

## Validate and inspect without running

Use `--check` to validate YAML syntax, schema constraints, `env:` ordering, local source paths, and
required binaries without prompting, fetching secrets, or executing `exec:` commands:

```shell
env-alias --check ~/projects/awesome/env-awesome-vars.yml
```

Use `--list` to inspect the variable names, internal-only markers, source types, and parsers defined
in a file (written to STDERR; secret values are never printed):

```shell
env-alias --list ~/projects/awesome/env-awesome-vars.yml
```

## Verbose debug logs (`--debug`)

Add `--debug` to see diagnostic logs on STDERR while the alias is generated:

```shell
source <(env-alias --debug ~/projects/awesome/env-awesome-vars.yml)
```

You can also set `ENVALIAS_DEBUG=true` before invoking the alias. Debug output can include definition
paths, selectors, command lines, and resolved values. Treat it as sensitive: do not paste it into an
issue tracker or chat without reviewing and redacting it first. See [Security](security.md) for details.
