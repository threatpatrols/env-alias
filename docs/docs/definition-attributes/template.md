# template

The `template` definition-attribute composes a string from earlier definitions and process environment
variables using explicit `{NAME}` placeholders. Like `value`, it bypasses `source`, `parser`, and
`selector`.

Use `value` when you want a literal string (where `{...}` is kept verbatim) or a whole-value `env:NAME`
reference. Use `template` when you need to combine multiple variables into one value, such as a database
connection URI or a file path.

## Placeholder rules

* `{NAME}` looks up `NAME` in the process environment first, then in earlier definitions in the same run
  (matching `env:NAME` resolution order). If `NAME` is unset, generation fails with an error.
* Placeholder names must match `[A-Za-z_][A-Za-z0-9_-]*` (supporting `name: null` hyphenated handles).
  Attribute access or format specifiers such as `{VAR.__class__}` are rejected at load time.
* Expansion is **single-pass**: substituted secret values are never re-scanned for `{...}` placeholders.
* Escape literal braces as `{{` and `}}`.
* `template` cannot be combined with `source`, `exec`, `value`, `sops`, `keepass_password`,
  `ansible_vault_password`, or `ansible_vault_password_file`.

## Example

```yaml
env-alias:

  DB_USER:
    name: null
    value: "appuser"

  DB_PASS:
    name: null
    source: "<getpass>"

  DB_HOST:
    name: null
    value: "db.internal"

  DATABASE_URL:
    template: "postgres://{DB_USER}:{DB_PASS}@{DB_HOST}:5432/app"
```
