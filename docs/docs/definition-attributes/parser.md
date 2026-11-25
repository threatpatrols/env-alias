# parser

The `parser` attribute controls how local, remote, and `exec` content is deserialised before selection.
When omitted, Env Alias infers `ini`, `json`, `yaml`, `toml`, or `dotenv` from a file extension or HTTP
`Content-Type` header. All other content is treated as plaintext.

Supported explicit parser values are:

* `ini`
* `json`
* `yaml` or `yml`
* `toml`
* `dotenv`
* `none` - return the complete raw content without parsing or selecting it

There is no explicit `text` parser. Omit `parser` for plaintext content; use a line-number `selector`
to choose a line, or omit the selector to use line 1. Structured parsers require a `selector`: JSON,
YAML, and TOML selectors must resolve to a scalar value rather than a mapping or list, and `dotenv`
selectors match the exact key name.

### Example - INI

Parse `aws_access_key_id` from a standard AWS credentials file.

```yaml
env-alias:
  AWS_ACCESS_KEY_ID:
    source: "~/.aws/credentials"
    parser: ini
    selector: "default.aws_access_key_id"
```


### Example - YAML

Parse a YAML file whose extension does not identify its format.

```yaml
env-alias:
  EXAMPLE:
    source: "/tmp/foobar.data"
    parser: yaml
    selector: "/foo/bar/data"
```


### Example - inferred JSON

The `.json` extension lets Env Alias infer the JSON parser.

```yaml
env-alias:
  EXAMPLE:
    source: "/tmp/foobar.json"
    selector: "/foo/bar/data"
```


### Example - TOML

Parse a nested value from a TOML file (`.toml` is also inferred automatically).

```yaml
env-alias:
  APP_VERSION:
    source: "~/project/pyproject.toml"
    parser: toml
    selector: "project.version"
```


### Example - dotenv (`.env`)

Read a key from a `.env` file (`.env`, `.env.*`, and `*.env` filenames are inferred automatically).

```yaml
env-alias:
  DATABASE_URL:
    source: "~/project/.env.local"
    parser: dotenv
    selector: "DATABASE_URL"
```


### Example - raw content

Use `parser: none` to return all content unchanged, even when the filename implies JSON.

```yaml
env-alias:
  EXAMPLE:
    source: "/tmp/foobar.json"
    parser: none
```
