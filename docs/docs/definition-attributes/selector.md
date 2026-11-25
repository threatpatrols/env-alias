# selector

The `selector` attribute chooses one value from parsed content.

JSON, YAML, and TOML selectors support equivalent dot, slash, and bracket forms (including trailing
bracket indices like `items[0]` and numeric string dictionary keys), for example:

* `service.ports.0.number`
* `/service/ports/0/number`
* `service.ports[0].number`

INI selectors use exactly `<section>.<option>`. Dotenv (`parser: dotenv`) selectors match the exact
variable key name (e.g. `DATABASE_URL`). All structured parsers require a selector, and JSON, YAML,
or TOML selections must resolve to a scalar (`string`, number, boolean, or ISO-formatted date/time),
not a mapping or list.

Plaintext selectors are one-based line numbers. If a plaintext selector is omitted, Env Alias returns
line 1.

`selector: null` and literal `selector: none` remain supported as legacy no-output sentinels for
normal parsed-source paths. They do not suppress direct `value`, `<stdin>`, `<getpass>`, KeePass, or
`parser: none` results. Use `name: null` when a definition must never export a value.


### Example - JSON path

Select a nested scalar with a dot/bracket path.

```yaml
env-alias:
    EXAMPLE:
        source: "config.json"
        selector: ".services[1].url"
```


### Example - INI path

Select an option from an INI section.

```yaml
env-alias:
    EXAMPLE:
        source: "~/.aws/credentials"
        parser: ini
        selector: "default.aws_access_key_id"
```


### Example - dotenv key

Select a key by exact name from a `.env` file.

```yaml
env-alias:
    DATABASE_URL:
        source: ".env.local"
        selector: "DATABASE_URL"
```


### Example - line number

Select line 5 from plaintext content.

```yaml
env-alias:
    EXAMPLE:
        source: "/proc/cpuinfo"
        selector: 5
```
