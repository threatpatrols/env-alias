# Structured Local Files

Load values out of common local structured files — INI, JSON, YAML, TOML, and dotenv (`.env`) —
using a parser and selector, without writing any parsing code.

## Example

[source](../definition-attributes/source.md){: .feat .f-src}
[parser](../definition-attributes/parser.md){: .feat .f-parser}
[selector](../definition-attributes/selector.md){: .feat .f-selector}
[value](../definition-attributes/value.md){: .feat .f-value}

```yaml
env-alias:

  BUILD_NUMBER:
    source: "~/.config/myproject/manifest.json"
    parser: "json"
    selector: ".meta.build"

  DOCKER_TAG:
    value: 'env:BUILD_NUMBER'

  APP_VERSION:
    source: "~/projects/myproject/pyproject.toml"
    selector: "project.version"

  DATABASE_URL:
    source: "~/projects/myproject/.env.local"
    selector: "DATABASE_URL"
```

Walkthrough:

1. `BUILD_NUMBER` — `parser: json` deserialises the local manifest and `selector: ".meta.build"`
   pulls out the nested build number. `~` expands to the current user's home directory, so the path
   does not depend on where the alias is invoked.
2. `DOCKER_TAG` — reuses that resolved value via `value: 'env:BUILD_NUMBER'` instead of duplicating
   it.
3. `APP_VERSION` — `.toml` is inferred automatically and `project.version` selects the nested key.
4. `DATABASE_URL` — `.env.local` is inferred as `dotenv` and `DATABASE_URL` selects the exact key.
