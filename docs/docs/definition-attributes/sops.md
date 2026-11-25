# sops

The `sops` definition-attribute is a boolean that decrypts a local [SOPS](https://getsops.io/)-encrypted
`source` file using `sops --decrypt` before parsing and selecting a value. Env Alias requires `sops` on
`PATH` and invokes it as an argv list without a shell.

Because SOPS manages its own keys (`age`, GPG, AWS KMS, GCP KMS, Azure Key Vault), no password attribute
is needed in the definition file.

## Format inference

Env Alias strips a trailing `.enc` or `.sops` extension when inferring the underlying format, so filenames
such as `secrets.enc.yaml`, `secrets.yaml.enc`, `secrets.enc.json`, and `.env.sops` are parsed
automatically. You can still set `parser` explicitly to override inference.

## Constraints

* Must be paired with a local file `source`.
* Cannot be combined with `exec`, `value`, `template`, `keepass_password`, `ansible_vault_password`,
  `ansible_vault_password_file`, `<stdin>`, `<getpass>`, or HTTP(S) URLs.

## Example

```yaml
env-alias:

  DB_USERNAME:
    source: "~/secrets/prod.enc.yaml"
    sops: true
    selector: "database.username"

  DB_PASSWORD:
    source: "~/secrets/prod.enc.yaml"
    sops: true
    selector: "database.password"
```
