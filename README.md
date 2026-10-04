# vault-seal-sakura-kms

A server that lets HashiCorp Vault auto-unseal with [SAKURA Cloud KMS](https://cloud.sakura.ad.jp/products/kms/). It answers Vault's transit seal on a Unix socket, encrypting and decrypting with one KMS key.

Run one beside each Vault node.

## Usage

```bash
$ export SAKURA_ACCESS_TOKEN="your-access-token"
$ export SAKURA_ACCESS_TOKEN_SECRET="your-access-token-secret"
$ export SAKURA_KMS_KEY_ID="123456789012"
$ vault-seal-sakura-kms -socket /run/vault-seal/kms.sock
```

| Option | Required | Description |
|---|---|---|
| `-socket <path>` | yes | Unix socket to listen on. Created with mode 0660 |

Credentials are resolved by [sacloud-sdk-go](https://github.com/sacloud/sacloud-sdk-go) from the environment: `SAKURA_ACCESS_TOKEN` and `SAKURA_ACCESS_TOKEN_SECRET`, or service principal credentials.

`SAKURA_KMS_KEY_ID` is the KMS key resource ID it encrypts and decrypts with. Requests for any other key are refused.

Run it as a user in the `vault` group, so that the Vault server can use the socket.

## Vault Configuration

```hcl
seal "transit" {
  address         = "unix:///run/vault-seal/kms.sock"
  mount_path      = "transit/"
  key_name        = "123456789012"
  disable_renewal = "true"
}
```

`key_name` is the KMS key resource ID. It may instead come from `VAULT_TRANSIT_SEAL_KEY_NAME` in the Vault server's environment.

Vault does not start while the socket is unreachable. It starts, and unseals, once vault-seal-sakura-kms is running.

## License

This project is licensed under the [MIT License](./LICENSE).
