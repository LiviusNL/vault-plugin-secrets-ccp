# Vault Secrets Plugin for CyberArk Central Credentials Provider

This repository contains the source code for a Vault plugin used to retrieve secrets from the CyberArk Enterprise Password Vault (EVP) using the CyberArk Central Credentials Provider (CCP).

## Usage

### Register

Vault requires that all plugins are stored in a predefined location and are registered with Vault.
Designate a folder as the Vault plugin folder.

Copy the plugin to the Vault plugin folder, for every node in the Vault cluster.

Configure all Vault nodes in the cluster, to use the desginated plugin folder, as shown below, and (re)start Vault:
```json
...
plugin_directory = "path/to/plugin/directory"
...
```

Generate the sha256 checksum for the plugin. Example using shasum:
```sh
shasum -a 256 bin/vault-plugin-secrets-ccp
...
909715453de17d70cc4944fe2451cf64f3945de9e9db14429503df347e6efcc5  bin/vault-plugin-secrets-ccp
```

Register the plugin
```sh
$ vault write vault write sys/plugins/catalog/ccp \
        sha_256=<expected SHA256 Hex value of the plugin binary> \
        command="vault-plugin-secrets-ccp"
...
Success! Data written to: sys/plugins/catalog/ccpsecrets
```

### Mount

Enable the secrets plugin backend using the `secrets enable` command:
```sh
$ vault secrets enable ccp
...

Success! Enabled the ccp secrets engine at: ccp/
```

### Configure

TBD 
### Retrieve secrets

TBD

## Developing

If you wish to work on the plugin, you need to have [Go](https://www.golang.org) installed on your system.
You can then download any required build tools by bootstrapping your environment:

```sh
$ make bootstrap
```

To compile a development version of this plugin, run `make` or `make dev`.
This will put the plugin binary in the `bin` folders. 
`make dev` will only generate the binary for your platform and is faster:

```sh
$ make
$ make dev
```

Put the plugin binary into a location of your choice. This folder
will be specified as the [`plugin_directory`](https://www.vaultproject.io/docs/configuration/index.html#plugin_directory)
in the Vault config used to start the server.

```json
...
plugin_directory = "path/to/plugin/directory"
...
```

Start a Vault server with this config file:
```sh
$ vault server -config=path/to/config.json ...
...
```

Once the server is started, register the plugin in the Vault server's [plugin catalog](https://www.vaultproject.io/docs/internals/plugins.html#plugin-catalog):

```sh
$ vault write vault write sys/plugins/catalog/ccp \
        sha_256=<expected SHA256 Hex value of the plugin binary> \
        command="vault-plugin-secrets-ccp"
...
Success! Data written to: sys/plugins/catalog/ccpsecrets
```

Note you should generate a new sha256 checksum if you have made changes to the plugin. Example using shasum:

```sh
shasum -a 256 bin/vault-plugin-secrets-ccp
...
909715453de17d70cc4944fe2451cf64f3945de9e9db14429503df347e6efcc5  bin/vault-plugin-secrets-ccp
```

Enable the secrets plugin backend using the secrets enable plugin command:
```sh
$ vault secrets enable ccp
...

Success! Enabled the ccp secrets engine at: ccp/
```
