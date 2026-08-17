<!-- Toolchain | SPDX-License-Identifier: MPL-2.0 -->
# private-registry authentication

Toolchain resolves registry credentials in this order:

1. `TOOLCHAIN_TOKEN` as an explicit bearer token;
2. `TOOLCHAIN_USERNAME` and `TOOLCHAIN_PASSWORD` together;
3. `TOOLCHAIN_AUTH_FILE` or `REGISTRY_AUTH_FILE`;
4. `$DOCKER_CONFIG/config.json`;
5. `~/.docker/config.json`;
6. `~/.config/containers/auth.json`.

Docker-compatible `auth`, `identitytoken`, per-registry `credHelpers`, and global
`credsStore` entries are supported. Credential helpers use the standard
`docker-credential-<name> get` protocol, have a ten-second deadline, and their
secrets are never written to Toolchain output. This supports Docker Desktop,
Windows Credential Manager, macOS Keychain, `pass`, `secretservice`, and cloud
helpers such as ECR or GCR when those helpers are installed.

Set `TOOLCHAIN_DISABLE_CREDENTIAL_HELPERS=1` to prevent helper execution. Registry
credentials embedded in registry URLs remain rejected. `tlc doctor -PassThru`
reports only the credential source, never a username, token, or password.
