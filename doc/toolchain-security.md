<!--
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
-->

# security

Toolchain supports supply-chain hardening for both online (OCI registry) and offline (air-gapped) workflows.

## Signed manifests (offline)

When you run:

	toolchain save -Sign <pkgs...> <outputDir>

Toolchain writes a detached CMS/PKCS#7 signature for each `manifest.json`:

- `manifest.json`
- `manifest.json.p7s`

Signing uses a certificate from `Cert:\CurrentUser\My` or `Cert:\LocalMachine\My`.

- Choose a specific signer with `TOOLCHAIN_MANIFEST_SIGN_THUMBPRINT`.

Verification can be enforced with policy:

- `requireSignedManifests: true`
- `trustedSigners: ["<thumbprint>"]`

Or with an environment toggle:

- `TOOLCHAIN_REQUIRE_SIGNED_MANIFESTS=1`

## Sigstore / cosign verification (online pulls)

Before blobs are downloaded, Toolchain can run:

	cosign verify <registry>/<repo>@sha256:...

Enable verification:

- `TOOLCHAIN_COSIGN_VERIFY=1` (or `requireCosign: true` in policy)

Optional constraints:

- `TOOLCHAIN_COSIGN_KEY` (public key)
- `TOOLCHAIN_COSIGN_CERT_IDENTITY`
- `TOOLCHAIN_COSIGN_OIDC_ISSUER`

## Air-gapped registry support

Internal registries may use self-signed or private PKI certificates. For controlled environments you can disable TLS validation for Toolchain HTTP calls:

- `TOOLCHAIN_TLS_INSECURE=1`

