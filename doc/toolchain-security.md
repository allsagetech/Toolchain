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

Before blobs are downloaded, Toolchain runs:

	cosign verify <registry>/<repo>@sha256:...

The official Docker Hub repository (`allsagetech/toolchains`) is verified by
default against the protected `build-push.yml` GitHub Actions identity and its
OIDC issuer. Cosign must be installed on `PATH`; a missing verifier fails closed.

Private registries remain policy-controlled because their trust identities are
deployment-specific. Enable verification for them with:

- `TOOLCHAIN_COSIGN_VERIFY=1` (or `requireCosign: true` in policy)

An explicit `TOOLCHAIN_COSIGN_VERIFY=0` disables the official default. This is a
trust override and should be limited to controlled diagnostics.

Optional constraints:

- `TOOLCHAIN_COSIGN_KEY` (public key)
- `TOOLCHAIN_COSIGN_CERT_IDENTITY`
- `TOOLCHAIN_COSIGN_OIDC_ISSUER`

See `toolchain-authentication.md` for private-registry credentials and credential
helpers. Authentication selects who may read an artifact; signature verification
independently proves who published its immutable digest.

## Air-gapped registry support

Internal registries may use self-signed or private PKI certificates. For controlled environments you can disable TLS validation for Toolchain HTTP calls:

- `TOOLCHAIN_TLS_INSECURE=1`

## Native cluster initialization

`tlc cluster init -Confirm` uses digest-pinned third-party component images and
a release-matched, signed Toolchain agent image. Its backing registry has only a
ClusterIP and accepts traffic from the Toolchain registry gateway. The gateway
allows anonymous reads needed by Kubernetes nodes but requires a generated,
random credential for every write or destructive request. That credential is
stored only in the `toolchain-registry-credentials` Kubernetes Secret and is
preserved during reconciliation.

The admission webhook starts with `failurePolicy: Ignore` and an empty CA bundle
to avoid blocking the cluster before TLS is ready. The agent patches its exact CA
bundle through resource-scoped RBAC and switches to `failurePolicy: Fail` before
becoming ready. Mutations are limited to exact source-to-target entries in the
`toolchain-image-mappings` ConfigMap; arbitrary registry prefixes are not
rewritten.

The default node-local registry endpoint uses plain HTTP on loopback because
container runtimes conventionally treat loopback registries as local. Do not
publish node port `31999` through an external load balancer or firewall. Registry
content should be treated as readable by principals with node-network access;
secrets must not be stored in image layers.

