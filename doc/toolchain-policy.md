<!--
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
-->

# policy

Toolchain can enforce an allow/deny policy for packages, versions, registries, and signature requirements.

Policy is applied:

- Before any registry request made while pulling, saving, or listing packages
- When loading packages into a session (so disallowed tools can't be used even if already installed)

When `requireSignedManifests` is enabled for an offline repository, at least one
`trustedSigners` certificate thumbprint is required. A cryptographically valid
signature without an explicit trust allowlist is rejected.

## Policy file discovery

Toolchain loads the first policy it finds:

1. `$ToolchainPolicyPath`
2. `$env:ToolchainPolicyPath`
3. `$env:TOOLCHAIN_POLICY_PATH`
4. `Toolchain.policy.json` next to the nearest YAML or legacy PowerShell project config (or current directory)

## Example policy

```json
{
  "version": 1,
  "defaultAction": "deny",
  "allowedRegistries": ["registry-1.docker.io"],
  "allowedRepositories": ["allsagetech/toolchains"],
  "packages": {
    "git": { "allow": [">=2.45.0 <3.0.0"] },
    "node": { "allow": ["20.*", "22.*"] },
    "python": { "deny": ["*"] }
  },
  "requireCosign": false,
  "cosign": { "key": "C:/keys/cosign.pub" },
  "requireSignedManifests": true,
  "trustedSigners": ["<CERT_THUMBPRINT>"]
}
```

## Supported constraints

Constraints may be used in `packages.<name>.allow` and `packages.<name>.deny`:

- Wildcards: `2.*`, `2.45.*`
- Exact versions: `2.45.1`
- Comparators: `>=2.45.0 <3.0.0` (space-separated AND)
- Digest pinning: `sha256:<64-hex>`
- `latest`

Registry allowlist entries are origins, not host globs. A bare host such as
`registry.example.com` means `https://registry.example.com:443`. Scheme, host,
and effective port must all match; `http://registry.example.com` and
`https://registry.example.com:444` are different origins. Credentials, paths,
queries, and fragments are rejected in registry origins.
