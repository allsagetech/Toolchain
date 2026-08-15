<!-- Toolchain | SPDX-License-Identifier: MPL-2.0 -->
# verify

Verifies remote package signatures explicitly with Cosign.

```powershell
tlc verify kubectl
tlc verify kind:0.32.0 -Json
```

For a multi-platform package, Toolchain verifies the signed OCI index and the
selected OS/architecture manifest. Configure a public key or keyless certificate
identity and issuer through the same policy and environment settings used by
automatic pull verification. Cosign must be available on `PATH`.
