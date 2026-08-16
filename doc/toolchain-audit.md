<!-- Toolchain | SPDX-License-Identifier: MPL-2.0 -->
# audit

`tlc audit` combines the project reproducibility and supply-chain checks that
would otherwise require separate lock, health, verification, and policy
commands. It compares the nearest `Toolchain.ps1` with `Toolchain.lock.json`,
the local package database, the currently resolved registry digests, and the
signed package-health catalog.

```powershell
tlc audit
tlc audit -Refresh -VerifySignatures
tlc audit -Path .\ci\Toolchain.lock.json -Json
tlc audit -VerifySignatures -Strict
```

The report identifies missing or orphaned lock entries, changed references,
installed digest drift, available updates, unhealthy or quarantined packages,
signature failures, and policy violations. Signature verification is automatic
when Cosign is required by policy; `-VerifySignatures` enables it explicitly.

Use `-Strict` in CI. The report is written first and the command then emits a
terminating error when any warning or error finding exists. `-Json` returns the
complete report, including per-package findings and summary counts.
