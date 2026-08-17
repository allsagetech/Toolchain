<!-- Toolchain | SPDX-License-Identifier: MPL-2.0 -->
# activate and deactivate

`tlc activate` synchronizes the current project, loads its exact locked package
digests, and records only the environment values changed by Toolchain.

```powershell
tlc activate
# use project tools
tlc deactivate
```

`deactivate` restores the original PATH and every other changed variable. A
second activation of the same project is idempotent; activating another project
requires deactivation first. Activation state belongs to the current PowerShell
process and is intentionally not shared with other terminals.

Use `-NoSync` only when package content has already been prepared and resolving
the manifest directly is intended. `-PassThru` returns activation metadata.
