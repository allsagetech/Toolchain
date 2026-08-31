<!--
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
-->

# shell

Starts the Toolchain-managed PowerShell 7 package in a new interactive session.

## Usage

```powershell
tlc shell pwsh
```

The command resolves the `powershell` package through the normal Toolchain pull
policy, launches that package's verified `pwsh.exe`, and imports the same
Toolchain module into the new session. It does not modify the system `PATH`,
replace `powershell.exe`, or change Windows Terminal's default profile.

After the new shell opens, enable automatic Toolchain suggestions when the
terminal supports PowerShell 7 predictive IntelliSense:

```powershell
tlc completion enable
```

To make `pwsh` available in every future PowerShell 5.1 session without
changing the system environment, add the package to that host's profile:

```powershell
tlc pull powershell
tlc profile add powershell
```
