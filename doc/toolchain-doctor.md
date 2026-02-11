<!--
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
-->

# doctor

Prints diagnostics for your Toolchain setup.

`doctor` is intended to help troubleshoot common problems such as:

- Cache path not writable
- Offline repository path missing
- Registry unreachable / authentication issues

## Usage

    toolchain doctor [-Strict]

## Output (example)

```
PS C:\repo> toolchain doctor
ToolchainPath: C:\Users\me\AppData\Local\Toolchain
Registry: https://registry-1.docker.io
Repository: allsagetech/toolchains
Registry reachable; tags count: 123
doctor: ok
```

## Strict mode

If issues are found, `-Strict` will throw an error (useful for CI):

```powershell
toolchain doctor -Strict
```
