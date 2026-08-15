<!--
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
-->

# k9s

Launches the K9s terminal UI for the current Kubernetes context, a
Toolchain-managed cluster, or an explicit kubeconfig file.

## Usage

```powershell
tlc k9s [-Cluster NAME | -Kubeconfig PATH] [K9S_ARGUMENT ...]
```

With no Toolchain options, K9s uses its normal kubeconfig and current-context
resolution:

```powershell
tlc k9s
```

Use a cluster created by `tlc cluster create` without changing the default
kubeconfig:

```powershell
tlc k9s -Cluster dev
```

Or select any kubeconfig file:

```powershell
tlc k9s -Kubeconfig .\kubeconfig.yaml
```

Every argument not consumed as a Toolchain option is passed to K9s:

```powershell
tlc k9s -Cluster dev --readonly -A
tlc k9s --context production -n monitoring
```

`-Cluster` and `-Kubeconfig` are mutually exclusive. Toolchain never merges a
selected kubeconfig into the user's default file and does not switch the
current context.

If `k9s` is not already on `PATH`, Toolchain resolves and loads `k9s` on
Windows or `k9s-linux` on Linux from the configured Toolchains catalog. In an
air-gapped environment, include the matching package in the offline repository
before launching the command:

```powershell
tlc save -Output .\toolchain-cache k9s
```
