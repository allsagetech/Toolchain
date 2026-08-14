<!--
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
-->

# cluster

Creates and manages local Kubernetes development clusters backed by Docker.
This command is intended for development and CI, not production clusters.

## Requirements

- Docker Desktop or another Docker Engine must be running Linux containers.
- The `kind` provider uses the kind executable.
- The `k3s` provider uses k3d to run K3s nodes in Docker.
- The `k0s` provider runs the official k0s container image directly and requires
  privileged containers.

When kind or k3d is absent from `PATH`, Toolchain automatically resolves and
loads the platform-appropriate package from the Toolchains catalog. This uses
the normal pull policy, integrity checks, signatures, and policy controls.
Docker Engine itself remains an external prerequisite; the `docker` Toolchains
package provides a client only and does not install or start an engine.

## Create

Create a one-node kind cluster:

```powershell
toolchain cluster create dev -Provider kind
```

Create kind or K3s clusters with workers and an optional fixed API port:

```powershell
toolchain cluster create kind-dev -Provider kind -Workers 2 -ApiPort 6443
toolchain cluster create k3s-dev -Provider k3s -Servers 1 -Workers 2 -ApiPort 6550
```

Pass a provider-specific kind or k3d configuration file with `-Config`. A
configuration file cannot be combined with `-Servers`, `-Workers`, or
`-ApiPort`. Use `-Image` to pin the kind node or K3s image and `-WaitSeconds` to
change the readiness timeout.

k0s currently supports one combined controller/worker container. Its image must
be supplied explicitly so cluster creation cannot silently move to a different
k0s version:

```powershell
toolchain cluster create k0s-dev -Provider k0s `
  -Image docker.io/k0sproject/k0s:v1.32.4-k0s.0
```

The k0s container runs with `--privileged`. All generated API bindings are
limited to `127.0.0.1`; omit `-ApiPort` to let Docker choose a free host port.

## Inspect and use

```powershell
toolchain cluster list
toolchain cluster list -Provider kind
toolchain cluster status dev
toolchain cluster kubeconfig dev
```

`kubeconfig` returns the managed file path. Toolchain never merges it into
`$HOME/.kube/config` or switches the current context. To use it in the current
PowerShell session:

```powershell
toolchain load kubectl
$env:KUBECONFIG = toolchain cluster kubeconfig dev
kubectl get nodes
```

Use `toolchain cluster kubeconfig dev -Raw` when an automation step needs the
file contents instead of its path.

Cluster state and kubeconfigs are stored beneath the Toolchain data directory in
`clusters/<name>`. Container images are not embedded in Toolchain packages;
Docker uses its local image cache and pulls missing images according to its own
configuration. For repeatable or offline work, pin image versions and preload
those images before creating the cluster.

## Delete

```powershell
toolchain cluster delete dev
```

Deletion removes the provider cluster first, then removes only Toolchain's known
state files. k0s anonymous data volumes created for the cluster are removed with
its container.
