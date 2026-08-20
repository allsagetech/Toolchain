<!--
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
-->

# cluster

Creates and manages local Kubernetes development clusters backed by Docker,
Podman, or nerdctl where the selected provider supports that engine.
This command is intended for development and CI, not production clusters.

## Requirements

- A ready Linux container engine is required. `-Engine auto` checks Docker,
  Podman, then nerdctl.
- The `kind` provider uses the kind executable.
- The `k3s` provider uses k3d. Docker is preferred; Podman support is
  experimental and requires its API service plus `DOCKER_HOST`.
- The `k0s` provider runs the official k0s container image directly and requires
  privileged containers.

When kind or k3d is absent from `PATH`, Toolchain automatically resolves and
loads the platform-appropriate package from the Toolchains catalog. This uses
the normal pull policy, integrity checks, signatures, and policy controls.
The engine daemon or Podman machine remains an external prerequisite; Toolchains
packages provide clients but do not silently start privileged host services.

## Create

Create a one-node kind cluster:

```powershell
toolchain cluster create dev -Provider kind
toolchain cluster create podman-dev -Provider kind -Engine podman
```

Create kind or K3s clusters with workers and an optional fixed API port:

```powershell
toolchain cluster create kind-dev -Provider kind -Workers 2 -ApiPort 6443
toolchain cluster create k3s-dev -Provider k3s -Servers 1 -Workers 2 -ApiPort 6550
```

Toolchain-created K3s clusters disable the bundled Traefik ingress controller.
Install an ingress controller explicitly if the cluster needs ingress. Toolchain
also stores the live API port published by Docker or Podman and uses
`127.0.0.1` in the managed kubeconfig so Docker Desktop host aliases cannot
break cluster access. Existing clusters retain their original K3s arguments;
recreate an existing K3s cluster to remove a previously installed Traefik.

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
toolchain cluster use dev
toolchain cluster current
```

`kubeconfig` returns the managed file path. `use` assigns that isolated file to
`KUBECONFIG` for the current PowerShell process and its child processes, so
subsequent Kubernetes commands target the selected cluster:

```powershell
toolchain load kubectl
toolchain cluster use dev
kubectl get nodes
```

When the first and only managed cluster is created, Toolchain selects it
automatically. `current` also selects that sole cluster if `KUBECONFIG` is
unset, including in a new PowerShell session. Switch between managed clusters
by running `use`. `current` prints the selected Toolchain cluster name; add
`-PassThru` to return its name, provider, and kubeconfig path as an object. Both
commands reject missing or tampered managed state. `current` rejects an
external or multi-file `KUBECONFIG` and requires `use` when more than one
managed cluster exists without a selection.

The selection is intentionally session-scoped. Toolchain does not merge or
modify `$HOME/.kube/config`, and a new PowerShell process starts with its normal
environment. Deleting the selected cluster clears `KUBECONFIG` so the session
does not retain a path to a deleted file.

Or launch K9s with the managed kubeconfig without changing the session:

```powershell
tlc k9s -Cluster dev
```

Use `toolchain cluster kubeconfig dev -Raw` when an automation step needs the
file contents instead of its path. Use `toolchain cluster use dev -PassThru`
when automation needs structured details about the new selection.

Cluster state and kubeconfigs are stored beneath the Toolchain data directory in
`clusters/<name>`. Container images are not embedded in Toolchain packages;
Docker uses its local image cache and pulls missing images according to its own
configuration. For repeatable or offline work, pin image versions and preload
those images before creating the cluster.

## Initialize deployment infrastructure

Prepare the current Kubernetes context with Toolchain's native deployment
foundation:

```powershell
tlc cluster init -Confirm
tlc cluster init dev -Confirm
tlc cluster init -Kubeconfig .\external-kubeconfig.yaml -Confirm
```

When `-Components` is omitted, Toolchain asks whether to initialize each
optional component. The Git server prompt is `Initialize optional Git server?
[y/N]`; pressing Enter selects no. Core registry, state, gateway, and admission
agent components are always initialized.

For non-interactive automation, skip the prompt explicitly:

```powershell
tlc cluster init dev -Confirm -Components none
tlc cluster init dev -Confirm -Components git-server
```

Initialization creates the `toolchain-system` namespace, persistent OCI
registry, node-local registry gateway, cluster state, exact-match image-mapping
configuration, and Toolchain admission agent. `-Confirm` is required so
cluster changes are explicitly acknowledged. A managed cluster name and an
explicit `-Kubeconfig` are mutually exclusive; with neither, kubectl's current
context is used. If `tlc cluster use` selected a managed cluster, `init` detects
that selection and treats it as the managed cluster target. When no context is
selected and exactly one managed cluster exists, `init` selects it
automatically. Before applying resources, K3s initialization refreshes the
managed kubeconfig from k3d and checks the Kubernetes `/readyz` endpoint.

For a Toolchain-managed kind, K3s, or k0s cluster, initialization builds the
admission agent from the source bundled with the installed module and imports
the content-addressed local image into that cluster's node runtime. This avoids
a dependency on a separately published admission-agent image. Supply
`-AgentImage` to skip the local build and use an external or preloaded image
instead. An explicit external kubeconfig continues to use the version-matched
published image unless `-AgentImage` is provided.

The registry gateway listens on node port `31999` by default and is recorded as
`127.0.0.1:31999`. Pulls are anonymous so workloads in any namespace can use
mirrored images without copying credentials. Pushes and destructive registry
requests require the generated `toolchain-registry-credentials` Secret. Select
a different free port with `-RegistryNodePort`.

The admission agent rewrites only complete image references listed in the
`toolchain-image-mappings` ConfigMap. It never performs prefix or heuristic
rewrites. The default `-AgentMutationPolicy labeled` requires
`toolchain.dev/agent: mutate` on each Toolchain-managed Pod, so Zarf and other
third-party workloads are not affected. `-AgentMutationPolicy all` is an
explicit legacy override that applies mappings to every non-excluded Pod.
Label a namespace or Pod `toolchain.dev/agent: ignore` to exclude it. The
webhook begins fail-open while establishing its generated TLS trust, then
changes itself to fail-closed.

Add the optional Git service interactively or explicitly:

```powershell
tlc cluster init dev -Confirm -Components git-server
```

Its persistent SQLite data, configuration, and generated administrator
credential survive repeat runs. The username is `toolchain-admin`; retrieve the
password only when needed:

```powershell
$encoded = kubectl get secret toolchain-git-admin -n toolchain-system `
  -o jsonpath='{.data.TOOLCHAIN_GIT_ADMIN_PASSWORD}'
[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded))
```

Repeat initialization to reconcile or upgrade the installation. Toolchain uses
server-side apply and preserves registry credentials, Git credentials, and
image mappings. Registry and Git images are digest-pinned by default; the local
Toolchain agent tag includes the installed module version and a build-context
digest.

Initialization does not invoke an external bootstrap product. On a connected
cluster, Kubernetes pulls missing registry and optional Git images normally.
For disconnected managed clusters, preload those images on every schedulable
node before running init or override their references with `-RegistryImage` and
`-GitImage`; Toolchain imports its locally built agent automatically. For an
arbitrary external cluster runtime, preload all required images or override
their references with `-AgentImage`, `-RegistryImage`, and `-GitImage`.

## Delete

```powershell
toolchain cluster delete dev
```

Deletion removes the provider cluster first, then removes only Toolchain's known
state files. k0s anonymous data volumes created for the cluster are removed with
its container.
