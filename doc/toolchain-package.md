<!-- Toolchain | SPDX-License-Identifier: MPL-2.0 -->
# package

Creates and deploys portable Kubernetes application bundles without Zarf.
Bundles can contain local Helm charts, packaged Helm `.tgz` charts, conventional
values and deployment configuration, and additional Kubernetes YAML manifests.

## Package manifest

Add a `deployment` section to `toolchain.yaml`. Developer-tool `packages` may
remain in the same file and continue to work with `tlc sync` and `tlc activate`.

```yaml
schemaVersion: 1
packages:
  - helm
  - kubectl
deployment:
  name: demo
  version: 1.0.0
  description: Demo application
  namespace: demo-system
  charts:
    - path: charts/demo
      release: demo
      values:
        - values/base.yaml
  manifests:
    - manifests
    - resources/extra-configmap.yaml
```

Chart paths must refer to a local directory containing `Chart.yaml` or a
packaged `.tgz` chart. Manifest entries may identify one YAML file or a
directory; directories are included recursively. Paths must remain inside the
package source and cannot traverse links or reparse points.

## Conventional files

When present beside `toolchain.yaml`, these files are included automatically:

- `toolchain-values.yaml` is passed to every Helm release after chart-specific
  values. An external `-Values` file supplied during deployment is applied last.
- `toolchain-config.yaml` controls deployment defaults:

```yaml
schemaVersion: 1
namespace: demo-system
wait: true
waitSeconds: 300
createNamespace: true
```

An external `-Config` file overlays the bundled configuration. Command-line
`-Namespace` and `-WaitSeconds` values take final precedence.

## Create

```powershell
tlc package create .
```

Toolchain validates every chart with `helm lint`, collects declared content,
and writes `dist/toolchain-package-NAME-VERSION.tlcpkg`. Each archive contains
an index covering every file with its path, size, and SHA-256 digest.

Choose another output or replace a previous build explicitly:

```powershell
tlc package create . -Output .\release\demo.tlcpkg
tlc package create . -Force
```

## Deploy

Deploy to a selected Toolchain-managed cluster:

```powershell
tlc package deploy .\dist\toolchain-package-demo-1.0.0.tlcpkg `
  -Cluster dev -Confirm
```

Use the current Kubernetes context or an explicit kubeconfig:

```powershell
tlc package deploy .\dist\toolchain-package-demo-1.0.0.tlcpkg -Confirm
tlc package deploy .\dist\toolchain-package-demo-1.0.0.tlcpkg `
  -Kubeconfig .\kubeconfig.yaml -Confirm
```

Toolchain verifies the archive before contacting Kubernetes, performs an API
readiness check, server-side applies declared manifests, and then runs
`helm upgrade --install` for each chart. Repeated deployments therefore upgrade
existing releases. Use `-DryRun` without `-Confirm` to validate and render
without persisting resources.

Archive hashing detects accidental or malicious modification after creation;
it does not establish publisher identity. Distribute packages through a trusted
channel until signed deployment packages are added.
