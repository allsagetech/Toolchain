<!-- Toolchain | SPDX-License-Identifier: MPL-2.0 -->
# package

Creates and deploys portable Toolchain Kubernetes application bundles.
Bundles can contain container images, local Helm charts, packaged Helm `.tgz`
charts, conventional values and deployment configuration, and additional
Kubernetes YAML manifests.

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

## Toolchain component packages

Toolchain accepts its native component package shape directly in
`toolchain.yaml`:

```yaml
apiVersion: toolchain.allsagetech.com/v1alpha1
kind: ToolchainPackageConfig
metadata:
  name: demo
  version: 1.0.0
components:
  - name: core
    required: true
    manifests:
      - name: demo-prerequisites
        namespace: demo-system
        files:
          - manifests
  - name: application
    description: Install the application chart
    default: true
    images:
      - ghcr.io/example/demo:1.0.0
    charts:
      - name: demo
        localPath: charts/demo
        releaseName: demo
        namespace: demo-system
        valuesFiles:
          - values/base.yaml
        noWait: false
```

Required and default components are selected automatically. Select additional
components, use wildcards, or deselect a default with a leading `-`:

```powershell
tlc package deploy .\dist\toolchain-package-demo-1.0.0.tlcpkg `
  -Components 'application,observability*,-example-data' -Confirm
```

Component packages currently support package metadata, component selection,
container images, local Helm charts, local manifest files/directories, chart
value files, package value files, documentation files, variables, namespaces,
wait behavior, and schema-validation control. Toolchain rejects remote
charts/manifests, image archives, repository bundling, file placement, actions,
imports, kustomizations, and health checks with an explicit error. These fields
are never silently ignored.

## Container images

Declare every workload image exactly as it appears in a Pod template under its
component's `images` list. During `package create`, Toolchain uses a ready Linux
Docker, Podman, or nerdctl engine to pull each unique image and converts it into
integrity-indexed registry blobs inside the `.tlcpkg`. `tar` must also be on
`PATH`. Package creation is the connected step; deployment of the resulting
archive does not need the original image registry. Set `metadata.architecture`
to `amd64` or `arm64` when the package must pull a specific Linux platform;
otherwise the active engine's platform is used.

Before applying package resources, `package deploy` publishes selected images
through the registry installed by `tlc cluster init`. It stores digest-pinned
targets in the cluster's exact-match image map, preserves mappings from earlier
packages, and restarts the admission agent so new Pods use the bundled copies.
The image spelling in `images` must therefore match the spelling used by the
chart or manifest. A source-directory deployment performs the pull and
conversion at deployment time. `-DryRun` reports planned images without pulling
or publishing them.

## Package variables

Declare deployment-time values with top-level `variables`. Names use uppercase
letters, digits, and underscores:

```yaml
variables:
  - name: APP_NAME
    description: Kubernetes application name
    default: demo
    pattern: '^[a-z][a-z0-9-]+$'
  - name: EXTRA_LABELS
    autoIndent: true
  - name: TLS_CERTIFICATE
    type: file
    sensitive: true
```

Reference a variable in Kubernetes manifests, Helm chart text files, or Helm
values files with a Toolchain template:

```yaml
metadata:
  name: ###TOOLCHAIN_VAR_APP_NAME###
```

Provide values during deployment with `-Set`:

```powershell
tlc package deploy .\demo.tlcpkg `
  -Set 'APP_NAME=production,EXTRA_LABELS=tier: frontend' -Confirm
```

Values resolve in this order: declared default, `TOOLCHAIN_VAR_NAME`
environment variable, `toolchain-config.yaml`, then `-Set`. A variable with
`prompt: true` prompts only when no environment, config, or command-line value
was supplied. `sensitive: true` hides prompted input and variable values are
never returned by `-PassThru`. `type: file` reads at most 1 MiB from the given
path; a default file is integrity-indexed into the package.

Map a variable directly to a dot-separated Helm values path:

```yaml
charts:
  - name: demo
    localPath: charts/demo
    variables:
      - name: APP_NAME
        path: application.name
```

Toolchain renders into a restricted temporary directory and removes rendered
manifests, charts, and values files after deployment, including on failure.

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
variables:
  APP_NAME: staging
```

An external `-Config` file overlays the bundled configuration. Command-line
`-Namespace`, `-WaitSeconds`, and `-Set` values take final precedence.

## Create

```powershell
tlc package create .
```

Toolchain validates every chart with `helm lint`, pulls declared images,
collects declared content, and writes
`dist/toolchain-package-NAME-VERSION.tlcpkg`. Each archive contains an index
covering every file and image blob with its path, size, and SHA-256 digest.

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
readiness check, publishes all selected component images, and deploys selected
components in declaration order. Within each component it server-side applies
declared manifests and then runs `helm upgrade --install` for each chart.
Repeated deployments therefore upgrade existing releases. Use `-DryRun`
without `-Confirm` to validate and render without persisting resources.

Archive hashing detects accidental or malicious modification after creation;
it does not establish publisher identity. Distribute packages through a trusted
channel until signed deployment packages are added.
