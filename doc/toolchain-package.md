<!-- Toolchain | SPDX-License-Identifier: MPL-2.0 -->
# package

Creates and deploys portable Toolchain Kubernetes application bundles.
Bundles can contain container images, local or remote Helm charts, packaged
Helm `.tgz` charts, conventional values and deployment configuration, and
additional Kubernetes YAML manifests.

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

Local chart paths must refer to a directory containing `Chart.yaml` or a
packaged `.tgz` chart; remote chart entries may use `url` as described below.
Manifest entries may identify one YAML file or a directory; directories are
included recursively. Paths must remain inside the package source and cannot
traverse links or reparse points.

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
container images, local and remote Helm charts, local manifest files/directories,
chart value files, package value files, documentation files, variables,
namespaces, wait behavior, schema-validation control, and component lifecycle
actions. Toolchain rejects remote manifests, image archives, repository
bundling, file placement, imports, kustomizations, and health checks with an
explicit error. These fields are never silently ignored.

## Component actions

An action-only component can serve as a deployment gate. `onCreate` runs while
building the package, and `onDeploy` runs for each selected component during a
confirmed deployment:

```yaml
components:
  - name: gate
    required: true
    actions:
      onDeploy:
        defaults:
          maxTotalSeconds: 60
          maxRetries: 2
        before:
          - cmd: |
              kubectl get namespace prerequisite
            description: Verify the prerequisite namespace
          - wait:
              cluster:
                kind: Deployment
                name: prerequisite
                namespace: toolchain-system
                condition: Available
        onSuccess:
          - cmd: echo deployment gate passed
```

Each lifecycle supports `before`, `after`, `onSuccess`, and `onFailure` lists.
Command actions support `mute`, `maxTotalSeconds`, `maxRetries`, `dir`, `env`,
and an operating-system-specific `shell`. Working directories must remain
inside the package. Toolchain supplies package, component, variable, and
Kubernetes context environment variables to the command. Network waits support
TCP, HTTP, and HTTPS endpoints; cluster waits support resource existence or a
Kubernetes wait condition.

An `onDeploy` command can capture standard output for later manifests, charts,
or values files:

```yaml
before:
  - cmd: echo generated-name
    mute: true
    setVariables:
      - name: GENERATED_NAME
        pattern: '^[a-z0-9-]+$'
```

Reference that output as `###TOOLCHAIN_VAR_GENERATED_NAME###`. Output variables
also support `sensitive`, `autoIndent`, and `type: file`. Deployment actions run
only after `-Confirm`; `-DryRun` validates them but does not execute them.
`onRemove` definitions execute during `tlc package remove`, which runs the
selected components' removal actions around manifest and Helm cleanup.

Actions execute local commands with the current user's permissions. Only create
or deploy package source you trust; archive integrity verification detects
changes but does not establish publisher identity.

## Remote Helm charts

Remote charts are downloaded only during `package create`, converted to a
packaged `.tgz`, and included in the package integrity index. Deploying the
resulting `.tlcpkg` uses the bundled chart and does not contact its original
source.

Use `url` with an exact `version` and chart `name`. For an HTTP(S) Helm
repository, `repoName` optionally identifies a chart whose repository name
differs from its Toolchain name:

```yaml
charts:
  - name: podinfo-release
    version: 6.4.0
    url: https://stefanprodan.github.io/podinfo
    repoName: podinfo
    releaseName: podinfo
```

OCI and Git sources are also supported:

```yaml
charts:
  - name: podinfo-oci
    version: 6.4.0
    url: oci://ghcr.io/stefanprodan/charts/podinfo
  - name: podinfo-git
    version: 6.4.0
    url: https://github.com/stefanprodan/podinfo.git
    gitPath: charts/podinfo
```

For Git sources, `version` is the tag or branch unless the repository URL ends
with an explicit `.git@REF`. Direct HTTP(S) `.tgz` URLs are accepted as well.
Helm and Git use their normal configured credential stores for private sources.

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

The cluster admission policy defaults to `labeled`. Toolchain-managed Pod
templates must opt in with `toolchain.dev/agent: mutate` when they need these
image mappings; unlabeled Zarf and other third-party workloads are left alone.
Initialize with `-AgentMutationPolicy all` only for legacy clusters that
intentionally need global image rewriting.

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

Toolchain also accepts command-scoped package configuration without requiring a
`schemaVersion`:

```yaml
package:
  create:
    skip_sbom: true
    set:
      package_name: demo
  deploy:
    retries: 3
    timeout: 15m
    components: 'application,observability*'
    set:
      app_name: staging
    values:
      - values/staging.yaml
```

Top-level `log_level` accepts `warn`, `info`, `debug`, or `trace`.
`log_format` accepts `console`, `json`, or `dev`. These settings apply for the
duration of package creation or deployment and are restored afterward.

`package.create.set` values replace native
`###TOOLCHAIN_PKG_TMPL_NAME###` tokens in `toolchain.yaml` before package
validation. Values can also come from matching `TOOLCHAIN_PKG_TMPL_NAME`
environment variables. Interactive creation prompts once for every remaining
template value; `-Confirm` instead reports all unset names together.
`package.create.skip_sbom` accepts a Boolean for compatibility with
v0.76-style package configuration; Toolchain package creation currently behaves
as though this setting is `true`. `package.deploy.set` names are case-insensitive and resolve declared
uppercase package variables. Configured components and values act as defaults;
explicit `-Components`, `-Values`, and `-Set` options take precedence. Relative
deploy values resolve beside the config file and values from the bundled config
are integrity-indexed into the package. `package.deploy.retries` accepts 0 through
10 retries for Kubernetes, image-publication, and Helm operations. `timeout`
accepts seconds or durations such as `30s`, `15m`, and `1h30m`, and controls Helm
wait operations.

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

## Remove

Remove the selected package components from a cluster. Toolchain deletes
declared manifests and uninstalls Helm releases in reverse component order,
then runs the declared `onRemove` lifecycle actions:

```powershell
tlc package remove .\dist\toolchain-package-demo-1.0.0.tlcpkg `
  -Cluster dev -Confirm
```

Use `-Components` to select optional components, `-Set` to provide variables
used by manifest templates or removal actions, and `-DryRun` to validate the
Kubernetes and Helm operations without changing the cluster:

```powershell
tlc package remove .\dist\toolchain-package-demo-1.0.0.tlcpkg `
  -Components 'application,observability*,-example-data' -DryRun
```
