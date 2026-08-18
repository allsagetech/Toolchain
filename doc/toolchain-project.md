<!-- Toolchain | SPDX-License-Identifier: MPL-2.0 -->
# project manifest

`toolchain.yaml` is Toolchain's declarative, reviewable project format. Toolchain
searches upward from the current directory and prefers YAML over `Toolchain.ps1`
at the same directory level.

```yaml
schemaVersion: 1
packages:
  - name: git
    version: latest
  - name: node
    version: ">=22 <25"
  - name: pnpm
    version: latest
    configuration: default
    dependencies:
      - name: node
        version: "^24"
```

Package entries may also use reference strings such as `git:latest`,
`node@sha256:<digest>`, or `file:///path/to/package`. Quote references containing
YAML control characters.

Supported constraints are exact prefixes (`24`, `24.2`, `24.2.1`), comparators
(`>=24`, `<25`), caret (`^24.2`), tilde (`~24.2`), wildcards (`24.x`), AND groups
separated by spaces or commas, and OR groups separated by `||`. The resolver
selects the highest matching published version.

Dependencies are declared explicitly in the project manifest. Duplicate package
requirements are merged, every constraint must be satisfied, conflicting named
configurations fail, cycles fail, and dependencies are restored before dependents.
Toolchain does not execute package code to discover dependencies.

The same manifest may also describe a Kubernetes deployment package:

```yaml
schemaVersion: 1
packages:
  - helm
  - kubectl
deployment:
  name: demo
  version: 1.0.0
  namespace: demo-system
  charts:
    - path: charts/demo
      release: demo
  manifests:
    - manifests
```

`packages`, `deployment`, and Toolchain-native `metadata`/`components` are
independently optional, but at least one package or deployment form must be
present. Deployment content is consumed by `tlc package create` and
`tlc package deploy`; top-level `variables` configure Toolchain templates for
that deployment. See `doc/toolchain-package.md` for components, variables,
conventional values, configuration, archive integrity, and deployment behavior.

The runtime parser intentionally implements this strict schema without a YAML
module dependency, preserving PowerShell 5.1 and offline operation. The editor
schema is `schema/toolchain-project.schema.json`.

Legacy `Toolchain.ps1` package lists remain supported. A neighboring
`Toolchain.ps1` can also define `Toolchain<Name>` functions for `tlc run`; when a
YAML manifest is present, those commands use its resolved packages.
