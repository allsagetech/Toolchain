<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

BeforeAll {
	. (Join-Path $PSScriptRoot 'config.ps1')
	. (Join-Path $PSScriptRoot 'project.ps1')
	function Write-ToolchainInfo { param([string]$Message) }
	function Get-ToolchainClusterExecutable { param($Name,$Package,$InstallHint) "$Name.exe" }
	function Invoke-ToolchainClusterProcess { param($FilePath,$Arguments,[switch]$AllowFailure) [pscustomobject]@{ ExitCode = 0; Output = @() } }
	function Resolve-ToolchainBootstrapKubeconfig { param($Name,$Kubeconfig) $Kubeconfig }
	function Resolve-ToolchainCurrentClusterContext { param([switch]$SelectSingle) }
	function Get-ToolchainBootstrapApiServer { param($Kubeconfig) 'https://127.0.0.1:6443' }
	function Invoke-ToolchainBootstrapKubectl { param($Kubectl,$Kubeconfig,$Arguments,[switch]$AllowFailure) [pscustomobject]@{ ExitCode = 0; Output = @('ok') } }
	. $PSCommandPath.Replace('.Tests.ps1', '.ps1')

	function New-TestDeploymentSource {
		param([Parameter(Mandatory)][string]$Root)
		[void][IO.Directory]::CreateDirectory((Join-Path $Root 'chart/templates'))
		[void][IO.Directory]::CreateDirectory((Join-Path $Root 'manifests'))
		[IO.File]::WriteAllText((Join-Path $Root 'toolchain.yaml'), @'
schemaVersion: 1
packages:
  - helm
deployment:
  name: demo
  version: 1.2.3
  description: Demo application
  namespace: demo-system
  charts:
    - path: chart
      release: demo
      values:
        - chart-values.yaml
  manifests:
    - manifests
'@)
		[IO.File]::WriteAllText((Join-Path $Root 'toolchain-values.yaml'), "replicas: 2`n")
		[IO.File]::WriteAllText((Join-Path $Root 'toolchain-config.yaml'), "schemaVersion: 1`nnamespace: demo-runtime`nwait: true`nwaitSeconds: 42`ncreateNamespace: true`n")
		[IO.File]::WriteAllText((Join-Path $Root 'chart-values.yaml'), "imageTag: stable`n")
		[IO.File]::WriteAllText((Join-Path $Root 'chart/Chart.yaml'), "apiVersion: v2`nname: demo`nversion: 1.2.3`n")
		[IO.File]::WriteAllText((Join-Path $Root 'chart/templates/configmap.yaml'), "apiVersion: v1`nkind: ConfigMap`nmetadata:`n  name: demo`n")
		[IO.File]::WriteAllText((Join-Path $Root 'manifests/namespace.yaml'), "apiVersion: v1`nkind: Namespace`nmetadata:`n  name: demo-runtime`n")
	}

	function New-TestToolchainComponentSource {
		param([Parameter(Mandatory)][string]$Root)
		[void][IO.Directory]::CreateDirectory((Join-Path $Root 'chart/templates'))
		[void][IO.Directory]::CreateDirectory((Join-Path $Root 'manifests'))
		[IO.File]::WriteAllText((Join-Path $Root 'toolchain.yaml'), @'
apiVersion: toolchain.allsagetech.com/v1alpha1
kind: ToolchainPackageConfig
metadata:
  name: component-demo
  description: Toolchain component package
  version: 2.0.0
components:
  - name: prerequisites
    required: true
    manifests:
      - name: prerequisite-resources
        namespace: component-system
        files:
          - manifests
  - name: application
    description: Main application
    default: true
    charts:
      - name: application
        localPath: chart
        releaseName: component-app
        namespace: component-system
        valuesFiles:
          - chart-values.yaml
        noWait: true
        schemaValidation: false
  - name: optional-addon
    charts:
      - name: addon
        localPath: chart
        releaseName: component-addon
        namespace: addon-system
values:
  files:
    - package-values.yaml
documentation:
  readme: package-readme.md
'@)
		[IO.File]::WriteAllText((Join-Path $Root 'chart-values.yaml'), "imageTag: stable`n")
		[IO.File]::WriteAllText((Join-Path $Root 'package-values.yaml'), "replicas: 2`n")
		[IO.File]::WriteAllText((Join-Path $Root 'package-readme.md'), "# component demo`n")
		[IO.File]::WriteAllText((Join-Path $Root 'chart/Chart.yaml'), "apiVersion: v2`nname: component-demo`nversion: 2.0.0`n")
		[IO.File]::WriteAllText((Join-Path $Root 'chart/templates/configmap.yaml'), "apiVersion: v1`nkind: ConfigMap`nmetadata:`n  name: component-demo`n")
		[IO.File]::WriteAllText((Join-Path $Root 'manifests/configmap.yaml'), "apiVersion: v1`nkind: ConfigMap`nmetadata:`n  name: prerequisite`n")
	}

	function New-TestVariableDeploymentSource {
		param([Parameter(Mandatory)][string]$Root)
		[void][IO.Directory]::CreateDirectory((Join-Path $Root 'chart/templates'))
		[void][IO.Directory]::CreateDirectory((Join-Path $Root 'manifests'))
		[IO.File]::WriteAllText((Join-Path $Root 'toolchain.yaml'), @'
apiVersion: toolchain.allsagetech.com/v1alpha1
kind: ToolchainPackageConfig
metadata:
  name: variable-demo
  version: 1.0.0
variables:
  - name: APP_NAME
    description: Application name
    default: default-app
    pattern: '^[a-z][a-z0-9-]+$'
  - name: EXTRA_LABELS
    default: tier-default
    autoIndent: true
  - name: FILE_CONTENT
    default: variable.txt
    type: file
    sensitive: true
components:
  - name: application
    required: true
    manifests:
      - name: application
        files:
          - manifests
    charts:
      - name: application
        localPath: chart
        releaseName: variable-demo
        valuesFiles:
          - chart-values.yaml
        variables:
          - name: APP_NAME
            path: application.name
'@)
		[IO.File]::WriteAllText((Join-Path $Root 'toolchain-config.yaml'), "schemaVersion: 1`nvariables:`n  APP_NAME: configured-app`n")
		[IO.File]::WriteAllText((Join-Path $Root 'variable.txt'), "secret-file-content`n")
		[IO.File]::WriteAllText((Join-Path $Root 'chart-values.yaml'), "displayName: ###TOOLCHAIN_VAR_APP_NAME###`n")
		[IO.File]::WriteAllText((Join-Path $Root 'chart/Chart.yaml'), "apiVersion: v2`nname: variable-demo`nversion: 1.0.0`n")
		[IO.File]::WriteAllText((Join-Path $Root 'chart/templates/configmap.yaml'), "apiVersion: v1`nkind: ConfigMap`nmetadata:`n  name: ###TOOLCHAIN_VAR_APP_NAME###-chart`n")
		[IO.File]::WriteAllText((Join-Path $Root 'manifests/configmap.yaml'), "apiVersion: v1`nkind: ConfigMap`nmetadata:`n  name: ###TOOLCHAIN_VAR_APP_NAME###`ndata:`n  labels: |`n    ###TOOLCHAIN_VAR_EXTRA_LABELS###`n  file: |`n    ###TOOLCHAIN_VAR_FILE_CONTENT###`n")
	}
}

Describe 'Toolchain deployment package creation' {
	BeforeEach {
		$script:packageProcessCalls = [Collections.Generic.List[object]]::new()
		Mock Get-ToolchainClusterExecutable { "$Name.exe" }
		Mock Invoke-ToolchainClusterProcess {
			$script:packageProcessCalls.Add([pscustomobject]@{ FilePath = $FilePath; Arguments = [string[]]$Arguments })
			[pscustomobject]@{ ExitCode = 0; Output = @() }
		}
	}

	It 'creates a verified bundle with Helm, values, config, and additional YAML files' {
		$source = Join-Path $TestDrive 'source'
		New-TestDeploymentSource -Root $source
		$output = Join-Path $TestDrive 'demo.tlcpkg'

		$result = New-ToolchainDeploymentPackage -Path $source -Output $output

		$result.Name | Should -BeExactly 'demo'
		$result.Version | Should -BeExactly '1.2.3'
		$result.Digest | Should -Match '^sha256:[0-9a-f]{64}$'
		Test-Path -LiteralPath $output -PathType Leaf | Should -BeTrue
		Should -Invoke Invoke-ToolchainClusterProcess -Times 1 -Exactly -ParameterFilter {
			$FilePath -eq 'helm.exe' -and $Arguments[0] -eq 'lint' -and $Arguments -contains (Join-Path $source 'toolchain-values.yaml')
		}

		$expanded = Expand-ToolchainDeploymentPackage -Path $output
		try {
			Test-Path -LiteralPath (Join-Path $expanded.Root 'chart/Chart.yaml') -PathType Leaf | Should -BeTrue
			Test-Path -LiteralPath (Join-Path $expanded.Root 'toolchain-values.yaml') -PathType Leaf | Should -BeTrue
			Test-Path -LiteralPath (Join-Path $expanded.Root 'toolchain-config.yaml') -PathType Leaf | Should -BeTrue
			Test-Path -LiteralPath (Join-Path $expanded.Root 'manifests/namespace.yaml') -PathType Leaf | Should -BeTrue
			$expanded.Index.name | Should -BeExactly 'demo'
		} finally {
			Remove-ToolchainDeploymentTemporaryRoot -Path $expanded.Root
		}
	}

	It 'resolves dot against the current PowerShell filesystem location' {
		$source = Join-Path $TestDrive 'dot-source'
		New-TestDeploymentSource -Root $source
		$output = Join-Path $TestDrive 'dot-source.tlcpkg'
		$originalLocation = Get-Location
		$originalProcessDirectory = [Environment]::CurrentDirectory
		try {
			[Environment]::CurrentDirectory = $TestDrive
			Set-Location -LiteralPath $source

			$result = Invoke-ToolchainDeploymentPackage -Command create -Path '.' -Output $output

			$result.Path | Should -BeExactly $output
			Test-Path -LiteralPath $output -PathType Leaf | Should -BeTrue
			$script:packageProcessCalls[0].Arguments | Should -Contain (Join-Path $source 'chart')
		} finally {
			Set-Location -LiteralPath $originalLocation.Path
			[Environment]::CurrentDirectory = $originalProcessDirectory
		}
	}

	It 'creates a package from Toolchain-native metadata and components' {
		$source = Join-Path $TestDrive 'toolchain-components'
		New-TestToolchainComponentSource -Root $source
		$output = Join-Path $TestDrive 'toolchain-components.tlcpkg'

		$result = New-ToolchainDeploymentPackage -Path $source -Output $output

		$result.Name | Should -BeExactly 'component-demo'
		$result.Components | Should -Be @('prerequisites', 'application', 'optional-addon')
		$result.Charts | Should -Be 2
		$script:packageProcessCalls.Count | Should -Be 2
		$script:packageProcessCalls[0].Arguments | Should -Contain (Join-Path $source 'package-values.yaml')
		$script:packageProcessCalls[0].Arguments | Should -Contain '--skip-schema-validation'
		$expanded = Expand-ToolchainDeploymentPackage -Path $output
		try {
			Test-Path -LiteralPath (Join-Path $expanded.Root 'package-readme.md') -PathType Leaf | Should -BeTrue
			$expanded.Index.components | Should -Be @('prerequisites', 'application', 'optional-addon')
		} finally { Remove-ToolchainDeploymentTemporaryRoot -Path $expanded.Root }
	}

	It 'creates an integrity-indexed package with native variable declarations and default files' {
		$source = Join-Path $TestDrive 'variable-package'
		New-TestVariableDeploymentSource -Root $source
		$output = Join-Path $TestDrive 'variable-package.tlcpkg'

		$result = New-ToolchainDeploymentPackage -Path $source -Output $output

		$result.Variables | Should -Be @('APP_NAME', 'EXTRA_LABELS', 'FILE_CONTENT')
		$expanded = Expand-ToolchainDeploymentPackage -Path $output
		try {
			$expanded.Index.variables | Should -Be @('APP_NAME', 'EXTRA_LABELS', 'FILE_CONTENT')
			Test-Path -LiteralPath (Join-Path $expanded.Root 'variable.txt') -PathType Leaf | Should -BeTrue
		} finally { Remove-ToolchainDeploymentTemporaryRoot -Path $expanded.Root }
	}

	It 'rejects unsupported Toolchain component assets explicitly' {
		$source = Join-Path $TestDrive 'toolchain-images'
		New-TestToolchainComponentSource -Root $source
		$manifestPath = Join-Path $source 'toolchain.yaml'
		$content = (Get-Content -LiteralPath $manifestPath -Raw).Replace('    required: true', "    required: true`n    images:`n      - example.invalid/app:1")
		[IO.File]::WriteAllText($manifestPath, $content)

		{ New-ToolchainDeploymentPackage -Path $source -Output (Join-Path $TestDrive 'toolchain-images.tlcpkg') } | Should -Throw "*uses 'images'*"
	}

	It 'rejects manifest paths that escape the package root' {
		$source = Join-Path $TestDrive 'unsafe'
		New-TestDeploymentSource -Root $source
		$content = Get-Content -LiteralPath (Join-Path $source 'toolchain.yaml') -Raw
		$content = $content.Replace('    - manifests', '    - ../outside.yaml')
		[IO.File]::WriteAllText((Join-Path $source 'toolchain.yaml'), $content)
		[IO.File]::WriteAllText((Join-Path $TestDrive 'outside.yaml'), 'kind: ConfigMap')

		{ New-ToolchainDeploymentPackage -Path $source -Output (Join-Path $TestDrive 'unsafe.tlcpkg') } | Should -Throw '*unsafe relative path*'
	}

	It 'detects archive content changed after package creation' {
		$source = Join-Path $TestDrive 'tampered-source'
		New-TestDeploymentSource -Root $source
		$output = Join-Path $TestDrive 'tampered.tlcpkg'
		$null = New-ToolchainDeploymentPackage -Path $source -Output $output
		Initialize-ToolchainCompression
		$stream = [IO.File]::Open($output, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
		$archive = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Update, $false)
		try {
			$entry = $archive.GetEntry('manifests/namespace.yaml')
			$entry.Delete()
			Add-ToolchainZipText -Archive $archive -EntryName 'manifests/namespace.yaml' -Text 'tampered'
		} finally { $archive.Dispose(); $stream.Dispose() }

		{ Expand-ToolchainDeploymentPackage -Path $output } | Should -Throw '*verification failed*'
	}
}

Describe 'Toolchain deployment package deployment' {
	BeforeEach {
		$script:kubectlCalls = [Collections.Generic.List[object]]::new()
		$script:helmCalls = [Collections.Generic.List[object]]::new()
		$script:appliedManifestContents = [Collections.Generic.List[string]]::new()
		$script:helmValueContents = [Collections.Generic.List[string]]::new()
		$script:renderedChartContents = [Collections.Generic.List[string]]::new()
		$script:renderedPaths = [Collections.Generic.List[string]]::new()
		Mock Resolve-ToolchainDeploymentKubeconfig { 'managed-kubeconfig.yaml' }
		Mock Get-ToolchainClusterExecutable { "$Name.exe" }
		Mock Invoke-ToolchainBootstrapKubectl {
			$script:kubectlCalls.Add([pscustomobject]@{ Kubectl = $Kubectl; Kubeconfig = $Kubeconfig; Arguments = [string[]]$Arguments })
			if ($Arguments -contains '-f') {
				$path = [string]$Arguments[[array]::IndexOf([object[]]$Arguments, '-f') + 1]
				$script:appliedManifestContents.Add((Get-Content -LiteralPath $path -Raw))
				$script:renderedPaths.Add($path)
			}
			[pscustomobject]@{ ExitCode = 0; Output = @('ok') }
		}
		Mock Invoke-ToolchainClusterProcess {
			$script:helmCalls.Add([pscustomobject]@{ FilePath = $FilePath; Arguments = [string[]]$Arguments })
			if ($Arguments.Count -gt 3 -and (Test-Path -LiteralPath $Arguments[3] -PathType Container)) {
				$templatePath = Join-Path $Arguments[3] 'templates/configmap.yaml'
				if (Test-Path -LiteralPath $templatePath -PathType Leaf) { $script:renderedChartContents.Add((Get-Content -LiteralPath $templatePath -Raw)); $script:renderedPaths.Add([string]$Arguments[3]) }
			}
			for ($argumentIndex = 0; $argumentIndex -lt ($Arguments.Count - 1); $argumentIndex++) {
				if ($Arguments[$argumentIndex] -eq '--values' -and (Test-Path -LiteralPath $Arguments[$argumentIndex + 1] -PathType Leaf)) {
					$script:helmValueContents.Add((Get-Content -LiteralPath $Arguments[$argumentIndex + 1] -Raw))
					$script:renderedPaths.Add([string]$Arguments[$argumentIndex + 1])
				}
			}
			[pscustomobject]@{ ExitCode = 0; Output = @() }
		}
	}

	It 'applies declared YAML before upgrading Helm releases with layered values' {
		$source = Join-Path $TestDrive 'deploy-source'
		New-TestDeploymentSource -Root $source
		$override = Join-Path $TestDrive 'override.yaml'
		[IO.File]::WriteAllText($override, "replicas: 4`n")

		$result = Invoke-ToolchainDeploymentPackage -Command deploy -Path $source -Cluster dev -Values $override -Confirm -PassThru

		$result.Name | Should -BeExactly 'demo'
		$result.Namespace | Should -BeExactly 'demo-runtime'
		$result.Releases[0].Name | Should -BeExactly 'demo'
		$script:kubectlCalls.Count | Should -Be 2
		($script:kubectlCalls[0].Arguments -join ' ') | Should -Match 'raw=/readyz'
		($script:kubectlCalls[1].Arguments -join ' ') | Should -Match '^apply .* -f '
		$helm = $script:helmCalls[0]
		($helm.Arguments -join ' ') | Should -Match '^upgrade --install demo '
		$helm.Arguments | Should -Contain 'demo-runtime'
		$helm.Arguments | Should -Contain (Join-Path $source 'chart-values.yaml')
		$helm.Arguments | Should -Contain (Join-Path $source 'toolchain-values.yaml')
		$helm.Arguments | Should -Contain $override
		$helm.Arguments | Should -Contain '42s'
		$helm.Arguments | Should -Contain 'managed-kubeconfig.yaml'
	}

	It 'requires confirmation for mutations but permits an unconfirmed dry run' {
		$source = Join-Path $TestDrive 'confirm-source'
		New-TestDeploymentSource -Root $source

		{ Invoke-ToolchainDeploymentPackage -Command deploy -Path $source } | Should -Throw '*-Confirm*'
		{ Invoke-ToolchainDeploymentPackage -Command deploy -Path $source -DryRun } | Should -Not -Throw
		$script:kubectlCalls[1].Arguments | Should -Contain '--dry-run=server'
		$script:helmCalls[0].Arguments | Should -Contain '--dry-run'
	}

	It 'deploys required and explicitly selected Toolchain components in declaration order' {
		$source = Join-Path $TestDrive 'selected-components'
		New-TestToolchainComponentSource -Root $source

		$result = Invoke-ToolchainDeploymentPackage -Command deploy -Path $source -Cluster dev -Components @('optional-*', '-application') -Confirm -PassThru

		$result.Components | Should -Be @('prerequisites', 'optional-addon')
		$result.Manifests[0] | Should -BeExactly 'manifests/configmap.yaml'
		$result.ManifestDetails[0].Component | Should -BeExactly 'prerequisites'
		$result.ManifestDetails[0].Name | Should -BeExactly 'prerequisite-resources'
		$result.Releases.Count | Should -Be 1
		$result.Releases[0].Component | Should -BeExactly 'optional-addon'
		$result.Releases[0].Name | Should -BeExactly 'component-addon'
		$script:helmCalls[0].Arguments | Should -Contain (Join-Path $source 'package-values.yaml')
	}

	It 'selects required and default components when no override is supplied' {
		$source = Join-Path $TestDrive 'default-components'
		New-TestToolchainComponentSource -Root $source

		$result = Invoke-ToolchainDeploymentPackage -Command deploy -Path $source -Cluster dev -Confirm -PassThru

		$result.Components | Should -Be @('prerequisites', 'application')
		$result.Releases[0].Name | Should -BeExactly 'component-app'
		$script:helmCalls[0].Arguments | Should -Not -Contain '--wait'
		$script:helmCalls[0].Arguments | Should -Contain '--skip-schema-validation'
	}

	It 'resolves and safely templates package variables into manifests, charts, and Helm values' {
		$source = Join-Path $TestDrive 'variable-deploy'
		New-TestVariableDeploymentSource -Root $source
		$labels = "team: platform`nowner: operations"

		$result = Invoke-ToolchainDeploymentPackage -Command deploy -Path $source -Cluster dev -Set @('APP_NAME=command-app', "EXTRA_LABELS=$labels") -Confirm -PassThru

		$result.Variables | Should -Be @('APP_NAME', 'EXTRA_LABELS', 'FILE_CONTENT')
		$script:appliedManifestContents[0] | Should -Match 'name: command-app'
		$script:appliedManifestContents[0] | Should -Match "(?m)^    team: platform$"
		$script:appliedManifestContents[0] | Should -Match "(?m)^    owner: operations$"
		$script:appliedManifestContents[0] | Should -Match 'secret-file-content'
		$script:renderedChartContents[0] | Should -Match 'name: command-app-chart'
		($script:helmValueContents -join "`n") | Should -Match 'displayName: command-app'
		($script:helmValueContents -join "`n") | Should -Match '"application"'
		($script:helmValueContents -join "`n") | Should -Match '"name"\s*:\s*"command-app"'
		foreach ($renderedPath in $script:renderedPaths) {
			if ($renderedPath -like (Join-Path ([IO.Path]::GetTempPath()) 'toolchain-render-*')) { Test-Path -LiteralPath $renderedPath | Should -BeFalse }
		}
	}

	It 'rejects invalid and undeclared variable overrides before contacting Kubernetes' {
		$source = Join-Path $TestDrive 'invalid-variable-deploy'
		New-TestVariableDeploymentSource -Root $source

		{ Invoke-ToolchainDeploymentPackage -Command deploy -Path $source -Set 'APP_NAME=INVALID!' -Confirm } | Should -Throw '*required pattern*'
		{ Invoke-ToolchainDeploymentPackage -Command deploy -Path $source -Set 'MISSING=value' -Confirm } | Should -Throw '*not declared*'
		$script:kubectlCalls.Count | Should -Be 0
	}
}
