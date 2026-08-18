<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

BeforeAll {
	. (Join-Path $PSScriptRoot 'config.ps1')
	. (Join-Path $PSScriptRoot 'project.ps1')
	function Write-ToolchainInfo { param([string]$Message) }
	function Set-ToolchainLogConfiguration { param($Level,$Format) [pscustomobject]@{ Level='info'; Format='console' } }
	function Reset-ToolchainLogConfiguration { param($Configuration) }
	function Get-ToolchainClusterExecutable { param($Name,$Package,$InstallHint) "$Name.exe" }
	function Invoke-ToolchainClusterProcess { param($FilePath,$Arguments,[switch]$AllowFailure) [pscustomobject]@{ ExitCode = 0; Output = @() } }
	function Resolve-ToolchainContainerEngine { param($Engine,$Provider) [pscustomobject]@{ Name = 'docker'; Path = 'docker.exe' } }
	function Resolve-ToolchainBootstrapKubeconfig { param($Name,$Kubeconfig) $Kubeconfig }
	function Resolve-ToolchainCurrentClusterContext { param([switch]$SelectSingle) }
	function Get-ToolchainBootstrapApiServer { param($Kubeconfig) 'https://127.0.0.1:6443' }
	function Invoke-ToolchainBootstrapKubectl { param($Kubectl,$Kubeconfig,$Arguments,[switch]$AllowFailure) [pscustomobject]@{ ExitCode = 0; Output = @('ok') } }
	function Get-ToolchainBootstrapSecretValue { param($Kubectl,$Kubeconfig,$Secret,$Key) }
	. $PSCommandPath.Replace('.Tests.ps1', '.ps1')

	function New-TestImageLayout {
		param(
			[Parameter(Mandatory)][string]$LayoutRoot,
			[Parameter(Mandatory)][string]$Source,
			[string]$Component = 'prerequisites'
		)
		$files = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
		$key = Get-ToolchainDeploymentStringSha256 -Value $Source
		$configRelative = "$script:ToolchainDeploymentImageRoot/blobs/sha256/"
		$configSource = Join-Path $LayoutRoot 'config-source.json'
		[void][IO.Directory]::CreateDirectory($LayoutRoot)
		[IO.File]::WriteAllText($configSource, '{}', [Text.UTF8Encoding]::new($false))
		$configHex = (Get-FileHash -LiteralPath $configSource -Algorithm SHA256).Hash.ToLowerInvariant()
		$configRelative += $configHex
		$configPath = Resolve-ToolchainChildPath -Root $LayoutRoot -RelativePath $configRelative -RejectReparsePoints -RejectRootReparsePoint
		[void][IO.Directory]::CreateDirectory((Split-Path -Parent $configPath))
		[IO.File]::Move($configSource, $configPath)
		$files.Add($configRelative, $configPath)
		$layerSource = Join-Path $LayoutRoot 'layer-source.tar'
		[IO.File]::WriteAllText($layerSource, 'layer-data', [Text.UTF8Encoding]::new($false))
		$layerHex = (Get-FileHash -LiteralPath $layerSource -Algorithm SHA256).Hash.ToLowerInvariant()
		$layerRelative = "$script:ToolchainDeploymentImageRoot/blobs/sha256/$layerHex"
		$layerPath = Resolve-ToolchainChildPath -Root $LayoutRoot -RelativePath $layerRelative -RejectReparsePoints -RejectRootReparsePoint
		[IO.File]::Move($layerSource, $layerPath)
		$files.Add($layerRelative, $layerPath)
		$manifest = [ordered]@{
			schemaVersion = 2
			mediaType = 'application/vnd.docker.distribution.manifest.v2+json'
			config = [ordered]@{ mediaType = 'application/vnd.docker.container.image.v1+json'; size = (Get-Item $configPath).Length; digest = "sha256:$configHex" }
			layers = @([ordered]@{ mediaType = 'application/vnd.docker.image.rootfs.diff.tar'; size = (Get-Item $layerPath).Length; digest = "sha256:$layerHex" })
		}
		$manifestRelative = "$script:ToolchainDeploymentImageRoot/manifests/$key.json"
		$manifestPath = Resolve-ToolchainChildPath -Root $LayoutRoot -RelativePath $manifestRelative -RejectReparsePoints -RejectRootReparsePoint
		[void][IO.Directory]::CreateDirectory((Split-Path -Parent $manifestPath))
		[IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json -Depth 10 -Compress), [Text.UTF8Encoding]::new($false))
		$files.Add($manifestRelative, $manifestPath)
		$manifestDigest = 'sha256:' + (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
		return [pscustomobject]@{
			Files = $files
			Images = @([ordered]@{ source = $Source; components = @($Component); manifest = $manifestRelative; manifestDigest = $manifestDigest })
		}
	}

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

	It 'supports nested package configuration and bundles its deploy values' {
		$source = Join-Path $TestDrive 'nested-package-config'
		New-TestVariableDeploymentSource -Root $source
		$manifestPath = Join-Path $source 'toolchain.yaml'
		$manifest = (Get-Content -LiteralPath $manifestPath -Raw).Replace('  name: variable-demo', '  name: "###TOOLCHAIN_PKG_TMPL_PACKAGE_NAME###"')
		[IO.File]::WriteAllText($manifestPath, $manifest)
		[IO.File]::WriteAllText((Join-Path $source 'deploy-values.yaml'), "configured: true`n")
		[IO.File]::WriteAllText((Join-Path $source 'toolchain-config.yaml'), @'
log_level: debug
log_format: json
package:
  create:
    skip_sbom: true
    set:
      package_name: nested-config-demo
  deploy:
    retries: 4
    timeout: 15m
    set:
      app_name: nested-app
    values:
      - deploy-values.yaml
'@)
		$config = Read-ToolchainDeploymentConfig -Path (Join-Path $source 'toolchain-config.yaml')

		$result = New-ToolchainDeploymentPackage -Path $source -Output (Join-Path $TestDrive 'nested-package-config.tlcpkg')

		$config.logLevel | Should -BeExactly 'debug'
		$config.logFormat | Should -BeExactly 'json'
		$config.skipSbom | Should -BeTrue
		$config.hasSkipSbom | Should -BeTrue
		$config.retries | Should -Be 4
		$config.waitSeconds | Should -Be 900
		$result.Name | Should -BeExactly 'nested-config-demo'
		$expanded = Expand-ToolchainDeploymentPackage -Path $result.Path
		try {
			Test-Path -LiteralPath (Join-Path $expanded.Root 'deploy-values.yaml') -PathType Leaf | Should -BeTrue
		} finally { Remove-ToolchainDeploymentTemporaryRoot -Path $expanded.Root }
	}

	It 'downloads and integrity-indexes a remote Helm repository chart for offline deployment' {
		$source = Join-Path $TestDrive 'remote-chart-source'
		[void][IO.Directory]::CreateDirectory($source)
		[IO.File]::WriteAllText((Join-Path $source 'toolchain.yaml'), @'
apiVersion: toolchain.allsagetech.com/v1alpha1
kind: ToolchainPackageConfig
metadata:
  name: remote-demo
  version: 1.0.0
components:
  - name: application
    required: true
    charts:
      - name: package-name
        version: 6.4.0
        url: https://charts.example.invalid
        repoName: upstream-name
        releaseName: remote-demo
        namespace: remote-system
'@)
		Mock Invoke-ToolchainClusterProcess {
			$script:packageProcessCalls.Add([pscustomobject]@{ FilePath = $FilePath; Arguments = [string[]]$Arguments })
			if ($Arguments[0] -eq 'pull') {
				$destinationIndex = [array]::IndexOf([object[]]$Arguments, '--destination')
				[IO.File]::WriteAllText((Join-Path ([string]$Arguments[$destinationIndex + 1]) 'upstream-name-6.4.0.tgz'), 'remote-chart')
			}
			[pscustomobject]@{ ExitCode = 0; Output = @() }
		}
		$output = Join-Path $TestDrive 'remote-demo.tlcpkg'

		$result = New-ToolchainDeploymentPackage -Path $source -Output $output

		$result.Charts | Should -Be 1
		$pullCalls = @($script:packageProcessCalls | Where-Object { $_.FilePath -eq 'helm.exe' -and $_.Arguments[0] -eq 'pull' })
		$pullCalls.Count | Should -Be 1
		$pullCalls[0].Arguments[1] | Should -BeExactly 'upstream-name'
		$pullCalls[0].Arguments | Should -Contain '--repo'
		$pullCalls[0].Arguments | Should -Contain 'https://charts.example.invalid'
		$pullCalls[0].Arguments | Should -Contain '6.4.0'
		$expanded = Expand-ToolchainDeploymentPackage -Path $output
		try {
			$definition = Read-ToolchainDeploymentDefinition -Root $expanded.Root
			$definition.Charts[0].Remote | Should -BeTrue
			$definition.Charts[0].Path | Should -Match '^\.toolchain/charts/[0-9a-f]{64}\.tgz$'
			Test-Path -LiteralPath (Join-Path $expanded.Root $definition.Charts[0].Path) -PathType Leaf | Should -BeTrue
			Initialize-ToolchainDeploymentRemoteCharts -Definition $definition | Should -BeNullOrEmpty
			@($script:packageProcessCalls | Where-Object { $_.Arguments[0] -eq 'pull' }).Count | Should -Be 1
		} finally { Remove-ToolchainDeploymentTemporaryRoot -Path $expanded.Root }
	}

	It 'downloads OCI charts through Helm without treating the URL as a chart repository' {
		$source = Join-Path $TestDrive 'oci-chart-source'
		[void][IO.Directory]::CreateDirectory($source)
		[IO.File]::WriteAllText((Join-Path $source 'toolchain.yaml'), @'
apiVersion: toolchain.allsagetech.com/v1alpha1
kind: ToolchainPackageConfig
metadata:
  name: oci-demo
  version: 1.0.0
components:
  - name: application
    required: true
    charts:
      - name: podinfo
        version: 6.4.0
        url: oci://ghcr.io/example/charts/podinfo
'@)
		Mock Invoke-ToolchainClusterProcess {
			$script:packageProcessCalls.Add([pscustomobject]@{ FilePath = $FilePath; Arguments = [string[]]$Arguments })
			if ($Arguments[0] -eq 'pull') {
				$destinationIndex = [array]::IndexOf([object[]]$Arguments, '--destination')
				[IO.File]::WriteAllText((Join-Path ([string]$Arguments[$destinationIndex + 1]) 'podinfo-6.4.0.tgz'), 'oci-chart')
			}
			[pscustomobject]@{ ExitCode = 0; Output = @() }
		}

		$null = New-ToolchainDeploymentPackage -Path $source -Output (Join-Path $TestDrive 'oci-demo.tlcpkg')

		$pull = @($script:packageProcessCalls | Where-Object { $_.Arguments[0] -eq 'pull' })[0]
		$pull.Arguments[1] | Should -BeExactly 'oci://ghcr.io/example/charts/podinfo'
		$pull.Arguments | Should -Not -Contain '--repo'
		$pull.Arguments | Should -Contain '6.4.0'
	}

	It 'clones and packages Git-backed charts at the pinned version' {
		$source = Join-Path $TestDrive 'git-chart-source'
		[void][IO.Directory]::CreateDirectory($source)
		[IO.File]::WriteAllText((Join-Path $source 'toolchain.yaml'), @'
apiVersion: toolchain.allsagetech.com/v1alpha1
kind: ToolchainPackageConfig
metadata:
  name: git-demo
  version: 1.0.0
components:
  - name: application
    required: true
    charts:
      - name: git-app
        version: v1.2.3
        url: https://git.example.invalid/app.git
        gitPath: charts/app
'@)
		Mock Invoke-ToolchainClusterProcess {
			$script:packageProcessCalls.Add([pscustomobject]@{ FilePath = $FilePath; Arguments = [string[]]$Arguments })
			if ($FilePath -eq 'git.exe' -and $Arguments[0] -eq 'clone') {
				$chartRoot = Join-Path ([string]$Arguments[-1]) 'charts/app'
				[void][IO.Directory]::CreateDirectory($chartRoot)
				[IO.File]::WriteAllText((Join-Path $chartRoot 'Chart.yaml'), "apiVersion: v2`nname: git-app`nversion: 1.2.3`n")
			} elseif ($FilePath -eq 'helm.exe' -and $Arguments[0] -eq 'package') {
				$destinationIndex = [array]::IndexOf([object[]]$Arguments, '--destination')
				[IO.File]::WriteAllText((Join-Path ([string]$Arguments[$destinationIndex + 1]) 'git-app-1.2.3.tgz'), 'git-chart')
			}
			[pscustomobject]@{ ExitCode = 0; Output = @() }
		}

		$null = New-ToolchainDeploymentPackage -Path $source -Output (Join-Path $TestDrive 'git-demo.tlcpkg')

		$clone = @($script:packageProcessCalls | Where-Object { $_.FilePath -eq 'git.exe' -and $_.Arguments[0] -eq 'clone' })[0]
		$clone.Arguments | Should -Contain '--branch'
		$clone.Arguments | Should -Contain 'v1.2.3'
		$clone.Arguments | Should -Contain 'https://git.example.invalid/app.git'
		@($script:packageProcessCalls | Where-Object { $_.FilePath -eq 'helm.exe' -and $_.Arguments[0] -eq 'dependency' }).Count | Should -Be 1
		@($script:packageProcessCalls | Where-Object { $_.FilePath -eq 'helm.exe' -and $_.Arguments[0] -eq 'package' }).Count | Should -Be 1
	}

	It 'requires a pinned name and version for remote charts' {
		$source = Join-Path $TestDrive 'invalid-remote-chart'
		[void][IO.Directory]::CreateDirectory($source)
		[IO.File]::WriteAllText((Join-Path $source 'toolchain.yaml'), @'
apiVersion: toolchain.allsagetech.com/v1alpha1
kind: ToolchainPackageConfig
metadata:
  name: invalid-remote
  version: 1.0.0
components:
  - name: application
    required: true
    charts:
      - name: remote
        url: https://charts.example.invalid
'@)

		{ New-ToolchainDeploymentPackage -Path $source -Output (Join-Path $TestDrive 'invalid-remote.tlcpkg') } | Should -Throw '*requires version when url is used*'
		Should -Invoke Invoke-ToolchainClusterProcess -Times 0
	}

	It 'creates packages with action-only components and runs onCreate lifecycle actions' {
		$source = Join-Path $TestDrive 'create-actions'
		[void][IO.Directory]::CreateDirectory($source)
		[IO.File]::WriteAllText((Join-Path $source 'toolchain.yaml'), @'
apiVersion: toolchain.allsagetech.com/v1alpha1
kind: ToolchainPackageConfig
metadata:
  name: action-create-demo
  version: 1.0.0
components:
  - name: gate
    required: true
    actions:
      onCreate:
        defaults:
          maxTotalSeconds: 30
        before:
          - cmd: |
              echo before > action.log
            description: Open creation gate
        after:
          - cmd: 'echo after >> action.log'
        onSuccess:
          - cmd: 'echo success >> action.log'
'@)

		$result = New-ToolchainDeploymentPackage -Path $source -Output (Join-Path $TestDrive 'action-create.tlcpkg')

		$result.Actions.Count | Should -Be 3
		$content = Get-Content -LiteralPath (Join-Path $source 'action.log') -Raw
		$content | Should -Match 'before'
		$content | Should -Match 'after'
		$content | Should -Match 'success'
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

	It 'bundles component images into the verified offline package' {
		$source = Join-Path $TestDrive 'toolchain-images'
		New-TestToolchainComponentSource -Root $source
		$manifestPath = Join-Path $source 'toolchain.yaml'
		$content = (Get-Content -LiteralPath $manifestPath -Raw).Replace('    required: true', "    required: true`n    images:`n      - example.invalid/app:1")
		[IO.File]::WriteAllText($manifestPath, $content)
		Mock New-ToolchainDeploymentImageLayout { New-TestImageLayout -LayoutRoot $LayoutRoot -Source ([string]$Images[0].Source) -Component ([string]$Images[0].Component) }
		$output = Join-Path $TestDrive 'toolchain-images.tlcpkg'

		$result = New-ToolchainDeploymentPackage -Path $source -Output $output

		$result.Images | Should -Be 1
		Should -Invoke New-ToolchainDeploymentImageLayout -Times 1 -Exactly
		$expanded = Expand-ToolchainDeploymentPackage -Path $output
		try {
			$expanded.Index.images[0].source | Should -BeExactly 'example.invalid/app:1'
			$expanded.Index.images[0].manifestDigest | Should -Match '^sha256:[0-9a-f]{64}$'
			Test-Path -LiteralPath (Join-Path $expanded.Root $expanded.Index.images[0].manifest) -PathType Leaf | Should -BeTrue
		} finally { Remove-ToolchainDeploymentTemporaryRoot -Path $expanded.Root }
	}

	It 'rejects unsafe component image references before invoking a container engine' {
		$source = Join-Path $TestDrive 'toolchain-invalid-image'
		New-TestToolchainComponentSource -Root $source
		$manifestPath = Join-Path $source 'toolchain.yaml'
		$content = (Get-Content -LiteralPath $manifestPath -Raw).Replace('    required: true', "    required: true`n    images:`n      - https://example.invalid/app:1")
		[IO.File]::WriteAllText($manifestPath, $content)

		{ New-ToolchainDeploymentPackage -Path $source -Output (Join-Path $TestDrive 'invalid-image.tlcpkg') } | Should -Throw '*invalid image reference*'
		Should -Invoke Invoke-ToolchainClusterProcess -Times 0 -ParameterFilter { $Arguments[0] -in @('pull', 'save') }
	}

	It 'pulls and converts each declared image into registry-ready verified blobs' {
		$layoutRoot = Join-Path $TestDrive 'image-layout'
		$image = [pscustomobject]@{ Source = 'example.invalid/app:1'; Component = 'application' }
		Mock Resolve-ToolchainContainerEngine { [pscustomobject]@{ Name = 'docker'; Path = 'docker.exe' } }
		Mock Invoke-ToolchainClusterProcess {
			$script:packageProcessCalls.Add([pscustomobject]@{ FilePath = $FilePath; Arguments = [string[]]$Arguments })
			if ($Arguments[0] -eq 'save') {
				$outputIndex = [array]::IndexOf([object[]]$Arguments, '--output')
				[IO.File]::WriteAllText([string]$Arguments[$outputIndex + 1], 'archive')
			} elseif ($Arguments[0] -eq '-xf') {
				$rootIndex = [array]::IndexOf([object[]]$Arguments, '-C')
				$extractRoot = [string]$Arguments[$rootIndex + 1]
				[void][IO.Directory]::CreateDirectory((Join-Path $extractRoot 'layer'))
				[IO.File]::WriteAllText((Join-Path $extractRoot 'config.json'), '{}')
				[IO.File]::WriteAllText((Join-Path $extractRoot 'layer/layer.tar'), 'layer-data')
				[IO.File]::WriteAllText((Join-Path $extractRoot 'manifest.json'), '[{"Config":"config.json","RepoTags":["example.invalid/app:1"],"Layers":["layer/layer.tar"]}]')
			}
			[pscustomobject]@{ ExitCode = 0; Output = @() }
		}

		$layout = New-ToolchainDeploymentImageLayout -Images @($image) -LayoutRoot $layoutRoot

		$layout.Images.Count | Should -Be 1
		$layout.Files.Count | Should -Be 3
		{ Resolve-ToolchainDeploymentImageArtifact -Root $layoutRoot -Artifact $layout.Images[0] } | Should -Not -Throw
		Should -Invoke Invoke-ToolchainClusterProcess -Times 1 -Exactly -ParameterFilter { $FilePath -eq 'docker.exe' -and $Arguments[0] -eq 'pull' -and $Arguments[1] -eq 'example.invalid/app:1' }
		Should -Invoke Invoke-ToolchainClusterProcess -Times 1 -Exactly -ParameterFilter { $FilePath -eq 'docker.exe' -and $Arguments[0] -eq 'save' }
		Should -Invoke Invoke-ToolchainClusterProcess -Times 1 -Exactly -ParameterFilter { $FilePath -eq 'tar.exe' -and $Arguments[0] -eq '-xf' }
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

	It 'applies nested package deploy variables, components, and values' {
		$source = Join-Path $TestDrive 'nested-deploy-config'
		New-TestToolchainComponentSource -Root $source
		$manifestPath = Join-Path $source 'toolchain.yaml'
		$manifest = Get-Content -LiteralPath $manifestPath -Raw
		$manifest = $manifest.Replace("components:`n", "variables:`n  - name: APP_NAME`n    default: default-app`ncomponents:`n")
		[IO.File]::WriteAllText($manifestPath, $manifest)
		[IO.File]::WriteAllText((Join-Path $source 'manifests/configmap.yaml'), "apiVersion: v1`nkind: ConfigMap`nmetadata:`n  name: ###TOOLCHAIN_VAR_APP_NAME###`n")
		[IO.File]::WriteAllText((Join-Path $source 'deploy-values.yaml'), "configured: true`n")
		[IO.File]::WriteAllText((Join-Path $source 'toolchain-config.yaml'), @'
package:
  deploy:
    components: 'optional-*,-application'
    set:
      app_name: nested-app
    values:
      - deploy-values.yaml
'@)

		$result = Invoke-ToolchainDeploymentPackage -Command deploy -Path $source -Confirm -PassThru

		$result.Components | Should -Be @('prerequisites', 'optional-addon')
		$script:appliedManifestContents[0] | Should -Match 'name: nested-app'
		$script:helmCalls[0].Arguments | Should -Contain (Join-Path $source 'deploy-values.yaml')
	}

	It 'runs action-only deployment gates and templates their output variables into later resources' {
		$source = Join-Path $TestDrive 'deploy-actions'
		[void][IO.Directory]::CreateDirectory((Join-Path $source 'manifests'))
		[IO.File]::WriteAllText((Join-Path $source 'toolchain.yaml'), @'
apiVersion: toolchain.allsagetech.com/v1alpha1
kind: ToolchainPackageConfig
metadata:
  name: action-deploy-demo
  version: 1.0.0
components:
  - name: gate
    required: true
    actions:
      onDeploy:
        before:
          - cmd: echo action-name
            mute: true
            setVariables:
              - name: ACTION_NAME
                pattern: '^[a-z-]+$'
  - name: application
    required: true
    manifests:
      - name: application
        files:
          - manifests
'@)
		[IO.File]::WriteAllText((Join-Path $source 'manifests/configmap.yaml'), "apiVersion: v1`nkind: ConfigMap`nmetadata:`n  name: ###TOOLCHAIN_VAR_ACTION_NAME###`n")

		$result = Invoke-ToolchainDeploymentPackage -Command deploy -Path $source -Confirm -PassThru

		$result.Components | Should -Be @('gate', 'application')
		$result.Actions.Count | Should -Be 1
		$result.Variables | Should -Contain 'ACTION_NAME'
		$script:appliedManifestContents[0] | Should -Match 'name: action-name'
		$package = New-ToolchainDeploymentPackage -Path $source -Output (Join-Path $TestDrive 'action-deploy.tlcpkg')
		$package.Variables | Should -Contain 'ACTION_NAME'
		$expanded = Expand-ToolchainDeploymentPackage -Path $package.Path
		try { $expanded.Index.variables | Should -Contain 'ACTION_NAME' }
		finally { Remove-ToolchainDeploymentTemporaryRoot -Path $expanded.Root }
	}

	It 'does not execute deployment actions during a dry run' {
		$source = Join-Path $TestDrive 'dry-run-actions'
		[void][IO.Directory]::CreateDirectory($source)
		[IO.File]::WriteAllText((Join-Path $source 'toolchain.yaml'), @'
apiVersion: toolchain.allsagetech.com/v1alpha1
kind: ToolchainPackageConfig
metadata:
  name: dry-run-actions
  version: 1.0.0
components:
  - name: gate
    required: true
    actions:
      onDeploy:
        before:
          - cmd: exit 19
'@)

		{ Invoke-ToolchainDeploymentPackage -Command deploy -Path $source -DryRun -PassThru } | Should -Not -Throw
	}

	It 'supports Kubernetes wait actions in deployment gates' {
		$source = Join-Path $TestDrive 'wait-actions'
		[void][IO.Directory]::CreateDirectory($source)
		[IO.File]::WriteAllText((Join-Path $source 'toolchain.yaml'), @'
apiVersion: toolchain.allsagetech.com/v1alpha1
kind: ToolchainPackageConfig
metadata:
  name: wait-actions
  version: 1.0.0
components:
  - name: gate
    required: true
    actions:
      onDeploy:
        before:
          - wait:
              cluster:
                kind: Deployment
                name: prerequisite
                namespace: toolchain-system
                condition: Available
            maxTotalSeconds: 30
'@)

		$result = Invoke-ToolchainDeploymentPackage -Command deploy -Path $source -Confirm -PassThru

		$result.Actions.Count | Should -Be 1
		@($script:kubectlCalls | Where-Object { $_.Arguments -contains 'wait' -and $_.Arguments -contains '--for=condition=Available' }).Count | Should -Be 1
	}

	It 'runs failure actions when a deployment gate command fails' {
		$source = Join-Path $TestDrive 'failure-actions'
		[void][IO.Directory]::CreateDirectory($source)
		[IO.File]::WriteAllText((Join-Path $source 'toolchain.yaml'), @'
apiVersion: toolchain.allsagetech.com/v1alpha1
kind: ToolchainPackageConfig
metadata:
  name: failure-actions
  version: 1.0.0
components:
  - name: gate
    required: true
    actions:
      onDeploy:
        before:
          - cmd: exit 19
        onFailure:
          - cmd: 'echo failed > failure.log'
'@)

		{ Invoke-ToolchainDeploymentPackage -Command deploy -Path $source -Confirm } | Should -Throw '*failed after 1 attempt*'
		(Get-Content -LiteralPath (Join-Path $source 'failure.log') -Raw) | Should -Match 'failed'
	}

	It 'supports TCP network waits in deployment gates' {
		$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
		$listener.Start()
		try {
			$port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
			$source = Join-Path $TestDrive 'network-actions'
			[void][IO.Directory]::CreateDirectory($source)
			[IO.File]::WriteAllText((Join-Path $source 'toolchain.yaml'), @"
apiVersion: toolchain.allsagetech.com/v1alpha1
kind: ToolchainPackageConfig
metadata:
  name: network-actions
  version: 1.0.0
components:
  - name: gate
    required: true
    actions:
      onDeploy:
        before:
          - wait:
              network:
                protocol: tcp
                address: 127.0.0.1:$port
            maxTotalSeconds: 5
"@)

			$result = Invoke-ToolchainDeploymentPackage -Command deploy -Path $source -Confirm -PassThru

			$result.Actions.Count | Should -Be 1
			$result.Actions[0].State | Should -BeExactly 'succeeded'
		} finally { $listener.Stop() }
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

	It 'publishes selected component images before applying their resources' {
		$source = Join-Path $TestDrive 'image-deploy'
		New-TestToolchainComponentSource -Root $source
		$manifestPath = Join-Path $source 'toolchain.yaml'
		$content = (Get-Content -LiteralPath $manifestPath -Raw).Replace('    required: true', "    required: true`n    images:`n      - example.invalid/app:1")
		[IO.File]::WriteAllText($manifestPath, $content)
		Mock Publish-ToolchainDeploymentImages {
			@([pscustomobject]@{ Component = 'prerequisites'; Source = 'example.invalid/app:1'; Target = '127.0.0.1:31999/toolchain/app@sha256:' + ('a' * 64); State = 'published' })
		}

		$result = Invoke-ToolchainDeploymentPackage -Command deploy -Path $source -Cluster dev -Confirm -PassThru

		$result.Images.Count | Should -Be 1
		$result.Images[0].Source | Should -BeExactly 'example.invalid/app:1'
		Should -Invoke Publish-ToolchainDeploymentImages -Times 1 -Exactly -ParameterFilter { $Components[0].Name -eq 'prerequisites' -and $Kubectl -eq 'kubectl.exe' }
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

Describe 'Toolchain deployment package image publication' {
	BeforeEach {
		$script:imageKubectlCalls = [Collections.Generic.List[object]]::new()
		$script:registryCalls = [Collections.Generic.List[object]]::new()
		Mock Get-ToolchainBootstrapSecretValue {
			switch ($Key) {
				'state.json' { return '{"registryAddress":"127.0.0.1:31999"}' }
				'username' { return 'toolchain-push' }
				'password' { return 'registry-secret' }
			}
		}
		Mock New-ToolchainDeploymentRegistryTunnel { [pscustomobject]@{ BaseUri = 'http://127.0.0.1:45678'; Process = $null } }
		Mock Remove-ToolchainDeploymentRegistryTunnel { }
		Mock Invoke-ToolchainBootstrapKubectl {
			$script:imageKubectlCalls.Add([pscustomobject]@{ Arguments = [string[]]$Arguments })
			if ($Arguments[0] -eq 'get') { return [pscustomobject]@{ ExitCode = 0; Output = @('{"existing.invalid/app:1":"127.0.0.1:31999/existing@sha256:abc"}') } }
			[pscustomobject]@{ ExitCode = 0; Output = @('ok') }
		}
		Mock Invoke-ToolchainDeploymentRegistryRequest {
			$script:registryCalls.Add([pscustomobject]@{ Method = $Method; Uri = $Uri; FilePath = $FilePath; Body = $Body; ContentType = $ContentType })
			if ($Method -eq 'HEAD') { return [pscustomobject]@{ StatusCode = 404; Location = $null; Digest = $null } }
			if ($Method -eq 'POST') { return [pscustomobject]@{ StatusCode = 202; Location = '/v2/upload/repository/blobs/uploads/id'; Digest = $null } }
			if ($Uri -match '/manifests/') { return [pscustomobject]@{ StatusCode = 201; Location = $null; Digest = $script:expectedManifestDigest } }
			[pscustomobject]@{ StatusCode = 201; Location = $null; Digest = $null }
		}
	}

	It 'uploads verified blobs, publishes a digest-pinned manifest, and updates exact image mappings' {
		$source = Join-Path $TestDrive 'registry-publish-source'
		New-TestToolchainComponentSource -Root $source
		$manifestPath = Join-Path $source 'toolchain.yaml'
		$content = (Get-Content -LiteralPath $manifestPath -Raw).Replace('    required: true', "    required: true`n    images:`n      - example.invalid/app:1")
		[IO.File]::WriteAllText($manifestPath, $content)
		$definition = Read-ToolchainDeploymentDefinition -Root $source
		$selected = @(Resolve-ToolchainDeploymentComponentSelection -Definition $definition)
		$layoutRoot = Join-Path $TestDrive 'registry-layout'
		$layout = New-TestImageLayout -LayoutRoot $layoutRoot -Source 'example.invalid/app:1'
		$script:expectedManifestDigest = [string]$layout.Images[0].manifestDigest
		$index = [pscustomobject]@{ images = $layout.Images }

		$result = @(Publish-ToolchainDeploymentImages -Definition $definition -Components $selected -Root $layoutRoot -PackageIndex $index -Kubectl 'kubectl.exe' -Kubeconfig 'managed.yaml')

		$result.Count | Should -Be 1
		$result[0].Target | Should -BeExactly "127.0.0.1:31999/toolchain/packages/component-demo/$(Get-ToolchainDeploymentStringSha256 -Value 'example.invalid/app:1')@$script:expectedManifestDigest"
		@($script:registryCalls | Where-Object { $_.Method -eq 'HEAD' }).Count | Should -Be 2
		@($script:registryCalls | Where-Object { $_.Uri -match '/manifests/' }).Count | Should -Be 1
		$patchCall = $script:imageKubectlCalls | Where-Object { $_.Arguments[0] -eq 'patch' } | Select-Object -First 1
		$patchValue = [string]$patchCall.Arguments[[array]::IndexOf([object[]]$patchCall.Arguments, '--patch') + 1]
		$patchObject = $patchValue | ConvertFrom-Json
		$mappings = $patchObject.data.'mappings.json' | ConvertFrom-Json
		$mappings.'existing.invalid/app:1' | Should -BeExactly '127.0.0.1:31999/existing@sha256:abc'
		$mappings.'example.invalid/app:1' | Should -BeExactly $result[0].Target
		Should -Invoke Invoke-ToolchainBootstrapKubectl -Times 1 -Exactly -ParameterFilter { $Arguments[0] -eq 'rollout' -and $Arguments[1] -eq 'restart' }
		Should -Invoke Remove-ToolchainDeploymentRegistryTunnel -Times 1 -Exactly
	}

	It 'plans image publication without pulling, pushing, or changing cluster mappings during dry run' {
		$component = [pscustomobject]@{ Images = @([pscustomobject]@{ Source = 'example.invalid/app:1'; Component = 'application' }) }
		$definition = [pscustomobject]@{ Name = 'demo' }

		$result = @(Publish-ToolchainDeploymentImages -Definition $definition -Components @($component) -Root $TestDrive -PackageIndex $null -Kubectl 'kubectl.exe' -DryRun)

		$result[0].State | Should -BeExactly 'planned'
		Should -Invoke New-ToolchainDeploymentRegistryTunnel -Times 0
		Should -Invoke Invoke-ToolchainDeploymentRegistryRequest -Times 0
		Should -Invoke Invoke-ToolchainBootstrapKubectl -Times 0
	}
}
