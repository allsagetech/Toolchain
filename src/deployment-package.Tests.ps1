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
		Mock Resolve-ToolchainDeploymentKubeconfig { 'managed-kubeconfig.yaml' }
		Mock Get-ToolchainClusterExecutable { "$Name.exe" }
		Mock Invoke-ToolchainBootstrapKubectl {
			$script:kubectlCalls.Add([pscustomobject]@{ Kubectl = $Kubectl; Kubeconfig = $Kubeconfig; Arguments = [string[]]$Arguments })
			[pscustomobject]@{ ExitCode = 0; Output = @('ok') }
		}
		Mock Invoke-ToolchainClusterProcess {
			$script:helmCalls.Add([pscustomobject]@{ FilePath = $FilePath; Arguments = [string[]]$Arguments })
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
}
