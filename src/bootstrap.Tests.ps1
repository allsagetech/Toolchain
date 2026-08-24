<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

BeforeAll {
	function Resolve-ToolchainFileSystemPath { param([Parameter(Mandatory)][string]$Path) [IO.Path]::GetFullPath($Path) }
	function Resolve-ToolchainChildPath { param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$RelativePath, [switch]$RejectReparsePoints, [switch]$RejectRootReparsePoint) [IO.Path]::GetFullPath((Join-Path $Root ($RelativePath -replace '/', [IO.Path]::DirectorySeparatorChar))) }
	function Assert-ToolchainClusterImage { param($Image) if (-not $Image -or $Image -match '\s') { throw 'invalid image' } }
	function Read-ToolchainClusterState { }
	function Get-ToolchainClusterRuntimeStatus { }
	function Get-ToolchainClusterKubeconfigPath { }
	function Sync-ToolchainClusterKubeconfig { param($State) }
	function Publish-ToolchainLocalAgentImage { param($Name) }
	function Get-ToolchainClusterExecutable { }
	function Invoke-ToolchainClusterProcess { }
	function Write-ToolchainClusterTextFile { param($Path, $Content) [IO.File]::WriteAllText($Path, $Content) }
	function Write-ToolchainInfo { }
	. $PSCommandPath.Replace('.Tests.ps1', '.ps1')
}

Describe 'Toolchain native cluster bootstrap manifests' {
	It 'renders a digest-pinned registry and fail-closing admission agent natively' {
		$manifest = New-ToolchainBootstrapManifest `
			-AgentImage 'ghcr.io/allsagetech/toolchain-agent:2.4.0' `
			-RegistryImage $script:ToolchainRegistryImage `
			-GitImage $script:ToolchainGitImage `
			-AgentMutationPolicy all `
			-RegistryAuth @{ Username='toolchain-push'; Password='registry-secret' }

		$manifest | Should -Match 'name: toolchain-state'
		$manifest | Should -Match 'name: toolchain-registry'
		$manifest | Should -Match 'name: toolchain-registry-gateway'
		$manifest | Should -Match 'nodePort: 31999'
		$manifest | Should -Match "password: 'registry-secret'"
		$manifest | Should -Match ([regex]::Escape($script:ToolchainRegistryImage))
		$manifest | Should -Match 'kind: MutatingWebhookConfiguration'
		$manifest | Should -Match 'failurePolicy: Ignore'
		$manifest | Should -Match 'TOOLCHAIN_MUTATION_POLICY'
		$manifest | Should -Not -Match 'name: toolchain-git'
	}

	It 'adds the optional pinned Git service and custom storage settings' {
		$manifest = New-ToolchainBootstrapManifest `
			-AgentImage 'ghcr.io/allsagetech/toolchain-agent:2.4.0' `
			-RegistryImage $script:ToolchainRegistryImage `
			-GitImage $script:ToolchainGitImage `
			-AgentMutationPolicy labeled `
			-RegistryAuth @{ Username='toolchain-push'; Password='registry-secret' } `
			-GitAdminAuth @{ Username='toolchain-admin'; Password='git-secret' } `
			-Components git-server `
			-StorageClass fast `
			-RegistryStorage 30Gi `
			-GitStorage 15Gi

		$manifest | Should -Match 'name: toolchain-git'
		$manifest | Should -Match 'name: toolchain-git-admin'
		$manifest | Should -Match 'name: ensure-admin'
		$manifest | Should -Match 'name: toolchain-git-config'
		$manifest | Should -Match ([regex]::Escape($script:ToolchainGitImage))
		$manifest | Should -Match "storageClassName: 'fast'"
		$manifest | Should -Match "storage: '30Gi'"
		$manifest | Should -Match "storage: '15Gi'"
		$manifest | Should -Match "value: 'labeled'"
	}

	It 'quotes manifest values and rejects control characters' {
		ConvertTo-ToolchainBootstrapYamlString "value's" | Should -Be "'value''s'"
		{ ConvertTo-ToolchainBootstrapYamlString "bad`nvalue" } | Should -Throw '*control*'
		{ New-ToolchainBootstrapManifest -AgentImage agent:1 -RegistryImage registry:3 -GitImage git:1 -AgentMutationPolicy all -RegistryAuth @{ Username='push'; Password='secret' } -MappingsJson '[]' } | Should -Throw '*JSON object*'
	}
}

Describe 'Toolchain cluster component selection' {
	BeforeEach {
		Mock Write-Warning { }
	}

	It 'defaults the Git server prompt to no' {
		Mock Read-Host { '' }

		@(Select-ToolchainClusterInitComponents).Count | Should -Be 0
		Should -Invoke Read-Host -Times 1 -Exactly
	}

	It 'accepts yes and no answers without case sensitivity' {
		Mock Read-Host { 'YES' }
		@(Select-ToolchainClusterInitComponents) | Should -Be @('git-server')

		Mock Read-Host { 'No' }
		@(Select-ToolchainClusterInitComponents).Count | Should -Be 0
	}

	It 'reprompts after an invalid answer' {
		$script:componentAnswers = [Collections.Generic.Queue[string]]::new()
		$script:componentAnswers.Enqueue('maybe')
		$script:componentAnswers.Enqueue('y')
		Mock Read-Host { $script:componentAnswers.Dequeue() }

		@(Select-ToolchainClusterInitComponents) | Should -Be @('git-server')
		Should -Invoke Read-Host -Times 2 -Exactly
		Should -Invoke Write-Warning -Times 1 -Exactly
	}

	It 'explains how non-interactive callers can select components' {
		Mock Read-Host { throw 'non-interactive host' }

		{ Select-ToolchainClusterInitComponents } | Should -Throw '*-Components git-server*Components none*'
	}
}

Describe 'Toolchain cluster backup restore helpers' {
	It 'safely expands directory and zip backups' {
		$backup = Join-Path $TestDrive 'backup'
		New-Item -ItemType Directory -Path $backup -Force | Out-Null
		[IO.File]::WriteAllText((Join-Path $backup 'namespace.yaml'), 'apiVersion: v1')
		$expandedDirectory = Expand-ToolchainClusterBootstrapBackup -Path $backup
		$expandedDirectory.Temporary | Should -BeFalse
		Test-Path -LiteralPath (Join-Path $expandedDirectory.Root 'namespace.yaml') -PathType Leaf | Should -BeTrue

		$archive = Join-Path $TestDrive 'backup.zip'
		Compress-Archive -Path (Join-Path $backup '*') -DestinationPath $archive
		$expandedArchive = Expand-ToolchainClusterBootstrapBackup -Path $archive
		try {
			$expandedArchive.Temporary | Should -BeTrue
			Test-Path -LiteralPath (Join-Path $expandedArchive.Root 'namespace.yaml') -PathType Leaf | Should -BeTrue
		} finally {
			if (Test-Path -LiteralPath $expandedArchive.Root -PathType Container) { Remove-Item -LiteralPath $expandedArchive.Root -Recurse -Force }
		}
	}
}

Describe 'Toolchain native cluster initialization' {
	BeforeEach {
		$script:kubectlCalls = [Collections.Generic.List[object]]::new()
		$script:appliedManifest = $null
		Mock Get-ToolchainClusterExecutable { 'kubectl' }
		Mock Invoke-ToolchainClusterProcess {
			param($FilePath, $Arguments, [switch]$AllowFailure)
			$script:kubectlCalls.Add([pscustomobject]@{ FilePath=$FilePath; Arguments=[string[]]$Arguments; AllowFailure=[bool]$AllowFailure })
			if ($Arguments -contains 'namespace/toolchain-system' -and $Arguments -contains 'jsonpath={.metadata.labels.app\.kubernetes\.io/managed-by}') {
				return [pscustomobject]@{ ExitCode=0; Output=@('toolchain') }
			}
			if ($Arguments -contains 'namespace/toolchain-system' -and $Arguments -contains '-o' -and $Arguments -contains 'name') {
				return [pscustomobject]@{ ExitCode=0; Output=@('namespace/toolchain-system') }
			}
			if ($Arguments -contains 'configmap/toolchain-image-mappings') {
				return [pscustomobject]@{ ExitCode=0; Output=@('{"docker.io/example:1":"registry.local/example:1"}') }
			}
			if ($Arguments -contains 'secret/toolchain-registry-credentials' -or $Arguments -contains 'secret/toolchain-git-admin') {
				return [pscustomobject]@{ ExitCode=0; Output=@() }
			}
			if ($Arguments -contains 'apply') {
				$manifestPath = $Arguments[-1]
				$script:appliedManifest = Get-Content -LiteralPath $manifestPath -Raw
			}
			[pscustomobject]@{ ExitCode=0; Output=@('ok') }
		}
		Mock Write-ToolchainInfo { }
		Mock Select-ToolchainClusterInitComponents { }
		Mock Sync-ToolchainClusterKubeconfig { }
		Mock Publish-ToolchainLocalAgentImage { 'toolchain-agent:2.4.0-local-test' }
	}

	It 'requires explicit non-interactive confirmation before contacting a cluster' {
		{ Invoke-ToolchainClusterInit } | Should -Throw '*-Confirm*'
		Should -Invoke Get-ToolchainClusterExecutable -Times 0 -Exactly
	}

	It 'applies and waits for the native registry and agent on the current context' {
		$result = Invoke-ToolchainClusterInit -Confirm -PassThru -AgentImage 'ghcr.io/allsagetech/toolchain-agent:2.4.0'

		$result.Cluster | Should -Be 'current-context'
		$result.Namespace | Should -Be 'toolchain-system'
		$script:appliedManifest | Should -Match 'kind: MutatingWebhookConfiguration'
		$result.Registry | Should -Be '127.0.0.1:31999'
		$result.RegistryCredentialSecret | Should -Be 'toolchain-registry-credentials'
		@($script:kubectlCalls).Count | Should -Be 10
		@($script:kubectlCalls | Where-Object { $_.Arguments -contains '--raw=/readyz' }).Count | Should -Be 1
		($script:kubectlCalls | Where-Object { $_.Arguments -contains 'apply' }).Arguments | Should -Contain '--server-side'
		$script:appliedManifest | Should -Match ([regex]::Escape('docker.io/example:1'))
		$script:appliedManifest | Should -Match "value: 'labeled'"
		@($script:kubectlCalls | Where-Object { $_.Arguments -contains 'restart' }).Count | Should -Be 1
		@($script:kubectlCalls | Where-Object { $_.Arguments -contains 'deployment/toolchain-agent' }).Count | Should -Be 2
		@($script:kubectlCalls | Where-Object { $_.Arguments -contains 'deployment/toolchain-registry-gateway' }).Count | Should -Be 1
		Should -Invoke Write-ToolchainInfo -Times 2 -Exactly
		Should -Invoke Select-ToolchainClusterInitComponents -Times 1 -Exactly
	}

	It 'uses an isolated managed kubeconfig and waits for the optional Git service' {
		$script:managedKubeconfig = Join-Path $TestDrive 'kubeconfig.yaml'
		[IO.File]::WriteAllText($script:managedKubeconfig, 'apiVersion: v1')
		Mock Read-ToolchainClusterState { [pscustomobject]@{ name='dev'; provider='kind' } }
		Mock Get-ToolchainClusterRuntimeStatus { 'Running' }
		Mock Get-ToolchainClusterKubeconfigPath { $script:managedKubeconfig }

		$result = Invoke-ToolchainClusterInit -Name dev -Confirm -PassThru -Components git-server -AgentImage 'ghcr.io/allsagetech/toolchain-agent:2.4.0'

		$result.Cluster | Should -Be dev
		$result.Kubeconfig | Should -Be $script:managedKubeconfig
		$result.GitUsername | Should -Be toolchain-admin
		$result.GitCredentialSecret | Should -Be toolchain-git-admin
		$script:appliedManifest | Should -Match 'name: toolchain-git'
		@($script:kubectlCalls | Where-Object { $_.Arguments -contains 'deployment/toolchain-git' }).Count | Should -Be 1
		foreach ($call in $script:kubectlCalls) { $call.Arguments | Should -Contain '--kubeconfig' }
		Should -Invoke Sync-ToolchainClusterKubeconfig -Times 1 -Exactly
		Should -Invoke Select-ToolchainClusterInitComponents -Times 0 -Exactly
	}

	It 'builds the local agent only after a managed cluster passes API preflight' {
		$script:managedKubeconfig = Join-Path $TestDrive 'kubeconfig.yaml'
		[IO.File]::WriteAllText($script:managedKubeconfig, "apiVersion: v1`nclusters:`n- cluster:`n    server: https://127.0.0.1:6443`n")
		Mock Read-ToolchainClusterState { [pscustomobject]@{ name='dev'; provider='k3s' } }
		Mock Get-ToolchainClusterRuntimeStatus { 'Running' }
		Mock Get-ToolchainClusterKubeconfigPath { $script:managedKubeconfig }

		Invoke-ToolchainClusterInit -Name dev -Confirm -Components none -BuildLocalAgent

		Should -Invoke Publish-ToolchainLocalAgentImage -Times 1 -Exactly -ParameterFilter { $Name -eq 'dev' }
		$script:appliedManifest | Should -Match 'toolchain-agent:2\.4\.0-local-test'
	}

	It 'reports the managed endpoint and underlying kubectl API failure' {
		$kubeconfig = Join-Path $TestDrive 'unreachable.yaml'
		[IO.File]::WriteAllText($kubeconfig, "apiVersion: v1`nclusters:`n- cluster:`n    server: https://127.0.0.1:65535`n")
		Mock Invoke-ToolchainClusterProcess {
			param($FilePath, $Arguments, [switch]$AllowFailure)
			if ($Arguments -contains '--raw=/readyz') { throw 'dial tcp 127.0.0.1:65535: connect refused' }
			return [pscustomobject]@{ ExitCode=0; Output=@('ok') }
		}

		{ Invoke-ToolchainClusterInit -Kubeconfig $kubeconfig -Confirm -Components none -AgentImage agent:1 } |
			Should -Throw '*API preflight*https://127.0.0.1:65535*dial tcp*'
		Should -Invoke Publish-ToolchainLocalAgentImage -Times 0 -Exactly
	}

	It 'supports an explicit non-interactive no-components selection' {
		$result = Invoke-ToolchainClusterInit -Confirm -PassThru -Components none -AgentImage 'ghcr.io/allsagetech/toolchain-agent:2.4.0'

		@($result.Components).Count | Should -Be 0
		$script:appliedManifest | Should -Not -Match 'name: toolchain-git'
		Should -Invoke Select-ToolchainClusterInitComponents -Times 0 -Exactly
	}

	It 'rejects none combined with another component before contacting a cluster' {
		{ Invoke-ToolchainClusterInit -Confirm -Components none,git-server } | Should -Throw '*cannot be combined*'
		Should -Invoke Get-ToolchainClusterExecutable -Times 0 -Exactly
	}

	It 'preserves existing generated registry credentials across upgrades' {
		$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('existing-secret'))
		Mock Invoke-ToolchainClusterProcess {
			param($FilePath, $Arguments, [switch]$AllowFailure)
			$script:kubectlCalls.Add([pscustomobject]@{ FilePath=$FilePath; Arguments=[string[]]$Arguments; AllowFailure=[bool]$AllowFailure })
			if ($Arguments -contains 'configmap/toolchain-image-mappings') { return [pscustomobject]@{ ExitCode=0; Output=@('{}') } }
			if ($Arguments -contains 'secret/toolchain-registry-credentials') { return [pscustomobject]@{ ExitCode=0; Output=@($encoded) } }
			if ($Arguments -contains 'apply') { $script:appliedManifest = Get-Content -LiteralPath $Arguments[-1] -Raw }
			return [pscustomobject]@{ ExitCode=0; Output=@('ok') }
		}

		Invoke-ToolchainClusterInit -Confirm -AgentImage 'ghcr.io/allsagetech/toolchain-agent:2.4.0'
		$script:appliedManifest | Should -Match "password: 'existing-secret'"
	}

	It 'rejects conflicting, missing, and stopped kubeconfig targets' {
		$kubeconfig = Join-Path $TestDrive 'kubeconfig.yaml'
		[IO.File]::WriteAllText($kubeconfig, 'apiVersion: v1')
		{ Resolve-ToolchainBootstrapKubeconfig -Name dev -Kubeconfig $kubeconfig } | Should -Throw '*either*'
		{ Resolve-ToolchainBootstrapKubeconfig -Kubeconfig (Join-Path $TestDrive 'missing') } | Should -Throw '*not a file*'
		Mock Read-ToolchainClusterState { [pscustomobject]@{ name='dev'; provider='kind' } }
		Mock Get-ToolchainClusterRuntimeStatus { 'Missing' }
		{ Resolve-ToolchainBootstrapKubeconfig -Name dev } | Should -Throw '*not running*'
	}

	It 'removes Toolchain bootstrap resources without deleting the cluster' {
		$script:managedKubeconfig = Join-Path $TestDrive 'deinit-kubeconfig.yaml'
		[IO.File]::WriteAllText($script:managedKubeconfig, "apiVersion: v1`nserver: https://127.0.0.1:6443`n")
		Mock Read-ToolchainClusterState { [pscustomobject]@{ name='dev'; provider='kind' } }
		Mock Get-ToolchainClusterRuntimeStatus { 'Running' }
		Mock Get-ToolchainClusterKubeconfigPath { $script:managedKubeconfig }

		$result = Invoke-ToolchainClusterDeinit -Name dev -Confirm -PassThru

		$result.PSObject.TypeNames[0] | Should -BeExactly 'Toolchain.ClusterDeinitialization'
		$result.Cluster | Should -BeExactly 'dev'
		$result.Namespace | Should -BeExactly 'toolchain-system'
		$result.Removed | Should -Contain 'mutatingwebhookconfiguration/toolchain-agent'
		$result.Removed | Should -Contain 'namespace/toolchain-system'
		@($script:kubectlCalls).Count | Should -Be 7
		($script:kubectlCalls[3].Arguments -join ' ') | Should -Match 'delete mutatingwebhookconfiguration/toolchain-agent'
		($script:kubectlCalls[6].Arguments -join ' ') | Should -Match 'delete namespace/toolchain-system'
		Test-Path -LiteralPath $script:managedKubeconfig | Should -BeTrue
	}

	It 'supports dry-run deinitialization while preserving storage' {
		$script:managedKubeconfig = Join-Path $TestDrive 'deinit-dry-run-kubeconfig.yaml'
		[IO.File]::WriteAllText($script:managedKubeconfig, "apiVersion: v1`nserver: https://127.0.0.1:6443`n")
		Mock Read-ToolchainClusterState { [pscustomobject]@{ name='dev'; provider='kind' } }
		Mock Get-ToolchainClusterRuntimeStatus { 'Running' }
		Mock Get-ToolchainClusterKubeconfigPath { $script:managedKubeconfig }

		$result = Invoke-ToolchainClusterDeinit -Name dev -Confirm -KeepStorage -DryRun -PassThru

		$result.DryRun | Should -BeTrue
		$result.KeepStorage | Should -BeTrue
		@($script:kubectlCalls | Where-Object { $_.Arguments -contains 'delete' -and $_.Arguments -notcontains '--dry-run=server' }).Count | Should -Be 0
	}
}
