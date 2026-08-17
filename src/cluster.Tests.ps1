<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

BeforeAll {
	. (Join-Path $PSScriptRoot 'config.ps1')
	. (Join-Path $PSScriptRoot 'log.ps1')
	. $PSCommandPath.Replace('.Tests.ps1', '.ps1')
	function ResolvePackage { param([string]$Ref) }
	function LoadPackage { param($Pkg) }
	function Invoke-ToolchainClusterInit {
		param($Name,$Kubeconfig,[switch]$Confirm,$Components,[switch]$PromptForComponents,$AgentMutationPolicy,$AgentImage,$RegistryImage,$GitImage,$StorageClass,$RegistryStorage,$GitStorage,$RegistryNodePort,$WaitSeconds,[switch]$PassThru)
	}

	function New-TestClusterProcessResult {
		param([int]$ExitCode = 0, [string[]]$Output = @())
		return [pscustomobject]@{ ExitCode = $ExitCode; Output = [string[]]$Output }
	}

	function Get-TestClusterArgumentValue {
		param([string[]]$Arguments, [string]$Name)
		for ($i = 0; $i -lt $Arguments.Count - 1; $i++) {
			if ($Arguments[$i] -ceq $Name) { return $Arguments[$i + 1] }
		}
		return $null
	}
}

Describe 'Toolchain cluster validation' {
	BeforeEach {
		Mock Publish-ToolchainLocalAgentImage { 'toolchain-agent:2.4.0-local-test' }
	}

	It 'accepts portable DNS-label cluster names' {
		{ Assert-ToolchainClusterName -Name 'dev-1' } | Should -Not -Throw
	}

	It 'rejects unsafe or non-portable cluster names' {
		foreach ($name in @('', 'UPPER', '-dev', 'dev-', 'dev_cluster', '../dev', ('a' * 64))) {
			{ Assert-ToolchainClusterName -Name $name } | Should -Throw
		}
	}

	It 'rejects whitespace and controls in image references' {
		{ Assert-ToolchainClusterImage -Image 'kindest/node:v1.34.0' } | Should -Not -Throw
		{ Assert-ToolchainClusterImage -Image "image name" } | Should -Throw
		{ Assert-ToolchainClusterImage -Image "image`ntag" } | Should -Throw
	}

	It 'requires k0s images to use a non-latest tag or digest' {
		{ Assert-ToolchainPinnedK0sImage -Image 'docker.io/k0sproject/k0s:v1.32.4-k0s.0' } | Should -Not -Throw
		{ Assert-ToolchainPinnedK0sImage -Image ('docker.io/k0sproject/k0s@sha256:' + ('a' * 64)) } | Should -Not -Throw
		{ Assert-ToolchainPinnedK0sImage -Image 'docker.io/k0sproject/k0s' } | Should -Throw
		{ Assert-ToolchainPinnedK0sImage -Image 'docker.io/k0sproject/k0s:latest' } | Should -Throw
	}

	It 'requires Docker to report Linux containers' {
		Mock Get-ToolchainClusterExecutable { 'docker' }
		Mock Invoke-ToolchainClusterProcess { New-TestClusterProcessResult -Output @('windows') }
		{ Assert-ToolchainDockerReady } | Should -Throw '*Linux containers*'
	}

	It 'returns Docker when its Linux daemon is ready' {
		Mock Get-ToolchainClusterExecutable { 'docker' }
		Mock Invoke-ToolchainClusterProcess { New-TestClusterProcessResult -Output @('linux') }
		Assert-ToolchainDockerReady | Should -Be 'docker'
	}

	It 'selects the first ready supported container engine' {
		Mock Get-Command {
			if ($Name -eq 'podman') { [pscustomobject]@{ Source = 'podman.exe' } }
		} -ParameterFilter { $Name -in @('docker','podman','nerdctl') }
		Mock Invoke-ToolchainClusterProcess { New-TestClusterProcessResult -Output @('linux') }

		$engine = Resolve-ToolchainContainerEngine -Provider kind
		$engine.Name | Should -Be 'podman'
		$engine.Path | Should -Be 'podman.exe'
	}

	It 'rejects a non-Linux engine and unsupported k3d engines' {
		Mock Get-Command { [pscustomobject]@{ Source = "$Name.exe" } } -ParameterFilter { $Name -in @('docker','podman','nerdctl') }
		Mock Invoke-ToolchainClusterProcess { New-TestClusterProcessResult -Output @('windows') }
		{ Resolve-ToolchainContainerEngine -Engine docker -Provider kind } | Should -Throw '*no ready Linux container engine*'
		{ Resolve-ToolchainContainerEngine -Engine nerdctl -Provider k3s } | Should -Throw '*no ready Linux container engine*'
	}

	It 'requires the Podman API socket for k3d' {
		$previousDockerHost = $env:DOCKER_HOST
		$env:DOCKER_HOST = $null
		Mock Get-Command { [pscustomobject]@{ Source = 'podman.exe' } } -ParameterFilter { $Name -eq 'podman' }
		Mock Invoke-ToolchainClusterProcess { New-TestClusterProcessResult -Output @('linux') }
		try {
			{ Resolve-ToolchainContainerEngine -Engine podman -Provider k3s } | Should -Throw '*DOCKER_HOST*'
		} finally { $env:DOCKER_HOST = $previousDockerHost }
	}

	It 'provisions a missing provider executable from the Toolchains catalog' {
		$script:clusterCommandChecks = 0
		$script:catalogRefreshDuringResolve = $null
		$previousCatalogRefresh = $env:TOOLCHAIN_CATALOG_REFRESH
		$env:TOOLCHAIN_CATALOG_REFRESH = 'previous-value'
		Mock Get-Command {
			$script:clusterCommandChecks++
			if ($script:clusterCommandChecks -gt 1) { return [pscustomobject]@{ Source = 'C:\toolchain\kind.exe' } }
			return $null
		} -ParameterFilter { $Name -eq 'kind' }
		Mock ResolvePackage {
			$script:catalogRefreshDuringResolve = $env:TOOLCHAIN_CATALOG_REFRESH
			return @{ Package = 'kind'; Tag = @{ Latest = $true }; Digest = 'sha256:test' }
		}
		Mock LoadPackage {}

		try {
			Get-ToolchainClusterExecutable -Name kind -Package kind -InstallHint 'Install kind.' | Should -Be 'C:\toolchain\kind.exe'
			$script:catalogRefreshDuringResolve | Should -Be '1'
			$env:TOOLCHAIN_CATALOG_REFRESH | Should -Be 'previous-value'
			Should -Invoke ResolvePackage -Times 1 -ParameterFilter { $Ref -in @('kind', 'kind-linux') }
			Should -Invoke LoadPackage -Times 1
		} finally {
			$env:TOOLCHAIN_CATALOG_REFRESH = $previousCatalogRefresh
		}
	}

	It 'routes native cluster initialization without invoking a provider' {
		Mock Invoke-ToolchainClusterInit { 'initialized' }
		Invoke-ToolchainCluster -Command init -Name dev -Confirm -Components git-server -AgentMutationPolicy labeled -PassThru | Should -Be 'initialized'
		Should -Invoke Publish-ToolchainLocalAgentImage -Times 1 -Exactly -ParameterFilter { $Name -eq 'dev' }
		Should -Invoke Invoke-ToolchainClusterInit -Times 1 -Exactly -ParameterFilter {
			$Name -eq 'dev' -and $Confirm -and $Components -contains 'git-server' -and $AgentMutationPolicy -eq 'labeled' -and
			$AgentImage -eq 'toolchain-agent:2.4.0-local-test' -and $PassThru
		}
	}

	It 'uses the selected managed cluster for initialization and its local agent build' {
		Mock Get-ToolchainCurrentClusterContext { [pscustomobject]@{ Name = 'dev'; Provider = 'k3s'; Kubeconfig = 'managed.yaml' } }
		Mock Invoke-ToolchainClusterInit {}

		Invoke-ToolchainCluster -Command init -Confirm -Components none

		Should -Invoke Publish-ToolchainLocalAgentImage -Times 1 -Exactly -ParameterFilter { $Name -eq 'dev' }
		Should -Invoke Invoke-ToolchainClusterInit -Times 1 -Exactly -ParameterFilter {
			$Name -eq 'dev' -and $AgentImage -eq 'toolchain-agent:2.4.0-local-test'
		}
	}

	It 'honors an explicit agent image without building locally' {
		Mock Invoke-ToolchainClusterInit {}

		Invoke-ToolchainCluster -Command init -Name dev -Confirm -Components none -AgentImage 'registry.example/agent:1'

		Should -Invoke Publish-ToolchainLocalAgentImage -Times 0 -Exactly
		Should -Invoke Invoke-ToolchainClusterInit -Times 1 -Exactly -ParameterFilter { $AgentImage -eq 'registry.example/agent:1' }
	}

	It 'preserves interactive component selection when Components is omitted' {
		$script:clusterInitShouldPrompt = $null
		Mock Invoke-ToolchainClusterInit {
			param([switch]$PromptForComponents)
			$script:clusterInitShouldPrompt = [bool]$PromptForComponents
		}

		Invoke-ToolchainCluster -Command init -Name dev -Confirm
		$script:clusterInitShouldPrompt | Should -BeTrue

		Invoke-ToolchainCluster -Command init -Name dev -Confirm -Components none
		$script:clusterInitShouldPrompt | Should -BeFalse
	}
}

Describe 'Toolchain local cluster agent image' {
	It 'derives a repeatable content-addressed local image tag' {
		$context = Join-Path $TestDrive 'agent'
		New-Item -Path $context -ItemType Directory | Out-Null
		foreach ($fileName in @('Dockerfile', 'go.mod', 'main.go')) {
			[IO.File]::WriteAllText((Join-Path $context $fileName), $fileName, [Text.UTF8Encoding]::new($false))
		}

		$first = Get-ToolchainLocalAgentImage -BuildContext $context
		$second = Get-ToolchainLocalAgentImage -BuildContext $context
		$first | Should -BeExactly $second
		$first | Should -Match '^toolchain-agent:[0-9.]+-local-[0-9a-f]{12}$'

		[IO.File]::AppendAllText((Join-Path $context 'main.go'), 'changed')
		(Get-ToolchainLocalAgentImage -BuildContext $context) | Should -Not -BeExactly $first
	}

	It 'builds and imports the local agent into a managed K3s cluster' {
		Mock Read-ToolchainClusterState { [pscustomobject]@{ name = 'dev'; provider = 'k3s'; engine = 'docker' } }
		Mock Resolve-ToolchainContainerEngine { [pscustomobject]@{ Name = 'docker'; Path = 'docker.exe' } }
		Mock Resolve-ToolchainAgentBuildContext { 'C:\agent' }
		Mock Get-ToolchainLocalAgentImage { 'toolchain-agent:2.4.0-local-test' }
		Mock Get-ToolchainClusterExecutable { 'k3d.exe' }
		Mock Invoke-ToolchainClusterProcess { New-TestClusterProcessResult }

		Publish-ToolchainLocalAgentImage -Name dev | Should -BeExactly 'toolchain-agent:2.4.0-local-test'

		Should -Invoke Invoke-ToolchainClusterProcess -Times 1 -Exactly -ParameterFilter {
			$FilePath -eq 'docker.exe' -and ($Arguments -join ' ') -eq 'build --tag toolchain-agent:2.4.0-local-test C:\agent'
		}
		Should -Invoke Invoke-ToolchainClusterProcess -Times 1 -Exactly -ParameterFilter {
			$FilePath -eq 'k3d.exe' -and ($Arguments -join ' ') -eq 'image import toolchain-agent:2.4.0-local-test --cluster dev'
		}
	}
}

Describe 'Toolchain cluster lifecycle' {
	BeforeEach {
		$case = 'case-' + [guid]::NewGuid().ToString('n')
		$script:clusterRoot = Join-Path $TestDrive $case
		$script:clusterCalls = [Collections.Generic.List[object]]::new()
		$script:previousKubeconfig = $env:KUBECONFIG
		Remove-Item Env:KUBECONFIG -ErrorAction SilentlyContinue
		Mock GetToolchainPath { $script:clusterRoot }
		Mock Resolve-ToolchainContainerEngine { [pscustomobject]@{ Name = 'docker'; Path = 'docker' } }
		Mock Get-ToolchainClusterExecutable { param($Name, $InstallHint) $Name }
		Mock Invoke-ToolchainClusterProcess {
			param($FilePath, $Arguments, [switch]$AllowFailure)
			$script:clusterCalls.Add([pscustomobject]@{ FilePath = $FilePath; Arguments = [string[]]$Arguments; AllowFailure = [bool]$AllowFailure })
			$joined = $Arguments -join ' '
			if ($FilePath -eq 'kind' -and $joined -like 'create cluster*') {
				$path = Get-TestClusterArgumentValue -Arguments $Arguments -Name '--kubeconfig'
				[IO.File]::WriteAllText($path, "apiVersion: v1`nkind: Config`n")
			}
			if ($FilePath -eq 'kind' -and $joined -eq 'get clusters') { return (New-TestClusterProcessResult -Output @('dev')) }
			if ($FilePath -eq 'k3d' -and $joined -like 'kubeconfig get *') {
				return (New-TestClusterProcessResult -Output @('apiVersion: v1', 'clusters: []'))
			}
			if ($FilePath -eq 'k3d' -and $joined -eq 'cluster list --no-headers') {
				return (New-TestClusterProcessResult -Output @('dev 1/1 1/1'))
			}
			if ($FilePath -eq 'docker' -and $joined -like 'exec * k0s kubectl get --raw=/readyz') {
				return (New-TestClusterProcessResult -Output @('ok'))
			}
			if ($FilePath -eq 'docker' -and $joined -like 'port * 6443/tcp') {
				return (New-TestClusterProcessResult -Output @('127.0.0.1:49152'))
			}
			if ($FilePath -eq 'docker' -and $joined -like 'exec * cat /var/lib/k0s/pki/admin.conf') {
				return (New-TestClusterProcessResult -Output @('apiVersion: v1', 'clusters:', '- cluster:', '    server: https://localhost:6443'))
			}
			if ($FilePath -eq 'docker' -and $joined -like 'inspect --format*') {
				return (New-TestClusterProcessResult -Output @('running'))
			}
			return (New-TestClusterProcessResult)
		}
	}

	AfterEach {
		if ($null -eq $script:previousKubeconfig) {
			Remove-Item Env:KUBECONFIG -ErrorAction SilentlyContinue
		} else {
			$env:KUBECONFIG = $script:previousKubeconfig
		}
	}

	It 'creates a multi-node kind cluster with isolated kubeconfig and generated config' {
		$result = Invoke-ToolchainCluster -Command create -Name dev -Provider kind -Servers 2 -Workers 1 -ApiPort 6443 -Image 'kindest/node:v1.34.0'

		$result.Name | Should -Be 'dev'
		$result.Provider | Should -Be 'kind'
		$result.Status | Should -Be 'Running'
		Test-Path -LiteralPath $result.Kubeconfig -PathType Leaf | Should -BeTrue
		$create = $script:clusterCalls | Where-Object { $_.FilePath -eq 'kind' -and $_.Arguments[0] -eq 'create' } | Select-Object -First 1
		$create.Arguments | Should -Contain '--kubeconfig'
		$create.Arguments | Should -Contain '--image'
		$configPath = Get-TestClusterArgumentValue -Arguments $create.Arguments -Name '--config'
		$config = Get-Content -LiteralPath $configPath -Raw
		([regex]::Matches($config, 'role: control-plane')).Count | Should -Be 2
		([regex]::Matches($config, 'role: worker')).Count | Should -Be 1
		$config | Should -Match 'apiServerAddress: "127\.0\.0\.1"'
	}

	It 'creates a k3s cluster through k3d without changing the default kubeconfig' {
		$result = Invoke-ToolchainCluster -Command create -Name dev -Provider k3s -Workers 2 -ApiPort 6550 -Image 'rancher/k3s:v1.33.3-k3s1'

		$result.Provider | Should -Be 'k3s'
		$create = $script:clusterCalls | Where-Object { $_.FilePath -eq 'k3d' -and ($_.Arguments -join ' ') -like 'cluster create*' } | Select-Object -First 1
		$create.Arguments | Should -Contain '--kubeconfig-update-default=false'
		$create.Arguments | Should -Contain '--kubeconfig-switch-context=false'
		(Get-TestClusterArgumentValue -Arguments $create.Arguments -Name '--agents') | Should -Be '2'
		(Get-TestClusterArgumentValue -Arguments $create.Arguments -Name '--api-port') | Should -Be '127.0.0.1:6550'
		Get-Content -LiteralPath $result.Kubeconfig -Raw | Should -Match 'apiVersion: v1'
	}

	It 'creates a single-node k0s cluster with localhost-only API access' {
		$result = Invoke-ToolchainCluster -Command create -Name dev -Provider k0s -Image 'docker.io/k0sproject/k0s:v1.32.4-k0s.0'

		$result.Provider | Should -Be 'k0s'
		$run = $script:clusterCalls | Where-Object { $_.FilePath -eq 'docker' -and $_.Arguments[0] -eq 'run' } | Select-Object -First 1
		$run.Arguments | Should -Contain '--privileged'
		$run.Arguments | Should -Contain '127.0.0.1::6443'
		$run.Arguments | Should -Contain 'io.allsagetech.toolchain.provider=k0s'
		Get-Content -LiteralPath $result.Kubeconfig -Raw | Should -Match 'server: https://127\.0\.0\.1:49152'
	}

	It 'requires an explicitly versioned image for k0s' {
		{ Invoke-ToolchainCluster -Command create -Name dev -Provider k0s } | Should -Throw '*requires -Image*'
		{ Invoke-ToolchainCluster -Command create -Name dev -Provider k0s -Image 'docker.io/k0sproject/k0s:latest' } | Should -Throw '*non-latest*'
		Should -Invoke -CommandName Resolve-ToolchainContainerEngine -Times 0
	}

	It 'rejects unsupported k0s topologies' {
		{ Invoke-ToolchainCluster -Command create -Name dev -Provider k0s -Image 'k0s:v1' -Workers 1 } | Should -Throw '*one combined controller/worker*'
	}

	It 'does not overwrite existing Toolchain cluster state' {
		$null = Invoke-ToolchainCluster -Command create -Name dev -Provider kind
		{ Invoke-ToolchainCluster -Command create -Name dev -Provider kind } | Should -Throw '*already exists*'
	}

	It 'does not overwrite an orphaned non-empty cluster state directory' {
		$directory = Get-ToolchainClusterDirectory -Name dev
		[void][IO.Directory]::CreateDirectory($directory)
		[IO.File]::WriteAllText((Join-Path $directory 'kubeconfig.yaml'), 'existing')
		{ Invoke-ToolchainCluster -Command create -Name dev -Provider kind } | Should -Throw '*not empty*'
		Should -Invoke -CommandName Resolve-ToolchainContainerEngine -Times 0
	}

	It 'does not combine provider configs with topology flags' {
		$config = Join-Path $TestDrive 'kind.yaml'
		[IO.File]::WriteAllText($config, "kind: Cluster`n")
		{ Invoke-ToolchainCluster -Command create -Name dev -Provider kind -Config $config -Workers 1 } | Should -Throw '*cannot be combined*'
	}

	It 'lists and reports runtime status from managed state' {
		$null = Invoke-ToolchainCluster -Command create -Name dev -Provider kind

		$list = @(Invoke-ToolchainCluster -Command list)
		$list.Count | Should -Be 1
		$list[0].Status | Should -Be 'Running'
		(Invoke-ToolchainCluster -Command status -Name dev).Provider | Should -Be 'kind'
	}

	It 'returns the kubeconfig path or raw contents without merging it' {
		$result = Invoke-ToolchainCluster -Command create -Name dev -Provider kind

		Invoke-ToolchainCluster -Command kubeconfig -Name dev | Should -Be $result.Kubeconfig
		Invoke-ToolchainCluster -Command kubeconfig -Name dev -Raw | Should -Match 'kind: Config'
	}

	It 'switches between isolated managed kubeconfigs in the current process' {
		$dev = Invoke-ToolchainCluster -Command create -Name dev -Provider kind
		$null = Invoke-ToolchainCluster -Command create -Name qa -Provider kind

		$selected = Invoke-ToolchainCluster -Command use -Name dev -PassThru
		$env:KUBECONFIG | Should -BeExactly ([IO.Path]::GetFullPath($dev.Kubeconfig))
		$selected.Name | Should -Be 'dev'
		$selected.Provider | Should -Be 'kind'
		Invoke-ToolchainCluster -Command current | Should -Be 'dev'

		$null = Invoke-ToolchainCluster -Command use -Name qa
		$current = Invoke-ToolchainCluster -Command current -PassThru
		$current.Name | Should -Be 'qa'
		$current.Kubeconfig | Should -BeExactly $env:KUBECONFIG
	}

	It 'rejects unknown and non-managed cluster selections' {
		{ Invoke-ToolchainCluster -Command use -Name missing } | Should -Throw '*not found*'
		{ Invoke-ToolchainCluster -Command current } | Should -Throw '*no Toolchain-managed cluster*'
		$env:KUBECONFIG = Join-Path $TestDrive 'external.yaml'
		{ Invoke-ToolchainCluster -Command current } | Should -Throw '*does not select exactly one*'
		$env:KUBECONFIG = "a$([IO.Path]::PathSeparator)b"
		{ Invoke-ToolchainCluster -Command current } | Should -Throw '*does not select exactly one*'
	}

	It 'deletes the provider cluster before removing local state' {
		$result = Invoke-ToolchainCluster -Command create -Name dev -Provider kind
		$null = Invoke-ToolchainCluster -Command use -Name dev

		Invoke-ToolchainCluster -Command delete -Name dev

		Test-Path -LiteralPath (Split-Path -Parent $result.Kubeconfig) | Should -BeFalse
		$env:KUBECONFIG | Should -BeNullOrEmpty
		$delete = $script:clusterCalls | Where-Object { $_.FilePath -eq 'kind' -and ($_.Arguments -join ' ') -eq 'delete cluster --name dev' }
		@($delete).Count | Should -Be 1
	}

	It 'removes a k0s container with its anonymous volumes' {
		$null = Invoke-ToolchainCluster -Command create -Name dev -Provider k0s -Image 'k0s:v1'
		Invoke-ToolchainCluster -Command delete -Name dev

		$remove = $script:clusterCalls | Where-Object { $_.FilePath -eq 'docker' -and ($_.Arguments -join ' ') -eq 'rm -f -v toolchain-k0s-dev' }
		@($remove).Count | Should -Be 1
	}

	It 'rejects tampered cluster state identity' {
		$null = Invoke-ToolchainCluster -Command create -Name dev -Provider kind
		$path = Get-ToolchainClusterStatePath -Name dev
		$state = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
		$state.name = 'other'
		[IO.File]::WriteAllText($path, ($state | ConvertTo-Json -Depth 10), [Text.UTF8Encoding]::new($false))
		{ Invoke-ToolchainCluster -Command status -Name dev } | Should -Throw '*invalid cluster state identity*'
	}
}
