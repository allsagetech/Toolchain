<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

function Get-ToolchainClusterRoot {
	return (Join-Path (GetToolchainPath) 'clusters')
}

function Assert-ToolchainClusterName {
	param([Parameter(Mandatory)][string]$Name)

	if ($Name.Length -gt 63 -or $Name -cnotmatch '^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$') {
		throw "cluster name must be a lowercase DNS label of 1-63 characters: $Name"
	}
}

function Assert-ToolchainClusterImage {
	param([Parameter(Mandatory)][string]$Image)

	if ([string]::IsNullOrWhiteSpace($Image) -or $Image -match '[\s\x00-\x1f]') {
		throw "invalid cluster image reference: $Image"
	}
}

function Assert-ToolchainPinnedK0sImage {
	param([Parameter(Mandatory)][string]$Image)

	if ($Image -match '(?i)@sha256:[0-9a-f]{64}$') { return }
	$lastSlash = [Math]::Max($Image.LastIndexOf('/'), $Image.LastIndexOf('\'))
	$lastColon = $Image.LastIndexOf(':')
	if ($lastColon -le $lastSlash -or $lastColon -eq ($Image.Length - 1) -or $Image.Substring($lastColon + 1) -ieq 'latest') {
		throw "k0s image must use an explicit non-latest tag or sha256 digest: $Image"
	}
}

function Get-ToolchainClusterDirectory {
	param([Parameter(Mandatory)][string]$Name)

	Assert-ToolchainClusterName -Name $Name
	return (Resolve-ToolchainChildPath -Root (Get-ToolchainClusterRoot) -RelativePath $Name -RejectReparsePoints -RejectRootReparsePoint)
}

function Get-ToolchainClusterStatePath {
	param([Parameter(Mandatory)][string]$Name)
	return (Join-Path (Get-ToolchainClusterDirectory -Name $Name) 'cluster.json')
}

function Get-ToolchainClusterKubeconfigPath {
	param([Parameter(Mandatory)][string]$Name)
	return (Join-Path (Get-ToolchainClusterDirectory -Name $Name) 'kubeconfig.yaml')
}

function Write-ToolchainClusterTextFile {
	param(
		[Parameter(Mandatory)][string]$Path,
		[Parameter(Mandatory)][AllowEmptyString()][string]$Content
	)
	[IO.File]::WriteAllText($Path, $Content, [Text.UTF8Encoding]::new($false))
}

function Get-ToolchainClusterExecutable {
	param(
		[Parameter(Mandatory)][string]$Name,
		[Parameter(Mandatory)][string]$InstallHint,
		[string]$Package
	)

	$command = Get-Command -Name $Name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
	if (-not $command -and $Package) {
		$packageName = if ([Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::Windows)) {
			$Package
		} elseif ([Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::Linux)) {
			"$Package-linux"
		} else {
			$null
		}

		if ($packageName) {
			$previousCatalogRefresh = $env:TOOLCHAIN_CATALOG_REFRESH
			try {
				Write-ToolchainInfo "Provisioning cluster dependency '$packageName' through Toolchain."
				# Cluster providers are provisioned only after a PATH miss. Force a fresh
				# catalog lookup so a newly published provider is not hidden by the normal
				# remote-tag cache.
				$env:TOOLCHAIN_CATALOG_REFRESH = '1'
				$resolved = ResolvePackage -Ref $packageName
				LoadPackage -Pkg $resolved
				$command = Get-Command -Name $Name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
			} catch {
				throw "$Name executable was not found on PATH and Toolchain could not provision package '$packageName': $($_.Exception.Message)"
			} finally {
				$env:TOOLCHAIN_CATALOG_REFRESH = $previousCatalogRefresh
			}
		}
	}
	if (-not $command) {
		throw "$Name executable was not found on PATH. $InstallHint"
	}
	return $command.Source
}

function Invoke-ToolchainClusterProcess {
	param(
		[Parameter(Mandatory)][string]$FilePath,
		[Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Arguments,
		[switch]$AllowFailure
	)

	$output = @(& $FilePath @Arguments 2>&1 | ForEach-Object { [string]$_ })
	$exitCode = $LASTEXITCODE
	if ($null -eq $exitCode) { $exitCode = 0 }
	$result = [pscustomobject]@{
		ExitCode = [int]$exitCode
		Output = [string[]]$output
	}
	if ($result.ExitCode -ne 0 -and -not $AllowFailure) {
		$message = ($result.Output -join [Environment]::NewLine).Trim()
		if (-not $message) { $message = 'no diagnostic output' }
		throw "$([IO.Path]::GetFileName($FilePath)) $($Arguments -join ' ') failed with exit code $($result.ExitCode): $message"
	}
	return $result
}

function Resolve-ToolchainContainerEngine {
	param(
		[ValidateSet('auto', 'docker', 'podman', 'nerdctl')]
		[string]$Engine = 'auto',
		[ValidateSet('kind', 'k0s', 'k3s')]
		[string]$Provider = 'kind'
	)

	$candidates = if ($Engine -eq 'auto') { @('docker', 'podman', 'nerdctl') } else { @($Engine) }
	if ($Provider -eq 'k3s') { $candidates = @($candidates | Where-Object { $_ -in @('docker', 'podman') }) }
	foreach ($candidate in $candidates) {
		$command = Get-Command -Name $candidate -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
		if (-not $command) { continue }
		$arguments = if ($candidate -eq 'docker') { @('info', '--format', '{{.OSType}}') } elseif ($candidate -eq 'podman') { @('info', '--format', '{{.Host.OS}}') } else { @('info') }
		$result = Invoke-ToolchainClusterProcess -FilePath $command.Source -Arguments $arguments -AllowFailure
		if ($result.ExitCode -ne 0) { continue }
		if ($candidate -ne 'nerdctl') {
			$osType = ($result.Output -join '').Trim()
			if ($osType -and $osType -ine 'linux') { continue }
		}
		if ($Provider -eq 'k3s' -and $candidate -eq 'podman' -and -not $env:DOCKER_HOST) {
			throw 'k3d Podman support requires the Podman API service and DOCKER_HOST pointing to its socket.'
		}
		return [pscustomobject]@{ Name = $candidate; Path = [string]$command.Source }
	}
	$requested = if ($Engine -eq 'auto') { 'Docker, Podman, or nerdctl' } else { $Engine }
	throw "no ready Linux container engine was found for $Provider; install and start $requested"
}

function Assert-ToolchainDockerReady {
	# Retained as an internal compatibility shim for callers that explicitly require
	# Docker. New cluster creation uses Resolve-ToolchainContainerEngine so that
	# Podman and nerdctl can be selected as well.
	$docker = Get-ToolchainClusterExecutable -Name 'docker' -InstallHint 'Install and start Docker Desktop or Docker Engine.'
	$result = Invoke-ToolchainClusterProcess -FilePath $docker -Arguments @('info', '--format', '{{.OSType}}') -AllowFailure
	$osType = ($result.Output -join '').Trim()
	if ($result.ExitCode -ne 0 -or $osType -ine 'linux') {
		throw 'Docker must be running Linux containers before a local cluster can be created.'
	}
	return $docker
}

function Invoke-ToolchainKindProcess {
	param(
		[Parameter(Mandatory)][string]$FilePath,
		[Parameter(Mandatory)][string[]]$Arguments,
		[Parameter(Mandatory)][string]$Engine,
		[switch]$AllowFailure
	)
	$previous = $env:KIND_EXPERIMENTAL_PROVIDER
	try {
		$env:KIND_EXPERIMENTAL_PROVIDER = $Engine
		return (Invoke-ToolchainClusterProcess -FilePath $FilePath -Arguments $Arguments -AllowFailure:$AllowFailure)
	} finally { $env:KIND_EXPERIMENTAL_PROVIDER = $previous }
}

function Resolve-ToolchainClusterConfigPath {
	param([Parameter(Mandatory)][string]$Path)
	$resolved = Resolve-Path -LiteralPath $Path -ErrorAction Stop
	if (-not (Test-Path -LiteralPath $resolved.Path -PathType Leaf)) {
		throw "cluster config is not a file: $Path"
	}
	return $resolved.Path
}

function Write-ToolchainKindConfig {
	param(
		[Parameter(Mandatory)][string]$Path,
		[Parameter(Mandatory)][int]$Servers,
		[Parameter(Mandatory)][int]$Workers,
		[Parameter(Mandatory)][int]$ApiPort
	)

	$lines = @('kind: Cluster', 'apiVersion: kind.x-k8s.io/v1alpha4')
	if ($ApiPort -gt 0) {
		$lines += @('networking:', '  apiServerAddress: "127.0.0.1"', "  apiServerPort: $ApiPort")
	}
	$lines += 'nodes:'
	for ($i = 0; $i -lt $Servers; $i++) { $lines += '- role: control-plane' }
	for ($i = 0; $i -lt $Workers; $i++) { $lines += '- role: worker' }
	Write-ToolchainClusterTextFile -Path $Path -Content (($lines -join "`n") + "`n")
}

function Remove-ToolchainClusterDirectory {
	param([Parameter(Mandatory)][string]$Name)

	$directory = Get-ToolchainClusterDirectory -Name $Name
	if (-not (Test-Path -LiteralPath $directory -PathType Container)) { return }
	$item = Get-Item -LiteralPath $directory -Force
	if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
		throw "refusing to remove cluster state through a link or reparse point: $directory"
	}
	$allowed = @('cluster.json', 'kubeconfig.yaml', 'kind.generated.yaml')
	$children = @(Get-ChildItem -LiteralPath $directory -Force)
	foreach ($child in $children) {
		if ($child.PSIsContainer -or ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $child.Name -notin $allowed) {
			throw "refusing to remove cluster state containing unexpected entry: $($child.FullName)"
		}
	}
	foreach ($child in $children) { [IO.File]::Delete($child.FullName) }
	[IO.Directory]::Delete($directory, $false)
}

function Write-ToolchainClusterState {
	param(
		[Parameter(Mandatory)][string]$Name,
		[Parameter(Mandatory)][ValidateSet('kind', 'k0s', 'k3s')][string]$Provider,
		[Parameter(Mandatory)][int]$Servers,
		[Parameter(Mandatory)][int]$Workers,
		[string]$Image,
		[string]$Engine = 'docker'
	)

	$directory = Get-ToolchainClusterDirectory -Name $Name
	[void][IO.Directory]::CreateDirectory($directory)
	$path = Get-ToolchainClusterStatePath -Name $Name
	if (Test-Path -LiteralPath $path) { throw "cluster state already exists: $Name" }
	$state = [ordered]@{
		schemaVersion = 1
		name = $Name
		provider = $Provider
		engine = $Engine
		createdAt = [datetime]::UtcNow.ToString('o')
		servers = $Servers
		workers = $Workers
		image = if ($Image) { $Image } else { $null }
	}
	$temp = Join-Path $directory ('.cluster.' + [guid]::NewGuid().ToString('n') + '.tmp')
	try {
		Write-ToolchainClusterTextFile -Path $temp -Content ($state | ConvertTo-Json)
		[IO.File]::Move($temp, $path)
	} finally {
		if (Test-Path -LiteralPath $temp -PathType Leaf) { [IO.File]::Delete($temp) }
	}
}

function Read-ToolchainClusterState {
	param([Parameter(Mandatory)][string]$Name)

	$path = Get-ToolchainClusterStatePath -Name $Name
	if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
	try {
		$state = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
	} catch {
		throw "invalid cluster state for '$Name': $($_.Exception.Message)"
	}
	if ([int]$state.schemaVersion -ne 1 -or [string]$state.name -cne $Name -or [string]$state.provider -notin @('kind', 'k0s', 'k3s')) {
		throw "invalid cluster state identity for '$Name'"
	}
	return $state
}

function Get-ToolchainClusterStates {
	$root = Get-ToolchainClusterRoot
	if (-not (Test-Path -LiteralPath $root -PathType Container)) { return @() }
	$states = @()
	foreach ($directory in @(Get-ChildItem -LiteralPath $root -Directory -Force | Sort-Object Name)) {
		try {
			Assert-ToolchainClusterName -Name $directory.Name
			$state = Read-ToolchainClusterState -Name $directory.Name
			if ($state) { $states += $state }
		} catch {
			Write-Warning "Skipping cluster state '$($directory.Name)': $($_.Exception.Message)"
		}
	}
	return $states
}

function New-ToolchainKindCluster {
	param(
		[Parameter(Mandatory)][string]$Name,
		[Parameter(Mandatory)][string]$Kubeconfig,
		[Parameter(Mandatory)][int]$Servers,
		[Parameter(Mandatory)][int]$Workers,
		[Parameter(Mandatory)][int]$ApiPort,
		[Parameter(Mandatory)][int]$WaitSeconds,
		[string]$Image,
		[string]$Config,
		[string]$Engine = 'docker'
	)

	$kind = Get-ToolchainClusterExecutable -Name 'kind' -Package 'kind' -InstallHint 'Install kind and ensure its executable is available on PATH.'
	$args = @('create', 'cluster', '--name', $Name, '--kubeconfig', $Kubeconfig, '--wait', "${WaitSeconds}s")
	$configPath = $null
	if ($Config) {
		$configPath = Resolve-ToolchainClusterConfigPath -Path $Config
	} elseif ($Servers -ne 1 -or $Workers -ne 0 -or $ApiPort -gt 0) {
		$configPath = Join-Path (Get-ToolchainClusterDirectory -Name $Name) 'kind.generated.yaml'
		Write-ToolchainKindConfig -Path $configPath -Servers $Servers -Workers $Workers -ApiPort $ApiPort
	}
	if ($configPath) { $args += @('--config', $configPath) }
	if ($Image) { $args += @('--image', $Image) }

	$created = $false
	try {
		$null = Invoke-ToolchainKindProcess -FilePath $kind -Arguments $args -Engine $Engine
		$created = $true
		if (-not (Test-Path -LiteralPath $Kubeconfig -PathType Leaf)) {
			throw 'kind reported success but did not write the requested kubeconfig'
		}
	} catch {
		if ($created) {
			$null = Invoke-ToolchainKindProcess -FilePath $kind -Arguments @('delete', 'cluster', '--name', $Name) -Engine $Engine -AllowFailure
		}
		throw
	}
}

function New-ToolchainK3dCluster {
	param(
		[Parameter(Mandatory)][string]$Name,
		[Parameter(Mandatory)][string]$Kubeconfig,
		[Parameter(Mandatory)][int]$Servers,
		[Parameter(Mandatory)][int]$Workers,
		[Parameter(Mandatory)][int]$ApiPort,
		[Parameter(Mandatory)][int]$WaitSeconds,
		[string]$Image,
		[string]$Config
	)

	$k3d = Get-ToolchainClusterExecutable -Name 'k3d' -Package 'k3d' -InstallHint 'Install k3d and ensure its executable is available on PATH.'
	$args = @('cluster', 'create', $Name, '--wait', '--timeout', "${WaitSeconds}s", '--kubeconfig-update-default=false', '--kubeconfig-switch-context=false')
	if ($Config) {
		$args += @('--config', (Resolve-ToolchainClusterConfigPath -Path $Config))
	} else {
		$args += @('--servers', [string]$Servers, '--agents', [string]$Workers)
		if ($ApiPort -gt 0) { $args += @('--api-port', "127.0.0.1:$ApiPort") }
	}
	if ($Image) { $args += @('--image', $Image) }

	$created = $false
	try {
		$null = Invoke-ToolchainClusterProcess -FilePath $k3d -Arguments $args
		$created = $true
		$result = Invoke-ToolchainClusterProcess -FilePath $k3d -Arguments @('kubeconfig', 'get', $Name)
		$content = ($result.Output -join "`n").Trim()
		if (-not $content) { throw 'k3d returned an empty kubeconfig' }
		Write-ToolchainClusterTextFile -Path $Kubeconfig -Content ($content + "`n")
	} catch {
		if ($created) {
			$null = Invoke-ToolchainClusterProcess -FilePath $k3d -Arguments @('cluster', 'delete', $Name) -AllowFailure
		}
		throw
	}
}

function Set-ToolchainK0sKubeconfigServer {
	param(
		[Parameter(Mandatory)][string]$Content,
		[Parameter(Mandatory)][int]$Port
	)

	$match = [regex]::Match($Content, '(?m)^(\s*server:\s*)\S+\s*$')
	if (-not $match.Success) { throw 'k0s admin kubeconfig did not contain a server entry' }
	$replacement = $match.Groups[1].Value + "https://127.0.0.1:$Port"
	return $Content.Substring(0, $match.Index) + $replacement + $Content.Substring($match.Index + $match.Length)
}

function New-ToolchainK0sCluster {
	param(
		[Parameter(Mandatory)][string]$ContainerEngine,
		[Parameter(Mandatory)][string]$Name,
		[Parameter(Mandatory)][string]$Kubeconfig,
		[Parameter(Mandatory)][int]$ApiPort,
		[Parameter(Mandatory)][int]$WaitSeconds,
		[Parameter(Mandatory)][string]$Image
	)

	$container = "toolchain-k0s-$Name"
	$publish = if ($ApiPort -gt 0) { "127.0.0.1:${ApiPort}:6443" } else { '127.0.0.1::6443' }
	$args = @(
		'run', '-d', '--name', $container, '--hostname', $container,
		'--label', "io.allsagetech.toolchain.cluster=$Name",
		'--label', 'io.allsagetech.toolchain.provider=k0s',
		'--privileged', '--tmpfs', '/run', '-v', '/var/lib/k0s', '-v', '/var/log/pods',
		'-p', $publish, $Image
	)
	$created = $false
	try {
		$null = Invoke-ToolchainClusterProcess -FilePath $ContainerEngine -Arguments $args
		$created = $true
		$deadline = [datetime]::UtcNow.AddSeconds($WaitSeconds)
		$ready = $false
		do {
			$check = Invoke-ToolchainClusterProcess -FilePath $ContainerEngine -Arguments @('exec', $container, 'k0s', 'kubectl', 'get', '--raw=/readyz') -AllowFailure
			if ($check.ExitCode -eq 0) { $ready = $true; break }
			if ([datetime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 1000 }
		} while ([datetime]::UtcNow -lt $deadline)
		if (-not $ready) { throw "k0s cluster did not become ready within $WaitSeconds seconds" }

		$portResult = Invoke-ToolchainClusterProcess -FilePath $ContainerEngine -Arguments @('port', $container, '6443/tcp')
		$portText = ([string]($portResult.Output | Select-Object -First 1)).Trim()
		if ($portText -notmatch ':(?<Port>\d+)$') { throw "could not determine k0s API port from Docker output: $portText" }
		$hostPort = [int]$Matches.Port
		$configResult = Invoke-ToolchainClusterProcess -FilePath $ContainerEngine -Arguments @('exec', $container, 'cat', '/var/lib/k0s/pki/admin.conf')
		$content = ($configResult.Output -join "`n").Trim()
		if (-not $content) { throw 'k0s returned an empty admin kubeconfig' }
		$content = Set-ToolchainK0sKubeconfigServer -Content $content -Port $hostPort
		Write-ToolchainClusterTextFile -Path $Kubeconfig -Content ($content + "`n")
	} catch {
		if ($created) {
			$null = Invoke-ToolchainClusterProcess -FilePath $ContainerEngine -Arguments @('rm', '-f', '-v', $container) -AllowFailure
		}
		throw
	}
}

function Get-ToolchainClusterRuntimeStatus {
	param([Parameter(Mandatory)]$State)

	try {
		switch ([string]$State.provider) {
			'kind' {
				$kind = Get-ToolchainClusterExecutable -Name 'kind' -Package 'kind' -InstallHint 'Install kind to inspect this cluster.'
				$engine = if ($State.engine) { [string]$State.engine } else { 'docker' }
				$result = Invoke-ToolchainKindProcess -FilePath $kind -Arguments @('get', 'clusters') -Engine $engine -AllowFailure
				if ($result.ExitCode -ne 0) { return 'Unknown' }
				if (@($result.Output | Where-Object { $_.Trim() -ceq [string]$State.name }).Count -gt 0) { return 'Running' }
				return 'Missing'
			}
			'k3s' {
				$k3d = Get-ToolchainClusterExecutable -Name 'k3d' -Package 'k3d' -InstallHint 'Install k3d to inspect this cluster.'
				$result = Invoke-ToolchainClusterProcess -FilePath $k3d -Arguments @('cluster', 'list', '--no-headers') -AllowFailure
				if ($result.ExitCode -ne 0) { return 'Unknown' }
				if (@($result.Output | Where-Object { ($_ -split '\s+')[0] -ceq [string]$State.name }).Count -gt 0) { return 'Running' }
				return 'Missing'
			}
			'k0s' {
				$engineName = if ($State.engine) { [string]$State.engine } else { 'docker' }
				$engine = Resolve-ToolchainContainerEngine -Engine $engineName -Provider k0s
				$container = "toolchain-k0s-$($State.name)"
				$result = Invoke-ToolchainClusterProcess -FilePath $engine.Path -Arguments @('inspect', '--format', '{{.State.Status}}', $container) -AllowFailure
				if ($result.ExitCode -ne 0) { return 'Missing' }
				$status = ($result.Output -join '').Trim()
				if ($status -ieq 'running') { return 'Running' }
				if ($status) { return $status.Substring(0, 1).ToUpperInvariant() + $status.Substring(1).ToLowerInvariant() }
				return 'Unknown'
			}
		}
	} catch {
		return 'Unavailable'
	}
}

function ConvertTo-ToolchainClusterObject {
	param(
		[Parameter(Mandatory)]$State,
		[string]$Status
	)
	if (-not $Status) { $Status = Get-ToolchainClusterRuntimeStatus -State $State }
	return [pscustomobject]@{
		PSTypeName = 'Toolchain.Cluster'
		Name = [string]$State.name
		Provider = [string]$State.provider
		Status = $Status
		Servers = [int]$State.servers
		Workers = [int]$State.workers
		Image = [string]$State.image
		Engine = if ($State.engine) { [string]$State.engine } else { 'docker' }
		Kubeconfig = Get-ToolchainClusterKubeconfigPath -Name ([string]$State.name)
		CreatedAt = [datetime]::Parse([string]$State.createdAt).ToLocalTime()
	}
}

function Remove-ToolchainProviderCluster {
	param(
		[Parameter(Mandatory)]$State,
		[switch]$AllowMissing
	)
	$provider = [string]$State.provider
	$name = [string]$State.name
	switch ($provider) {
		'kind' {
			$kind = Get-ToolchainClusterExecutable -Name 'kind' -Package 'kind' -InstallHint 'Install kind to delete this cluster.'
			$engine = if ($State.engine) { [string]$State.engine } else { 'docker' }
			$result = Invoke-ToolchainKindProcess -FilePath $kind -Arguments @('delete', 'cluster', '--name', $name) -Engine $engine -AllowFailure
		}
		'k3s' {
			$k3d = Get-ToolchainClusterExecutable -Name 'k3d' -Package 'k3d' -InstallHint 'Install k3d to delete this cluster.'
			$result = Invoke-ToolchainClusterProcess -FilePath $k3d -Arguments @('cluster', 'delete', $name) -AllowFailure
		}
		'k0s' {
			$engineName = if ($State.engine) { [string]$State.engine } else { 'docker' }
			$engine = Resolve-ToolchainContainerEngine -Engine $engineName -Provider k0s
			$container = "toolchain-k0s-$name"
			$inspect = Invoke-ToolchainClusterProcess -FilePath $engine.Path -Arguments @('inspect', $container) -AllowFailure
			if ($inspect.ExitCode -ne 0) { return }
			$result = Invoke-ToolchainClusterProcess -FilePath $engine.Path -Arguments @('rm', '-f', '-v', $container) -AllowFailure
		}
	}
	if ($result.ExitCode -ne 0 -and -not $AllowMissing) {
		$message = ($result.Output -join [Environment]::NewLine).Trim()
		throw "failed to delete $provider cluster '$name': $message"
	}
}

function Invoke-ToolchainCluster {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory, Position = 0)]
		[ValidateSet('create', 'list', 'status', 'kubeconfig', 'delete')]
		[string]$Command,
		[Parameter(Position = 1)]
		[string]$Name,
		[ValidateSet('kind', 'k0s', 'k3s')]
		[string]$Provider = 'kind',
		[ValidateRange(1, 9)]
		[int]$Servers = 1,
		[ValidateRange(0, 20)]
		[int]$Workers = 0,
		[ValidateRange(0, 65535)]
		[int]$ApiPort = 0,
		[ValidateRange(10, 1800)]
		[int]$WaitSeconds = 120,
		[string]$Image,
		[string]$Config,
		[ValidateSet('auto', 'docker', 'podman', 'nerdctl')]
		[string]$Engine = 'auto',
		[switch]$Raw
	)

	switch ($Command) {
		'create' {
			if (-not $Name) { throw 'cluster create requires a name' }
			Assert-ToolchainClusterName -Name $Name
			if ($Image) { Assert-ToolchainClusterImage -Image $Image }
			if ($Provider -eq 'k0s' -and -not $Image) {
				throw 'k0s cluster creation requires -Image with an explicit versioned k0s image (example: docker.io/k0sproject/k0s:v1.32.4-k0s.0)'
			}
			if ($Provider -eq 'k0s') { Assert-ToolchainPinnedK0sImage -Image $Image }
			if ($Provider -eq 'k0s' -and ($Servers -ne 1 -or $Workers -ne 0)) {
				throw 'the k0s Docker provider currently supports one combined controller/worker node; use -Servers 1 -Workers 0'
			}
			if ($Config -and $Provider -eq 'k0s') { throw '-Config is supported for kind and k3s providers, not k0s' }
			if ($Config -and ($PSBoundParameters.ContainsKey('Servers') -or $PSBoundParameters.ContainsKey('Workers') -or $PSBoundParameters.ContainsKey('ApiPort'))) {
				throw '-Config cannot be combined with -Servers, -Workers, or -ApiPort'
			}

			$statePath = Get-ToolchainClusterStatePath -Name $Name
			if (Test-Path -LiteralPath $statePath) { throw "a Toolchain cluster named '$Name' already exists" }
			$directory = Get-ToolchainClusterDirectory -Name $Name
			if (Test-Path -LiteralPath $directory -PathType Container) {
				$existing = @(Get-ChildItem -LiteralPath $directory -Force)
				if ($existing.Count -gt 0) { throw "cluster state directory is not empty: $directory" }
			}
			[void][IO.Directory]::CreateDirectory($directory)
			$kubeconfig = Get-ToolchainClusterKubeconfigPath -Name $Name
			$containerEngine = Resolve-ToolchainContainerEngine -Engine $Engine -Provider $Provider
			$created = $false
			try {
				switch ($Provider) {
					'kind' { New-ToolchainKindCluster -Name $Name -Kubeconfig $kubeconfig -Servers $Servers -Workers $Workers -ApiPort $ApiPort -WaitSeconds $WaitSeconds -Image $Image -Config $Config -Engine $containerEngine.Name }
					'k3s' { New-ToolchainK3dCluster -Name $Name -Kubeconfig $kubeconfig -Servers $Servers -Workers $Workers -ApiPort $ApiPort -WaitSeconds $WaitSeconds -Image $Image -Config $Config }
					'k0s' { New-ToolchainK0sCluster -ContainerEngine $containerEngine.Path -Name $Name -Kubeconfig $kubeconfig -ApiPort $ApiPort -WaitSeconds $WaitSeconds -Image $Image }
				}
				$created = $true
				Write-ToolchainClusterState -Name $Name -Provider $Provider -Servers $Servers -Workers $Workers -Image $Image -Engine $containerEngine.Name
				$state = Read-ToolchainClusterState -Name $Name
				Write-ToolchainInfo "Created $Provider cluster '$Name'. Kubeconfig: $kubeconfig"
				return (ConvertTo-ToolchainClusterObject -State $state -Status 'Running')
			} catch {
				if ($created) {
					try {
						$tempState = [pscustomobject]@{ name = $Name; provider = $Provider }
						Remove-ToolchainProviderCluster -State $tempState -AllowMissing
					} catch { Write-Warning "cluster rollback failed: $($_.Exception.Message)" }
				}
				try { Remove-ToolchainClusterDirectory -Name $Name } catch { Write-Warning "cluster state cleanup failed: $($_.Exception.Message)" }
				throw
			}
		}
		'list' {
			if ($Name) { throw 'cluster list does not accept a cluster name' }
			$states = @(Get-ToolchainClusterStates)
			if ($PSBoundParameters.ContainsKey('Provider')) { $states = @($states | Where-Object { $_.provider -eq $Provider }) }
			return @($states | ForEach-Object { ConvertTo-ToolchainClusterObject -State $_ })
		}
		'status' {
			if (-not $Name) { throw 'cluster status requires a name' }
			$state = Read-ToolchainClusterState -Name $Name
			if (-not $state) { throw "Toolchain cluster not found: $Name" }
			return (ConvertTo-ToolchainClusterObject -State $state)
		}
		'kubeconfig' {
			if (-not $Name) { throw 'cluster kubeconfig requires a name' }
			$state = Read-ToolchainClusterState -Name $Name
			if (-not $state) { throw "Toolchain cluster not found: $Name" }
			$path = Get-ToolchainClusterKubeconfigPath -Name $Name
			if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "cluster kubeconfig is missing: $path" }
			if ($Raw) { return (Get-Content -LiteralPath $path -Raw) }
			return $path
		}
		'delete' {
			if (-not $Name) { throw 'cluster delete requires a name' }
			$state = Read-ToolchainClusterState -Name $Name
			if (-not $state) { throw "Toolchain cluster not found: $Name" }
			Remove-ToolchainProviderCluster -State $state
			Remove-ToolchainClusterDirectory -Name $Name
			Write-ToolchainInfo "Deleted $($state.provider) cluster '$Name'."
		}
	}
}
