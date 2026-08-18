<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

$script:ToolchainDeploymentPackageIndex = 'toolchain.package.json'
$script:ToolchainDeploymentPackageMaximumFiles = 10000
$script:ToolchainDeploymentPackageMaximumBytes = 20GB
$script:ToolchainDeploymentImageRoot = '.toolchain/images'

function Assert-ToolchainDeploymentIdentifier {
	param(
		[Parameter(Mandatory)][string]$Value,
		[Parameter(Mandatory)][string]$Kind,
		[int]$MaximumLength = 253
	)
	if ($Value.Length -gt $MaximumLength -or $Value -cnotmatch '^[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?$') {
		throw "invalid Toolchain deployment $Kind '$Value'"
	}
}

function Assert-ToolchainDeploymentVersion {
	param([Parameter(Mandatory)][string]$Version)
	if ($Version.Length -gt 128 -or $Version -cnotmatch '^[A-Za-z0-9](?:[-A-Za-z0-9._+]*[A-Za-z0-9])?$') {
		throw "invalid Toolchain deployment version '$Version'"
	}
}

function Assert-ToolchainDeploymentVariableName {
	param([Parameter(Mandatory)][string]$Name, [string]$Context = 'variable')
	if ($Name -cnotmatch '^[A-Z0-9_]+$') { throw "$Context name '$Name' must contain only uppercase letters, digits, and underscores" }
}

function ConvertTo-ToolchainDeploymentImage {
	param(
		[Parameter(Mandatory)][object]$Value,
		[Parameter(Mandatory)][string]$ComponentName,
		[Parameter(Mandatory)][int]$Index
	)
	if ($Value -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$Value)) {
		throw "deployment component '$ComponentName' image $Index must be a non-empty string"
	}
	$reference = [string]$Value
	if ($reference -ne $reference.Trim() -or $reference.Length -gt 1024 -or $reference -match '[\s\x00-\x1f]' -or
		$reference -match '://' -or $reference -match '\\' -or $reference -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._:/@-]*$') {
		throw "deployment component '$ComponentName' contains invalid image reference '$reference'"
	}
	if ($reference.Contains('@') -and $reference -cnotmatch '@sha256:[0-9a-f]{64}$') {
		throw "deployment component '$ComponentName' image '$reference' must use a sha256 digest"
	}
	return [pscustomobject]@{
		Source = $reference
		Component = $ComponentName
	}
}

function ConvertTo-ToolchainDeploymentVariable {
	param(
		[Parameter(Mandatory)][Collections.IDictionary]$Value,
		[Parameter(Mandatory)][int]$Index
	)
	foreach ($key in $Value.Keys) {
		if ([string]$key -notin @('name', 'description', 'default', 'prompt', 'sensitive', 'autoIndent', 'pattern', 'type')) {
			throw "deployment variable $Index contains unsupported key '$key'"
		}
	}
	$name = [string]$Value['name']
	if ([string]::IsNullOrWhiteSpace($name)) { throw "deployment variable $Index requires a name" }
	Assert-ToolchainDeploymentVariableName -Name $name -Context "deployment variable $Index"
	foreach ($booleanKey in @('prompt', 'sensitive', 'autoIndent')) {
		if ($null -ne $Value[$booleanKey] -and $Value[$booleanKey] -isnot [bool]) {
			throw "deployment variable '$name' requires $booleanKey to be true or false"
		}
	}
	$type = if ($Value['type']) { [string]$Value['type'] } else { 'raw' }
	if ($type -notin @('raw', 'file')) { throw "deployment variable '$name' type must be raw or file" }
	$pattern = [string]$Value['pattern']
	if ($pattern) {
		try { $null = [Text.RegularExpressions.Regex]::new($pattern, [Text.RegularExpressions.RegexOptions]::None, [TimeSpan]::FromSeconds(1)) }
		catch { throw "deployment variable '$name' has an invalid pattern: $($_.Exception.Message)" }
	}
	$hasDefault = $Value.Contains('default') -and $null -ne $Value['default']
	$defaultValue = if ($hasDefault) {
		if ($Value['default'] -is [Collections.IDictionary] -or ($Value['default'] -is [Collections.IEnumerable] -and $Value['default'] -isnot [string])) {
			throw "deployment variable '$name' default must be a scalar value"
		}
		[Convert]::ToString($Value['default'], [Globalization.CultureInfo]::InvariantCulture)
	} else { '' }
	return [pscustomobject]@{
		Name = $name
		Description = [string]$Value['description']
		Default = $defaultValue
		HasDefault = $hasDefault
		Prompt = [bool]$Value['prompt']
		Sensitive = [bool]$Value['sensitive']
		AutoIndent = [bool]$Value['autoIndent']
		Pattern = $pattern
		Type = $type
	}
}

function ConvertTo-ToolchainDeploymentChartVariable {
	param(
		[Parameter(Mandatory)][Collections.IDictionary]$Value,
		[Parameter(Mandatory)][int]$ChartIndex,
		[Parameter(Mandatory)][int]$Index
	)
	foreach ($key in $Value.Keys) {
		if ([string]$key -notin @('name', 'path', 'description')) { throw "deployment chart $ChartIndex variable $Index contains unsupported key '$key'" }
	}
	$name = [string]$Value['name']
	$path = [string]$Value['path']
	Assert-ToolchainDeploymentVariableName -Name $name -Context "deployment chart $ChartIndex variable $Index"
	if ($path -cnotmatch '^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*$') {
		throw "deployment chart $ChartIndex variable '$name' requires a dot-separated Helm values path"
	}
	return [pscustomobject]@{ Name = $name; Path = $path; Description = [string]$Value['description'] }
}

function ConvertTo-ToolchainDeploymentChart {
	param(
		[Parameter(Mandatory)][object]$Value,
		[Parameter(Mandatory)][string]$DefaultRelease,
		[Parameter(Mandatory)][int]$ChartCount,
		[Parameter(Mandatory)][int]$Index,
		[string]$ComponentName
	)
	$path = $null
	$release = $null
	$namespace = $null
	$values = @()
	$wait = $true
	$schemaValidation = $true
	$chartName = $null
	$chartVersion = $null
	$url = $null
	$repoName = $null
	$gitPath = $null
	$remote = $false
	$variableMappings = @()
	if ($Value -is [string]) {
		$path = [string]$Value
	} elseif ($Value -is [Collections.IDictionary]) {
		foreach ($key in $Value.Keys) {
			if ([string]$key -notin @('path', 'release', 'namespace', 'values', 'name', 'version', 'url', 'repoName', 'gitPath', 'localPath', 'releaseName', 'noWait', 'valuesFiles', 'variables', 'schemaValidation', 'serverSideApply')) {
				throw "deployment chart $Index contains unsupported key '$key'"
			}
		}
		$localPath = if ($Value['path']) { [string]$Value['path'] } else { [string]$Value['localPath'] }
		$release = if ($Value['release']) { [string]$Value['release'] } else { [string]$Value['releaseName'] }
		$namespace = [string]$Value['namespace']
		$chartName = [string]$Value['name']
		$chartVersion = [string]$Value['version']
		$url = [string]$Value['url']
		$repoName = [string]$Value['repoName']
		$gitPath = [string]$Value['gitPath']
		if ($null -ne $Value['values']) { $values += @($Value['values']) }
		if ($null -ne $Value['valuesFiles']) { $values += @($Value['valuesFiles']) }
		if ($url) {
			if ($localPath) { throw "deployment chart $Index cannot specify both localPath and url" }
			if ([string]::IsNullOrWhiteSpace($chartName)) { throw "deployment chart $Index requires name when url is used" }
			if ([string]::IsNullOrWhiteSpace($chartVersion)) { throw "deployment chart $Index requires version when url is used" }
			if ($chartVersion.Length -gt 128 -or $chartVersion -cnotmatch '^[A-Za-z0-9](?:[-A-Za-z0-9._+]*[A-Za-z0-9])?$') {
				throw "deployment chart $Index contains invalid remote version '$chartVersion'"
			}
			if ($url.Length -gt 2048 -or $url -match '[\s\x00-\x1f]' -or $url -cnotmatch '^(?i:https?|oci)://') {
				throw "deployment chart $Index contains unsupported url '$url'; use an http, https, or oci URL"
			}
			foreach ($remoteValue in @($repoName, $gitPath)) {
				if ($remoteValue -and ($remoteValue.Length -gt 1024 -or $remoteValue -match '[\x00-\x1f]' -or $remoteValue.StartsWith('-'))) {
					throw "deployment chart $Index contains an invalid remote chart field"
				}
			}
			$remoteKey = Get-ToolchainDeploymentStringSha256 -Value "$ComponentName|$Index|$chartName|$chartVersion|$url|$repoName|$gitPath"
			$path = ".toolchain/charts/$remoteKey.tgz"
			$remote = $true
		} else {
			if ($repoName -or $gitPath) { throw "deployment chart $Index requires url when repoName or gitPath is used" }
			$path = $localPath
		}
		if ($null -ne $Value['variables']) {
			$mappingValues = @($Value['variables'])
			for ($mappingIndex = 0; $mappingIndex -lt $mappingValues.Count; $mappingIndex++) {
				if ($mappingValues[$mappingIndex] -isnot [Collections.IDictionary]) { throw "deployment chart $Index variable $($mappingIndex + 1) must be a mapping" }
				$variableMappings += ConvertTo-ToolchainDeploymentChartVariable -Value $mappingValues[$mappingIndex] -ChartIndex $Index -Index ($mappingIndex + 1)
			}
		}
		if ($null -ne $Value['serverSideApply'] -and [string]$Value['serverSideApply'] -notin @('', 'auto')) {
			throw "deployment chart $Index requests serverSideApply behavior that is not supported by this Helm runtime"
		}
		if ($null -ne $Value['noWait']) {
			if ($Value['noWait'] -isnot [bool]) { throw "deployment chart $Index requires noWait to be true or false" }
			$wait = -not [bool]$Value['noWait']
		}
		if ($null -ne $Value['schemaValidation']) {
			if ($Value['schemaValidation'] -isnot [bool]) { throw "deployment chart $Index requires schemaValidation to be true or false" }
			$schemaValidation = [bool]$Value['schemaValidation']
		}
	} else {
		throw "deployment chart $Index must be a path string or mapping"
	}
	if ([string]::IsNullOrWhiteSpace($path)) { throw "deployment chart $Index requires a path" }
	if (-not $release) {
		$release = if ($chartName) { $chartName } elseif ($ChartCount -eq 1) { $DefaultRelease } else { [IO.Path]::GetFileNameWithoutExtension($path.TrimEnd([char[]]@('/', '\'))) }
	}
	Assert-ToolchainDeploymentIdentifier -Value $release -Kind 'chart release' -MaximumLength 53
	if ($namespace) { Assert-ToolchainDeploymentIdentifier -Value $namespace -Kind 'chart namespace' }
	$normalizedValues = @()
	foreach ($valuePath in $values) {
		if ($valuePath -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$valuePath)) {
			throw "deployment chart $Index contains an invalid values path"
		}
		$normalizedValues += [string]$valuePath
	}
	return [pscustomobject]@{
		Path = $path
		ResolvedPath = $null
		Remote = $remote
		Name = $chartName
		Url = $url
		RemoteName = $repoName
		Version = $chartVersion
		GitPath = $gitPath
		Release = $release
		Namespace = $namespace
		Values = [string[]]$normalizedValues
		Wait = $wait
		SchemaValidation = $schemaValidation
		Component = $ComponentName
		VariableMappings = [object[]]$variableMappings
	}
}

function ConvertTo-ToolchainDeploymentManifestSet {
	param(
		[Parameter(Mandatory)][object]$Value,
		[Parameter(Mandatory)][int]$Index,
		[string]$ComponentName,
		[string]$DefaultNamespace
	)
	$name = "manifest-$Index"
	$namespace = $DefaultNamespace
	$files = @()
	if ($Value -is [string]) {
		$files = @([string]$Value)
	} elseif ($Value -is [Collections.IDictionary]) {
		foreach ($key in $Value.Keys) {
			if ([string]$key -notin @('name', 'namespace', 'files', 'kustomizations', 'kustomizeAllowAnyDirectory', 'enableKustomizePlugins', 'noWait', 'serverSideApply', 'template')) {
				throw "deployment manifest $Index contains unsupported key '$key'"
			}
		}
		if ($Value['name']) { $name = [string]$Value['name'] }
		if ($Value['namespace']) { $namespace = [string]$Value['namespace'] }
		if ($null -ne $Value['files']) { $files = @($Value['files']) }
		if ($null -ne $Value['kustomizations'] -and @($Value['kustomizations']).Count -gt 0) {
			throw "deployment manifest '$name' uses kustomizations; render them to local YAML files before creating a Toolchain package"
		}
		if ([bool]$Value['template']) { throw "deployment manifest '$name' uses Go templating; use Helm or pre-rendered YAML with Toolchain" }
		if ($null -ne $Value['serverSideApply'] -and [string]$Value['serverSideApply'] -eq 'false') {
			throw "deployment manifest '$name' disables server-side apply, but Toolchain packages deploy manifests with server-side apply"
		}
	} else {
		throw "deployment manifest $Index must be a path string or mapping"
	}
	Assert-ToolchainDeploymentIdentifier -Value $name -Kind 'manifest name'
	if ($namespace) { Assert-ToolchainDeploymentIdentifier -Value $namespace -Kind 'manifest namespace' }
	$normalizedFiles = @()
	foreach ($file in $files) {
		if ($file -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$file)) { throw "deployment manifest '$name' contains an invalid file path" }
		if ([string]$file -match '^(?i:https?|oci)://') { throw "deployment manifest '$name' uses a remote file; download it locally so Toolchain can integrity-index it" }
		$normalizedFiles += [string]$file
	}
	if ($normalizedFiles.Count -eq 0) { throw "deployment manifest '$name' requires at least one local file or directory" }
	return [pscustomobject]@{
		Name = $name
		Namespace = $namespace
		Files = [string[]]$normalizedFiles
		Component = $ComponentName
	}
}

function ConvertTo-ToolchainDeploymentActionShell {
	param([object]$Value, [Parameter(Mandatory)][string]$Context)
	if ($null -eq $Value) { return [pscustomobject]@{ Windows = $null; Linux = $null; Darwin = $null } }
	if ($Value -is [string]) {
		$shellName = [string]$Value
		if ($shellName -notin @('sh', 'bash', 'powershell', 'pwsh', 'cmd')) { throw "$Context contains unsupported shell '$shellName'" }
		return [pscustomobject]@{ Windows = $shellName; Linux = $shellName; Darwin = $shellName }
	}
	if ($Value -isnot [Collections.IDictionary]) { throw "$Context shell must be a string or operating-system mapping" }
	foreach ($key in $Value.Keys) {
		if ([string]$key -notin @('windows', 'linux', 'darwin')) { throw "$Context shell contains unsupported key '$key'" }
		$shellName = [string]$Value[$key]
		if ($shellName -and $shellName -notin @('sh', 'bash', 'powershell', 'pwsh', 'cmd')) { throw "$Context contains unsupported shell '$shellName'" }
	}
	return [pscustomobject]@{ Windows = [string]$Value['windows']; Linux = [string]$Value['linux']; Darwin = [string]$Value['darwin'] }
}

function ConvertTo-ToolchainDeploymentActionEnvironment {
	param([object[]]$Values, [Parameter(Mandatory)][string]$Context)
	$environment = @()
	foreach ($entry in @($Values | Where-Object { $null -ne $_ })) {
		if ($entry -isnot [string] -or [string]$entry -cnotmatch '^[A-Za-z_][A-Za-z0-9_]*=[\s\S]*$') { throw "$Context contains invalid env entry; expected NAME=value" }
		$environment += [string]$entry
	}
	return [string[]]$environment
}

function ConvertTo-ToolchainDeploymentActionVariable {
	param([Parameter(Mandatory)][object]$Value, [Parameter(Mandatory)][string]$Context)
	if ($Value -is [string]) { $Value = @{ name = [string]$Value } }
	if ($Value -isnot [Collections.IDictionary]) { throw "$Context setVariables entries must be names or mappings" }
	foreach ($key in $Value.Keys) {
		if ([string]$key -notin @('name', 'sensitive', 'autoIndent', 'pattern', 'type')) { throw "$Context setVariables contains unsupported key '$key'" }
	}
	$name = [string]$Value['name']
	Assert-ToolchainDeploymentVariableName -Name $name -Context "$Context output variable"
	foreach ($booleanKey in @('sensitive', 'autoIndent')) {
		if ($null -ne $Value[$booleanKey] -and $Value[$booleanKey] -isnot [bool]) { throw "$Context output variable '$name' requires $booleanKey to be true or false" }
	}
	$type = if ($Value['type']) { [string]$Value['type'] } else { 'raw' }
	if ($type -notin @('raw', 'file')) { throw "$Context output variable '$name' type must be raw or file" }
	$pattern = [string]$Value['pattern']
	if ($pattern) {
		try { $null = [Text.RegularExpressions.Regex]::new($pattern, [Text.RegularExpressions.RegexOptions]::None, [TimeSpan]::FromSeconds(1)) }
		catch { throw "$Context output variable '$name' has an invalid pattern: $($_.Exception.Message)" }
	}
	return [pscustomobject]@{ Name = $name; Sensitive = [bool]$Value['sensitive']; AutoIndent = [bool]$Value['autoIndent']; Pattern = $pattern; Type = $type }
}

function ConvertTo-ToolchainDeploymentActionWait {
	param([Parameter(Mandatory)][Collections.IDictionary]$Value, [Parameter(Mandatory)][string]$Context)
	foreach ($key in $Value.Keys) { if ([string]$key -notin @('cluster', 'network')) { throw "$Context wait contains unsupported key '$key'" } }
	if ([bool]$Value['cluster'] -eq [bool]$Value['network']) { throw "$Context wait requires exactly one of cluster or network" }
	if ($Value['cluster']) {
		$cluster = $Value['cluster']
		if ($cluster -isnot [Collections.IDictionary]) { throw "$Context wait.cluster must be a mapping" }
		foreach ($key in $cluster.Keys) { if ([string]$key -notin @('kind', 'name', 'namespace', 'condition')) { throw "$Context wait.cluster contains unsupported key '$key'" } }
		if (-not $cluster['kind'] -or -not $cluster['name']) { throw "$Context wait.cluster requires kind and name" }
		return [pscustomobject]@{ Type = 'cluster'; Kind = [string]$cluster['kind']; Name = [string]$cluster['name']; Namespace = [string]$cluster['namespace']; Condition = [string]$cluster['condition'] }
	}
	$network = $Value['network']
	if ($network -isnot [Collections.IDictionary]) { throw "$Context wait.network must be a mapping" }
	foreach ($key in $network.Keys) { if ([string]$key -notin @('protocol', 'address', 'code')) { throw "$Context wait.network contains unsupported key '$key'" } }
	$protocol = [string]$network['protocol']
	if ($protocol -notin @('tcp', 'http', 'https') -or -not $network['address']) { throw "$Context wait.network requires protocol tcp, http, or https and an address" }
	$code = if ($null -ne $network['code']) { [int]$network['code'] } else { 200 }
	if ($code -lt 100 -or $code -gt 599) { throw "$Context wait.network code must be from 100 through 599" }
	return [pscustomobject]@{ Type = 'network'; Protocol = $protocol; Address = [string]$network['address']; Code = $code }
}

function ConvertTo-ToolchainDeploymentActionDefaults {
	param([object]$Value, [Parameter(Mandatory)][string]$Context)
	if ($null -eq $Value) { $Value = @{} }
	if ($Value -isnot [Collections.IDictionary]) { throw "$Context defaults must be a mapping" }
	foreach ($key in $Value.Keys) { if ([string]$key -notin @('mute', 'maxTotalSeconds', 'maxRetries', 'dir', 'env', 'shell')) { throw "$Context defaults contains unsupported key '$key'" } }
	if ($null -ne $Value['mute'] -and $Value['mute'] -isnot [bool]) { throw "$Context defaults.mute must be true or false" }
	$seconds = if ($null -ne $Value['maxTotalSeconds']) { [int]$Value['maxTotalSeconds'] } else { 300 }
	$retries = if ($null -ne $Value['maxRetries']) { [int]$Value['maxRetries'] } else { 0 }
	if ($seconds -lt 0 -or $seconds -gt 86400) { throw "$Context defaults.maxTotalSeconds must be from 0 through 86400" }
	if ($retries -lt 0 -or $retries -gt 10) { throw "$Context defaults.maxRetries must be from 0 through 10" }
	return [pscustomobject]@{
		Mute = [bool]$Value['mute']; MaxTotalSeconds = $seconds; MaxRetries = $retries; Dir = [string]$Value['dir']
		Env = ConvertTo-ToolchainDeploymentActionEnvironment -Values @($Value['env']) -Context "$Context defaults"
		Shell = ConvertTo-ToolchainDeploymentActionShell -Value $Value['shell'] -Context "$Context defaults"
	}
}

function ConvertTo-ToolchainDeploymentAction {
	param(
		[Parameter(Mandatory)][Collections.IDictionary]$Value,
		[Parameter(Mandatory)]$Defaults,
		[Parameter(Mandatory)][string]$Lifecycle,
		[Parameter(Mandatory)][string]$Context
	)
	foreach ($key in $Value.Keys) {
		if ([string]$key -notin @('mute', 'maxTotalSeconds', 'maxRetries', 'dir', 'env', 'cmd', 'shell', 'setVariable', 'setVariables', 'description', 'wait')) { throw "$Context contains unsupported key '$key'" }
	}
	if ($null -ne $Value['mute'] -and $Value['mute'] -isnot [bool]) { throw "$Context mute must be true or false" }
	$cmd = [string]$Value['cmd']
	$wait = $null
	if ($Value['wait']) {
		if ($Value['wait'] -isnot [Collections.IDictionary]) { throw "$Context wait must be a mapping" }
		$wait = ConvertTo-ToolchainDeploymentActionWait -Value $Value['wait'] -Context $Context
	}
	if ([bool]$cmd -eq [bool]$wait) { throw "$Context requires exactly one of cmd or wait" }
	$seconds = if ($null -ne $Value['maxTotalSeconds']) { [int]$Value['maxTotalSeconds'] } else { [int]$Defaults.MaxTotalSeconds }
	$retries = if ($null -ne $Value['maxRetries']) { [int]$Value['maxRetries'] } else { [int]$Defaults.MaxRetries }
	if ($seconds -lt 0 -or $seconds -gt 86400) { throw "$Context maxTotalSeconds must be from 0 through 86400" }
	if ($retries -lt 0 -or $retries -gt 10) { throw "$Context maxRetries must be from 0 through 10" }
	$setVariables = @()
	if ($Value['setVariable']) { $setVariables += ConvertTo-ToolchainDeploymentActionVariable -Value ([string]$Value['setVariable']) -Context $Context }
	if ($null -ne $Value['setVariables']) {
		foreach ($variable in @($Value['setVariables'])) { $setVariables += ConvertTo-ToolchainDeploymentActionVariable -Value $variable -Context $Context }
	}
	if ($setVariables.Count -gt 0 -and ($Lifecycle -ne 'onDeploy' -or -not $cmd)) { throw "$Context setVariables is supported only by onDeploy command actions" }
	return [pscustomobject]@{
		Cmd = $cmd; Wait = $wait; Description = [string]$Value['description']
		Mute = if ($Value.Contains('mute')) { [bool]$Value['mute'] } else { [bool]$Defaults.Mute }
		MaxTotalSeconds = $seconds; MaxRetries = $retries
		Dir = if ($Value.Contains('dir')) { [string]$Value['dir'] } else { [string]$Defaults.Dir }
		Env = if ($Value.Contains('env')) { ConvertTo-ToolchainDeploymentActionEnvironment -Values @($Value['env']) -Context $Context } else { [string[]]$Defaults.Env }
		Shell = if ($Value.Contains('shell')) { ConvertTo-ToolchainDeploymentActionShell -Value $Value['shell'] -Context $Context } else { $Defaults.Shell }
		SetVariables = [object[]]$setVariables
	}
}

function ConvertTo-ToolchainDeploymentActionSet {
	param([object]$Value, [Parameter(Mandatory)][string]$Lifecycle, [Parameter(Mandatory)][string]$Context)
	if ($null -eq $Value) { $Value = @{} }
	if ($Value -isnot [Collections.IDictionary]) { throw "$Context must be a mapping" }
	foreach ($key in $Value.Keys) { if ([string]$key -notin @('defaults', 'before', 'after', 'onSuccess', 'onFailure')) { throw "$Context contains unsupported key '$key'" } }
	$defaults = ConvertTo-ToolchainDeploymentActionDefaults -Value $Value['defaults'] -Context $Context
	$result = [ordered]@{ Defaults = $defaults }
	foreach ($phase in @('before', 'after', 'onSuccess', 'onFailure')) {
		$actions = @()
		$values = @()
		if ($null -ne $Value[$phase]) { $values += @($Value[$phase]) }
		for ($index = 0; $index -lt $values.Count; $index++) {
			if ($values[$index] -isnot [Collections.IDictionary]) { throw "$Context.$phase action $($index + 1) must be a mapping" }
			$actions += ConvertTo-ToolchainDeploymentAction -Value $values[$index] -Defaults $defaults -Lifecycle $Lifecycle -Context "$Context.$phase action $($index + 1)"
		}
		$result[$phase] = [object[]]$actions
	}
	return [pscustomobject]$result
}

function ConvertTo-ToolchainDeploymentActions {
	param([object]$Value, [Parameter(Mandatory)][string]$ComponentName)
	if ($null -eq $Value) { $Value = @{} }
	if ($Value -isnot [Collections.IDictionary]) { throw "deployment component '$ComponentName' actions must be a mapping" }
	foreach ($key in $Value.Keys) { if ([string]$key -notin @('onCreate', 'onDeploy', 'onRemove')) { throw "deployment component '$ComponentName' actions contains unsupported key '$key'" } }
	return [pscustomobject]@{
		OnCreate = ConvertTo-ToolchainDeploymentActionSet -Value $Value['onCreate'] -Lifecycle 'onCreate' -Context "component '$ComponentName' actions.onCreate"
		OnDeploy = ConvertTo-ToolchainDeploymentActionSet -Value $Value['onDeploy'] -Lifecycle 'onDeploy' -Context "component '$ComponentName' actions.onDeploy"
		OnRemove = ConvertTo-ToolchainDeploymentActionSet -Value $Value['onRemove'] -Lifecycle 'onRemove' -Context "component '$ComponentName' actions.onRemove"
	}
}

function ConvertTo-ToolchainDeploymentComponent {
	param(
		[Parameter(Mandatory)][Collections.IDictionary]$Value,
		[Parameter(Mandatory)][string]$PackageName,
		[string]$DefaultNamespace,
		[Parameter(Mandatory)][int]$Index
	)
	foreach ($key in $Value.Keys) {
		if ([string]$key -notin @('name', 'description', 'default', 'required', 'charts', 'manifests', 'only', 'group', 'import', 'images', 'imageArchives', 'repos', 'files', 'dataInjections', 'actions', 'scripts', 'healthChecks')) {
			throw "deployment component $Index contains unsupported key '$key'"
		}
	}
	$name = [string]$Value['name']
	Assert-ToolchainDeploymentIdentifier -Value $name -Kind 'component name'
	foreach ($booleanKey in @('default', 'required')) {
		if ($null -ne $Value[$booleanKey] -and $Value[$booleanKey] -isnot [bool]) { throw "deployment component '$name' requires $booleanKey to be true or false" }
	}
	foreach ($unsupported in @('only', 'group', 'import', 'imageArchives', 'repos', 'files', 'dataInjections', 'scripts', 'healthChecks')) {
		$valueForKey = $Value[$unsupported]
		$hasValue = if ($valueForKey -is [Collections.IDictionary]) { $valueForKey.Count -gt 0 } else { @($valueForKey).Count -gt 0 -and $null -ne $valueForKey }
		if ($hasValue) { throw "Toolchain component '$name' uses '$unsupported', which Toolchain packages do not yet support" }
	}

	$chartValues = @()
	if ($null -ne $Value['charts']) { $chartValues = @($Value['charts']) }
	$charts = @()
	for ($chartIndex = 0; $chartIndex -lt $chartValues.Count; $chartIndex++) {
		$charts += ConvertTo-ToolchainDeploymentChart -Value $chartValues[$chartIndex] -DefaultRelease $PackageName -ChartCount $chartValues.Count -Index ($chartIndex + 1) -ComponentName $name
	}
	$manifestValues = @()
	if ($null -ne $Value['manifests']) { $manifestValues = @($Value['manifests']) }
	$manifestSets = @()
	for ($manifestIndex = 0; $manifestIndex -lt $manifestValues.Count; $manifestIndex++) {
		$manifestSets += ConvertTo-ToolchainDeploymentManifestSet -Value $manifestValues[$manifestIndex] -Index ($manifestIndex + 1) -ComponentName $name -DefaultNamespace $DefaultNamespace
	}
	$imageValues = @()
	if ($null -ne $Value['images']) { $imageValues = @($Value['images']) }
	$images = @()
	$imageSources = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
	for ($imageIndex = 0; $imageIndex -lt $imageValues.Count; $imageIndex++) {
		$image = ConvertTo-ToolchainDeploymentImage -Value $imageValues[$imageIndex] -ComponentName $name -Index ($imageIndex + 1)
		if (-not $imageSources.Add([string]$image.Source)) { throw "deployment component '$name' contains duplicate image '$($image.Source)'" }
		$images += $image
	}
	$actions = ConvertTo-ToolchainDeploymentActions -Value $Value['actions'] -ComponentName $name
	$actionCount = @($actions.OnCreate.before + $actions.OnCreate.after + $actions.OnCreate.onSuccess + $actions.OnCreate.onFailure + $actions.OnDeploy.before + $actions.OnDeploy.after + $actions.OnDeploy.onSuccess + $actions.OnDeploy.onFailure + $actions.OnRemove.before + $actions.OnRemove.after + $actions.OnRemove.onSuccess + $actions.OnRemove.onFailure).Count
	if ($charts.Count -eq 0 -and $manifestSets.Count -eq 0 -and $images.Count -eq 0 -and $actionCount -eq 0) { throw "deployment component '$name' must declare at least one chart, manifest, image, or action" }
	return [pscustomobject]@{
		Name = $name
		Description = [string]$Value['description']
		Required = [bool]$Value['required']
		Default = [bool]$Value['default']
		Charts = [object[]]$charts
		ManifestSets = [object[]]$manifestSets
		Images = [object[]]$images
		Actions = $actions
	}
}

function Read-ToolchainDeploymentDefinition {
	param([Parameter(Mandatory)][string]$Root)
	$rootPath = Resolve-ToolchainFileSystemPath -Path $Root
	$manifestPath = Join-Path $rootPath 'toolchain.yaml'
	if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
		throw "Toolchain deployment manifest not found: $manifestPath"
	}
	$manifest = ConvertFrom-ToolchainYaml -Text (Get-Content -LiteralPath $manifestPath -Raw) -Context $manifestPath
	foreach ($key in $manifest.Keys) {
		if ([string]$key -notin @('schemaVersion', 'packages', 'deployment', 'apiVersion', 'kind', 'metadata', 'components', 'values', 'documentation', 'constants', 'variables', 'build')) {
			throw "$manifestPath contains unsupported top-level key '$key'"
		}
	}
	if ($null -ne $manifest['schemaVersion'] -and [int]$manifest['schemaVersion'] -ne 1) { throw "$manifestPath requires schemaVersion: 1" }
	if ($manifest['kind'] -and [string]$manifest['kind'] -ne 'ToolchainPackageConfig') { throw "$manifestPath supports only kind: ToolchainPackageConfig" }
	if ($manifest['apiVersion'] -and [string]$manifest['apiVersion'] -ne 'toolchain.allsagetech.com/v1alpha1') { throw "$manifestPath supports only apiVersion: toolchain.allsagetech.com/v1alpha1" }
	foreach ($unsupportedTopLevel in @('constants', 'build')) {
		if ($null -ne $manifest[$unsupportedTopLevel] -and @($manifest[$unsupportedTopLevel]).Count -gt 0) {
			throw "Toolchain top-level field '$unsupportedTopLevel' is not yet supported by Toolchain packages"
		}
	}

	$deployment = $manifest['deployment']
	$metadata = $manifest['metadata']
	if ($null -ne $deployment -and $deployment -isnot [Collections.IDictionary]) { throw "$manifestPath deployment must be a mapping" }
	if ($null -ne $metadata -and $metadata -isnot [Collections.IDictionary]) { throw "$manifestPath metadata must be a mapping" }
	if ($deployment) {
		foreach ($key in $deployment.Keys) {
			if ([string]$key -notin @('name', 'version', 'description', 'namespace', 'charts', 'manifests')) {
				throw "$manifestPath deployment contains unsupported key '$key'"
			}
		}
	}
	if ($metadata) {
		foreach ($key in $metadata.Keys) {
			if ([string]$key -notin @('name', 'description', 'version', 'url', 'image', 'uncompressed', 'architecture', 'yolo', 'authors', 'documentation', 'source', 'vendor', 'aggregateChecksum', 'annotations', 'allowNamespaceOverride')) {
				throw "$manifestPath metadata contains unsupported Toolchain key '$key'"
			}
		}
	}
	if (-not $deployment -and -not $metadata) { throw "$manifestPath requires either a deployment or metadata mapping" }
	$name = if ($deployment -and $deployment['name']) { [string]$deployment['name'] } else { [string]$metadata['name'] }
	$version = if ($deployment -and $deployment['version']) { [string]$deployment['version'] } else { [string]$metadata['version'] }
	$description = if ($deployment -and $deployment['description']) { [string]$deployment['description'] } else { [string]$metadata['description'] }
	$namespace = if ($deployment) { [string]$deployment['namespace'] } else { $null }
	$architecture = if ($metadata) { [string]$metadata['architecture'] } else { $null }
	Assert-ToolchainDeploymentIdentifier -Value $name -Kind 'name'
	Assert-ToolchainDeploymentVersion -Version $version
	if ($namespace) { Assert-ToolchainDeploymentIdentifier -Value $namespace -Kind 'namespace' }
	if ($architecture -and $architecture -notin @('amd64', 'arm64')) { throw "$manifestPath metadata.architecture must be amd64 or arm64" }

	$variables = @()
	$variableNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
	$variableValues = @()
	if ($null -ne $manifest['variables']) { $variableValues = @($manifest['variables']) }
	for ($variableIndex = 0; $variableIndex -lt $variableValues.Count; $variableIndex++) {
		if ($variableValues[$variableIndex] -isnot [Collections.IDictionary]) { throw "deployment variable $($variableIndex + 1) must be a mapping" }
		$variable = ConvertTo-ToolchainDeploymentVariable -Value $variableValues[$variableIndex] -Index ($variableIndex + 1)
		if (-not $variableNames.Add([string]$variable.Name)) { throw "$manifestPath contains duplicate deployment variable '$($variable.Name)'" }
		$variables += $variable
	}

	$components = @()
	if ($deployment -and ($null -ne $deployment['charts'] -or $null -ne $deployment['manifests'])) {
		$legacyComponent = @{
			name = 'default'
			description = 'Toolchain deployment resources'
			required = $true
			charts = @($deployment['charts'])
			manifests = @($deployment['manifests'])
		}
		$components += ConvertTo-ToolchainDeploymentComponent -Value $legacyComponent -PackageName $name -DefaultNamespace $namespace -Index 1
	}
	$componentValues = @()
	if ($null -ne $manifest['components']) { $componentValues = @($manifest['components']) }
	for ($componentIndex = 0; $componentIndex -lt $componentValues.Count; $componentIndex++) {
		if ($componentValues[$componentIndex] -isnot [Collections.IDictionary]) { throw "deployment component $($componentIndex + 1) must be a mapping" }
		$components += ConvertTo-ToolchainDeploymentComponent -Value $componentValues[$componentIndex] -PackageName $name -DefaultNamespace $namespace -Index ($componentIndex + 1)
	}
	if ($components.Count -eq 0) { throw "$manifestPath must declare deployment charts/manifests or at least one component" }
	$componentNames = @($components | ForEach-Object { $_.Name })
	if (@($componentNames | Sort-Object -Unique).Count -ne $componentNames.Count) { throw "$manifestPath contains duplicate component names" }
	$actionVariablesByName = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
	foreach ($component in $components) {
		foreach ($phase in @('before', 'after', 'onSuccess', 'onFailure')) {
			foreach ($action in @($component.Actions.OnDeploy.$phase)) {
				foreach ($actionVariable in $action.SetVariables) {
					if ($actionVariablesByName.ContainsKey([string]$actionVariable.Name)) {
						$existing = $actionVariablesByName[[string]$actionVariable.Name]
						if ($existing.Sensitive -ne $actionVariable.Sensitive -or $existing.AutoIndent -ne $actionVariable.AutoIndent -or $existing.Pattern -ne $actionVariable.Pattern -or $existing.Type -ne $actionVariable.Type) {
							throw "$manifestPath declares conflicting action output variable '$($actionVariable.Name)'"
						}
					} else { $actionVariablesByName.Add([string]$actionVariable.Name, $actionVariable) }
					[void]$variableNames.Add([string]$actionVariable.Name)
				}
			}
		}
	}

	$globalValues = @()
	$packageFiles = @()
	if ($null -ne $manifest['values']) {
		if ($manifest['values'] -isnot [Collections.IDictionary]) { throw "$manifestPath values must be a mapping" }
		foreach ($key in $manifest['values'].Keys) {
			if ([string]$key -notin @('files', 'schema')) { throw "$manifestPath values contains unsupported key '$key'" }
		}
		foreach ($valuePath in @($manifest['values']['files'])) {
			if ($valuePath -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$valuePath)) { throw "$manifestPath values.files contains an invalid path" }
			$globalValues += [string]$valuePath
			$packageFiles += [string]$valuePath
		}
		if ($manifest['values']['schema']) { $packageFiles += [string]$manifest['values']['schema'] }
	}
	$documentation = @()
	if ($null -ne $manifest['documentation']) {
		if ($manifest['documentation'] -isnot [Collections.IDictionary]) { throw "$manifestPath documentation must be a mapping" }
		foreach ($documentationPath in $manifest['documentation'].Values) {
			if ($documentationPath -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$documentationPath)) { throw "$manifestPath documentation contains an invalid path" }
			$documentation += [string]$documentationPath
			$packageFiles += [string]$documentationPath
		}
	}
	$allCharts = @($components | ForEach-Object { $_.Charts })
	foreach ($chart in $allCharts) {
		foreach ($mapping in $chart.VariableMappings) {
			if (-not $variableNames.Contains([string]$mapping.Name)) {
				throw "deployment chart '$($chart.Release)' maps undefined variable '$($mapping.Name)'"
			}
		}
	}
	foreach ($variable in $variables) {
		if ($variable.Type -eq 'file' -and $variable.HasDefault -and -not [string]::IsNullOrWhiteSpace([string]$variable.Default)) {
			$packageFiles += [string]$variable.Default
		}
	}
	$allManifestSets = @($components | ForEach-Object { $_.ManifestSets })
	$allManifests = @($allManifestSets | ForEach-Object { $_.Files })
	$allImages = @($components | ForEach-Object { $_.Images })
	return [pscustomobject]@{
		Root = $rootPath
		ManifestPath = $manifestPath
		Name = $name
		Version = $version
		Description = $description
		Namespace = $namespace
		Architecture = $architecture
		Components = [object[]]$components
		Charts = [object[]]$allCharts
		ManifestSets = [object[]]$allManifestSets
		Manifests = [string[]]$allManifests
		Images = [object[]]$allImages
		Variables = [object[]]$variables
		ActionVariables = [object[]]@($actionVariablesByName.Values)
		GlobalValues = [string[]]$globalValues
		Documentation = [string[]]$documentation
		PackageFiles = [string[]]$packageFiles
		Compatibility = if ($manifest['components'] -or $manifest['kind']) { 'toolchain-components-v1alpha1' } else { 'toolchain' }
	}
}

function Read-ToolchainDeploymentConfig {
	param([Parameter(Mandatory)][string]$Path)
	$fullPath = Resolve-ToolchainFileSystemPath -Path $Path
	if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) { throw "Toolchain deployment config is not a file: $fullPath" }
	$config = ConvertFrom-ToolchainYaml -Text (Get-Content -LiteralPath $fullPath -Raw) -Context $fullPath
	foreach ($key in $config.Keys) {
		if ([string]$key -notin @('schemaVersion', 'namespace', 'wait', 'waitSeconds', 'createNamespace', 'variables')) {
			throw "$fullPath contains unsupported deployment config key '$key'"
		}
	}
	if ([int]$config.schemaVersion -ne 1) { throw "$fullPath requires schemaVersion: 1" }
	if ($config.namespace) { Assert-ToolchainDeploymentIdentifier -Value ([string]$config.namespace) -Kind 'namespace' }
	foreach ($booleanKey in @('wait', 'createNamespace')) {
		if ($null -ne $config[$booleanKey] -and $config[$booleanKey] -isnot [bool]) { throw "$fullPath requires $booleanKey to be true or false" }
	}
	if ($null -ne $config.waitSeconds) {
		$seconds = 0
		if (-not [int]::TryParse([string]$config.waitSeconds, [ref]$seconds) -or $seconds -lt 1 -or $seconds -gt 3600) {
			throw "$fullPath requires waitSeconds from 1 through 3600"
		}
	}
	if ($null -ne $config.variables) {
		if ($config.variables -isnot [Collections.IDictionary]) { throw "$fullPath variables must be a mapping" }
		foreach ($variableName in $config.variables.Keys) {
			Assert-ToolchainDeploymentVariableName -Name ([string]$variableName) -Context "$fullPath variable"
			$variableValue = $config.variables[$variableName]
			if ($variableValue -is [Collections.IDictionary] -or ($variableValue -is [Collections.IEnumerable] -and $variableValue -isnot [string])) {
				throw "$fullPath variable '$variableName' must be a scalar value"
			}
		}
	}
	return $config
}

function ConvertFrom-ToolchainDeploymentSet {
	param([string[]]$Set)
	$values = @{}
	foreach ($setValue in @($Set | Where-Object { $null -ne $_ })) {
		foreach ($assignment in @([string]$setValue -split ',(?=[A-Z0-9_]+=)')) {
			$match = [regex]::Match($assignment, '^([A-Z0-9_]+)=([\s\S]*)$')
			if (-not $match.Success) { throw "invalid package variable assignment '$assignment'; expected NAME=value" }
			$name = $match.Groups[1].Value
			Assert-ToolchainDeploymentVariableName -Name $name -Context 'package variable assignment'
			$values[$name] = $match.Groups[2].Value
		}
	}
	return $values
}

function Read-ToolchainDeploymentSensitiveValue {
	param([Parameter(Mandatory)][string]$Prompt)
	$secureValue = Read-Host -Prompt $Prompt -AsSecureString
	$pointer = [IntPtr]::Zero
	try {
		$pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureValue)
		return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
	} finally {
		if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
	}
}

function Resolve-ToolchainDeploymentVariables {
	param(
		[Parameter(Mandatory)]$Definition,
		[Parameter(Mandatory)][string]$Root,
		[hashtable]$Configured = @{},
		[hashtable]$Overrides = @{}
	)
	$declaredNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
	foreach ($variable in $Definition.Variables) { [void]$declaredNames.Add([string]$variable.Name) }
	foreach ($name in @($Configured.Keys) + @($Overrides.Keys)) {
		if (-not $declaredNames.Contains([string]$name)) { throw "package variable '$name' is not declared in toolchain.yaml" }
	}

	$resolved = @{}
	foreach ($variable in $Definition.Variables) {
		$name = [string]$variable.Name
		$value = if ($variable.HasDefault) { [string]$variable.Default } else { '' }
		$valueSource = if ($variable.HasDefault) { 'default' } else { 'empty' }
		$environmentValue = [Environment]::GetEnvironmentVariable("TOOLCHAIN_VAR_$name")
		if ($null -ne $environmentValue) { $value = $environmentValue; $valueSource = 'environment' }
		if ($Configured.ContainsKey($name)) { $value = [Convert]::ToString($Configured[$name], [Globalization.CultureInfo]::InvariantCulture); $valueSource = 'config' }
		if ($Overrides.ContainsKey($name)) { $value = [string]$Overrides[$name]; $valueSource = 'command' }

		if ($variable.Prompt -and $valueSource -notin @('environment', 'config', 'command')) {
			$prompt = if ($variable.Description) { [string]$variable.Description } else { "Enter a value for $name" }
			if ($variable.HasDefault -and -not $variable.Sensitive) { $prompt += " [$($variable.Default)]" }
			try {
				$entered = if ($variable.Sensitive) { Read-ToolchainDeploymentSensitiveValue -Prompt $prompt } else { Read-Host -Prompt $prompt }
			} catch {
				throw "package variable '$name' requires input; provide -Set '$name=value' for non-interactive deployment"
			}
			if (-not [string]::IsNullOrEmpty([string]$entered)) { $value = [string]$entered; $valueSource = 'prompt' }
		}

		if ($variable.Type -eq 'file') {
			if ([string]::IsNullOrWhiteSpace($value)) { throw "package variable '$name' requires a file path" }
			$filePath = if ($valueSource -eq 'default') {
				Resolve-ToolchainChildPath -Root $Root -RelativePath $value -RejectReparsePoints -RejectRootReparsePoint
			} else {
				$rootCandidate = if ([IO.Path]::IsPathRooted($value)) { $null } else { Join-Path $Root $value }
				if ($rootCandidate -and (Test-Path -LiteralPath $rootCandidate -PathType Leaf)) {
					Resolve-ToolchainChildPath -Root $Root -RelativePath $value -RejectReparsePoints -RejectRootReparsePoint
				} else { Resolve-ToolchainFileSystemPath -Path $value }
			}
			if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) { throw "package variable '$name' file is not a file: $filePath" }
			$fileItem = Get-Item -LiteralPath $filePath -Force
			if ($fileItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "package variable '$name' file cannot be a link or reparse point: $filePath" }
			if ($fileItem.Length -gt 1MB) { throw "package variable '$name' file exceeds the 1 MiB limit" }
			$value = Get-Content -LiteralPath $filePath -Raw
		}
		if ($variable.Pattern) {
			$matcher = [Text.RegularExpressions.Regex]::new([string]$variable.Pattern, [Text.RegularExpressions.RegexOptions]::None, [TimeSpan]::FromSeconds(1))
			if (-not $matcher.IsMatch([string]$value)) { throw "package variable '$name' does not match its required pattern" }
		}
		$resolved[$name] = [pscustomobject]@{
			Name = $name
			Value = [string]$value
			Sensitive = [bool]$variable.Sensitive
			AutoIndent = [bool]$variable.AutoIndent
			Source = $valueSource
		}
	}
	foreach ($variable in $Definition.ActionVariables) {
		if ($resolved.ContainsKey([string]$variable.Name)) { continue }
		$resolved[[string]$variable.Name] = [pscustomobject]@{
			Name = [string]$variable.Name; Value = ''; Sensitive = [bool]$variable.Sensitive
			AutoIndent = [bool]$variable.AutoIndent; Source = 'action-pending'
		}
	}
	return $resolved
}

function New-ToolchainDeploymentRenderRoot {
	$path = Join-Path ([IO.Path]::GetTempPath()) "toolchain-render-$([guid]::NewGuid().ToString('n'))"
	[void][IO.Directory]::CreateDirectory($path)
	return $path
}

function Remove-ToolchainDeploymentRenderRoot {
	param([Parameter(Mandatory)][string]$Path)
	$fullPath = [IO.Path]::GetFullPath($Path).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
	$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
	if ((Split-Path -Parent $fullPath) -ne $tempRoot -or [IO.Path]::GetFileName($fullPath) -notmatch '^toolchain-render-[0-9a-f]{32}$') {
		throw "refusing to remove unexpected Toolchain render path: $fullPath"
	}
	if (Test-Path -LiteralPath $fullPath -PathType Container) { [IO.Directory]::Delete($fullPath, $true) }
}

function Expand-ToolchainDeploymentVariableText {
	param(
		[Parameter(Mandatory)][AllowEmptyString()][string]$Text,
		[Parameter(Mandatory)][hashtable]$Variables,
		[Parameter(Mandatory)][string]$Context
	)
	$expanded = $Text
	foreach ($variable in @($Variables.Values | Sort-Object Name)) {
		$token = "###TOOLCHAIN_VAR_$($variable.Name)###"
		if (-not $expanded.Contains($token)) { continue }
		if ($variable.AutoIndent -and $variable.Value -match "`r?`n") {
			$pattern = [regex]::Escape($token)
			$replacementValue = ([string]$variable.Value).Replace("`r`n", "`n")
			$expanded = [regex]::Replace($expanded, $pattern, [Text.RegularExpressions.MatchEvaluator]{
				param($match)
				$lineStart = $expanded.LastIndexOf("`n", [Math]::Max(0, $match.Index - 1))
				$column = if ($lineStart -lt 0) { $match.Index } else { $match.Index - $lineStart - 1 }
				return $replacementValue.Replace("`n", "`n" + (' ' * $column))
			})
		} else {
			$expanded = $expanded.Replace($token, [string]$variable.Value)
		}
	}
	$unknown = [regex]::Match($expanded, '###TOOLCHAIN_VAR_([A-Z0-9_]+)###')
	if ($unknown.Success) { throw "$Context references undeclared package variable '$($unknown.Groups[1].Value)'" }
	return $expanded
}

function Get-ToolchainDeploymentRenderedFile {
	param(
		[Parameter(Mandatory)][string]$Path,
		[Parameter(Mandatory)][hashtable]$Variables,
		[Parameter(Mandatory)][string]$RenderRoot,
		[Parameter(Mandatory)][string]$Context
	)
	$text = Get-Content -LiteralPath $Path -Raw
	if ($text -notmatch '###TOOLCHAIN_VAR_[A-Z0-9_]+###') { return $Path }
	$rendered = Expand-ToolchainDeploymentVariableText -Text $text -Variables $Variables -Context $Context
	$destination = Join-Path $RenderRoot "$([guid]::NewGuid().ToString('n'))$([IO.Path]::GetExtension($Path))"
	[IO.File]::WriteAllText($destination, $rendered, [Text.UTF8Encoding]::new($false))
	return $destination
}

function Get-ToolchainDeploymentRenderedChart {
	param(
		[Parameter(Mandatory)][string]$Path,
		[Parameter(Mandatory)][hashtable]$Variables,
		[Parameter(Mandatory)][string]$RenderRoot,
		[Parameter(Mandatory)][string]$Context
	)
	if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return $Path }
	$textExtensions = @('.yaml', '.yml', '.tpl', '.txt', '.json', '.toml', '.conf', '.ini', '.properties', '.env', '.lock')
	$sourceFiles = @(Get-ChildItem -LiteralPath $Path -File -Recurse -Force | Sort-Object FullName)
	$templated = @()
	foreach ($file in $sourceFiles) {
		$sourceRelative = Get-ToolchainDeploymentRelativePath -Root $Path -Path $file.FullName
		$null = Resolve-ToolchainChildPath -Root $Path -RelativePath $sourceRelative -RejectReparsePoints -RejectRootReparsePoint
		if ($file.Extension -notin $textExtensions) { continue }
		$text = Get-Content -LiteralPath $file.FullName -Raw
		if ($text -match '###TOOLCHAIN_VAR_[A-Z0-9_]+###') { $templated += [pscustomobject]@{ File = $file; Text = $text } }
	}
	if ($templated.Count -eq 0) { return $Path }
	$destinationRoot = Join-Path $RenderRoot "chart-$([guid]::NewGuid().ToString('n'))"
	[void][IO.Directory]::CreateDirectory($destinationRoot)
	foreach ($file in $sourceFiles) {
		$relative = Get-ToolchainDeploymentRelativePath -Root $Path -Path $file.FullName
		$destination = Resolve-ToolchainChildPath -Root $destinationRoot -RelativePath $relative -RejectReparsePoints -RejectRootReparsePoint
		[void][IO.Directory]::CreateDirectory((Split-Path -Parent $destination))
		[IO.File]::Copy($file.FullName, $destination, $false)
	}
	foreach ($item in $templated) {
		$relative = Get-ToolchainDeploymentRelativePath -Root $Path -Path $item.File.FullName
		$destination = Resolve-ToolchainChildPath -Root $destinationRoot -RelativePath $relative -RejectReparsePoints -RejectRootReparsePoint
		$rendered = Expand-ToolchainDeploymentVariableText -Text $item.Text -Variables $Variables -Context "$Context/$relative"
		[IO.File]::WriteAllText($destination, $rendered, [Text.UTF8Encoding]::new($false))
	}
	return $destinationRoot
}

function New-ToolchainDeploymentChartVariableValues {
	param(
		[Parameter(Mandatory)]$Chart,
		[Parameter(Mandatory)][hashtable]$Variables,
		[Parameter(Mandatory)][string]$RenderRoot
	)
	if ($Chart.VariableMappings.Count -eq 0) { return $null }
	$values = [ordered]@{}
	foreach ($mapping in $Chart.VariableMappings) {
		$current = $values
		$segments = @([string]$mapping.Path -split '\.')
		for ($index = 0; $index -lt $segments.Count; $index++) {
			$segment = $segments[$index]
			if ($index -eq ($segments.Count - 1)) {
				if ($current.Contains($segment)) { throw "deployment chart '$($Chart.Release)' maps more than one variable to '$($mapping.Path)'" }
				$current[$segment] = [string]$Variables[[string]$mapping.Name].Value
			} else {
				if (-not $current.Contains($segment)) { $current[$segment] = [ordered]@{} }
				if ($current[$segment] -isnot [Collections.IDictionary]) { throw "deployment chart '$($Chart.Release)' has conflicting variable path '$($mapping.Path)'" }
				$current = $current[$segment]
			}
		}
	}
	$path = Join-Path $RenderRoot "chart-variables-$([guid]::NewGuid().ToString('n')).json"
	[IO.File]::WriteAllText($path, ($values | ConvertTo-Json -Depth 30), [Text.UTF8Encoding]::new($false))
	return $path
}

function Get-ToolchainDeploymentBuildVariables {
	param([Parameter(Mandatory)]$Definition)
	$resolved = @{}
	foreach ($variable in $Definition.Variables) {
		$value = if ($variable.HasDefault) { [string]$variable.Default } else { 'toolchain-variable' }
		if ($variable.Type -eq 'file') {
			if ($variable.HasDefault -and -not [string]::IsNullOrWhiteSpace($value)) {
				$filePath = Resolve-ToolchainChildPath -Root $Definition.Root -RelativePath $value -RejectReparsePoints -RejectRootReparsePoint
				if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) { throw "package variable '$($variable.Name)' default file is not a file: $value" }
				$fileItem = Get-Item -LiteralPath $filePath -Force
				if ($fileItem.Length -gt 1MB) { throw "package variable '$($variable.Name)' default file exceeds the 1 MiB limit" }
				$value = Get-Content -LiteralPath $filePath -Raw
			} else { $value = 'toolchain-variable' }
		}
		$resolved[[string]$variable.Name] = [pscustomobject]@{
			Name = [string]$variable.Name
			Value = [string]$value
			Sensitive = [bool]$variable.Sensitive
			AutoIndent = [bool]$variable.AutoIndent
			Source = 'build-validation'
		}
	}
	foreach ($variable in $Definition.ActionVariables) {
		if ($resolved.ContainsKey([string]$variable.Name)) { continue }
		$resolved[[string]$variable.Name] = [pscustomobject]@{
			Name = [string]$variable.Name; Value = 'toolchain-action-variable'; Sensitive = [bool]$variable.Sensitive
			AutoIndent = [bool]$variable.AutoIndent; Source = 'build-validation'
		}
	}
	return $resolved
}

function Get-ToolchainDeploymentRelativePath {
	param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Path)
	$rootPath = [IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
	$fullPath = [IO.Path]::GetFullPath($Path)
	$prefix = $rootPath + [IO.Path]::DirectorySeparatorChar
	if (-not $fullPath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw "path is outside the deployment root: $fullPath" }
	return $fullPath.Substring($prefix.Length).Replace([IO.Path]::DirectorySeparatorChar, '/')
}

function Get-ToolchainDeploymentSourceFiles {
	param(
		[Parameter(Mandatory)][string]$Root,
		[Parameter(Mandatory)][string]$RelativePath,
		[switch]$YamlOnly
	)
	$path = Resolve-ToolchainChildPath -Root $Root -RelativePath $RelativePath -RejectReparsePoints -RejectRootReparsePoint
	if (-not (Test-Path -LiteralPath $path)) { throw "deployment source path does not exist: $RelativePath" }
	$item = Get-Item -LiteralPath $path -Force
	$files = if ($item.PSIsContainer) {
		@(Get-ChildItem -LiteralPath $path -File -Recurse -Force | Sort-Object FullName)
	} else { @($item) }
	if ($YamlOnly) {
		$files = @($files | Where-Object { $_.Extension -in @('.yaml', '.yml') })
	}
	$qualifier = if ($YamlOnly) { ' YAML' } else { '' }
	if ($files.Count -eq 0) { throw "deployment source path contains no$qualifier files: $RelativePath" }
	foreach ($file in $files) {
		$relative = Get-ToolchainDeploymentRelativePath -Root $Root -Path $file.FullName
		$null = Resolve-ToolchainChildPath -Root $Root -RelativePath $relative -RejectReparsePoints -RejectRootReparsePoint
		if ($file.Extension -ieq '.tlcpkg') { continue }
		$file
	}
}

function Get-ToolchainDeploymentBundleFiles {
	param([Parameter(Mandatory)]$Definition)
	$files = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
	function AddBundleFile {
		param([Parameter(Mandatory)][IO.FileInfo]$File, [string]$RelativePath)
		$relative = if ($RelativePath) { $RelativePath.Replace('\', '/') } else { Get-ToolchainDeploymentRelativePath -Root $Definition.Root -Path $File.FullName }
		$null = Resolve-ToolchainChildPath -Root $Definition.Root -RelativePath $relative -RejectReparsePoints -RejectRootReparsePoint
		if ($files.ContainsKey($relative)) {
			if (-not [string]::Equals($files[$relative], $File.FullName, [StringComparison]::OrdinalIgnoreCase)) {
				throw "deployment bundle contains case-conflicting paths: $relative"
			}
			return
		}
		$files.Add($relative, $File.FullName)
	}
	AddBundleFile -File (Get-Item -LiteralPath $Definition.ManifestPath -Force)
	foreach ($conventionalName in @('toolchain-values.yaml', 'toolchain-config.yaml')) {
		$conventionalPath = Join-Path $Definition.Root $conventionalName
		if (Test-Path -LiteralPath $conventionalPath -PathType Leaf) { AddBundleFile -File (Get-Item -LiteralPath $conventionalPath -Force) }
	}
	foreach ($chart in $Definition.Charts) {
		if ($chart.Remote) {
			$chartPath = Get-ToolchainDeploymentChartSourcePath -Definition $Definition -Chart $chart
			if (-not (Test-Path -LiteralPath $chartPath -PathType Leaf)) { throw "downloaded Helm chart is missing: $($chart.Release)" }
			AddBundleFile -File (Get-Item -LiteralPath $chartPath -Force) -RelativePath $chart.Path
		} else {
			foreach ($file in @(Get-ToolchainDeploymentSourceFiles -Root $Definition.Root -RelativePath $chart.Path)) { AddBundleFile -File $file }
		}
		foreach ($valuesPath in $chart.Values) {
			foreach ($file in @(Get-ToolchainDeploymentSourceFiles -Root $Definition.Root -RelativePath $valuesPath -YamlOnly)) { AddBundleFile -File $file }
		}
	}
	foreach ($manifestPath in $Definition.Manifests) {
		foreach ($file in @(Get-ToolchainDeploymentSourceFiles -Root $Definition.Root -RelativePath $manifestPath -YamlOnly)) { AddBundleFile -File $file }
	}
	foreach ($packageFile in $Definition.PackageFiles) {
		foreach ($file in @(Get-ToolchainDeploymentSourceFiles -Root $Definition.Root -RelativePath $packageFile)) { AddBundleFile -File $file }
	}
	if ($files.Count -gt $script:ToolchainDeploymentPackageMaximumFiles) {
		throw "deployment bundle exceeds the limit of $script:ToolchainDeploymentPackageMaximumFiles files"
	}
	return $files
}

function Get-ToolchainDeploymentStringSha256 {
	param([Parameter(Mandatory)][string]$Value)
	$algorithm = [Security.Cryptography.SHA256]::Create()
	try {
		$bytes = [Text.Encoding]::UTF8.GetBytes($Value)
		return ([BitConverter]::ToString($algorithm.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
	} finally { $algorithm.Dispose() }
}

function New-ToolchainDeploymentChartTemporaryRoot {
	$path = Join-Path ([IO.Path]::GetTempPath()) "toolchain-charts-$([guid]::NewGuid().ToString('n'))"
	[void][IO.Directory]::CreateDirectory($path)
	return $path
}

function Remove-ToolchainDeploymentChartTemporaryRoot {
	param([Parameter(Mandatory)][string]$Path)
	$fullPath = [IO.Path]::GetFullPath($Path).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
	$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
	if ((Split-Path -Parent $fullPath) -ne $tempRoot -or [IO.Path]::GetFileName($fullPath) -notmatch '^toolchain-charts-[0-9a-f]{32}$') {
		throw "refusing to remove unexpected Toolchain chart temporary path: $fullPath"
	}
	if (Test-Path -LiteralPath $fullPath -PathType Container) { [IO.Directory]::Delete($fullPath, $true) }
}

function Get-ToolchainDeploymentChartSourcePath {
	param([Parameter(Mandatory)]$Definition, [Parameter(Mandatory)]$Chart)
	if ($Chart.ResolvedPath) { return [string]$Chart.ResolvedPath }
	return (Resolve-ToolchainChildPath -Root $Definition.Root -RelativePath $Chart.Path -RejectReparsePoints -RejectRootReparsePoint)
}

function Get-ToolchainDeploymentDownloadedChart {
	param(
		[Parameter(Mandatory)]$Chart,
		[Parameter(Mandatory)][string]$TemporaryRoot,
		[Parameter(Mandatory)][string]$Helm
	)
	$destination = Resolve-ToolchainChildPath -Root $TemporaryRoot -RelativePath $Chart.Path -RejectReparsePoints -RejectRootReparsePoint
	$workRoot = Join-Path $TemporaryRoot ("work-" + [IO.Path]::GetFileNameWithoutExtension([string]$Chart.Path))
	[void][IO.Directory]::CreateDirectory($workRoot)
	[void][IO.Directory]::CreateDirectory((Split-Path -Parent $destination))
	$url = [string]$Chart.Url
	$version = [string]$Chart.Version
	$isGit = [bool]$Chart.GitPath -or $url -match '(?i)\.git(?:@[^/]+)?$'
	if ($isGit) {
		$git = Get-ToolchainClusterExecutable -Name git -Package git -InstallHint 'Install Git and ensure its executable is available on PATH.'
		$repositoryUrl = $url
		$gitReference = $version
		if ($url -match '^(?<repository>.+\.git)@(?<reference>[^/]+)$') {
			$repositoryUrl = [string]$Matches.repository
			$gitReference = [string]$Matches.reference
		}
		$cloneRoot = Join-Path $workRoot 'repository'
		$null = Invoke-ToolchainClusterProcess -FilePath $git -Arguments @('clone', '--depth', '1', '--branch', $gitReference, '--single-branch', '--', $repositoryUrl, $cloneRoot)
		$chartSource = if ($Chart.GitPath) {
			Resolve-ToolchainChildPath -Root $cloneRoot -RelativePath ([string]$Chart.GitPath) -RejectReparsePoints -RejectRootReparsePoint
		} else { $cloneRoot }
		if (-not (Test-Path -LiteralPath (Join-Path $chartSource 'Chart.yaml') -PathType Leaf)) {
			throw "remote Git chart '$($Chart.Release)' is missing Chart.yaml at '$($Chart.GitPath)'"
		}
		$null = Invoke-ToolchainClusterProcess -FilePath $helm -Arguments @('dependency', 'build', $chartSource)
		$null = Invoke-ToolchainClusterProcess -FilePath $helm -Arguments @('package', $chartSource, '--destination', $workRoot)
	} else {
		$arguments = @('pull')
		if ($url -match '(?i)\.tgz(?:[?#].*)?$' -or $url.StartsWith('oci://', [StringComparison]::OrdinalIgnoreCase)) {
			$arguments += $url
		} else {
			$remoteName = if ($Chart.RemoteName) { [string]$Chart.RemoteName } else { [string]$Chart.Name }
			$arguments += @($remoteName, '--repo', $url)
		}
		$arguments += @('--version', $version, '--destination', $workRoot)
		$null = Invoke-ToolchainClusterProcess -FilePath $Helm -Arguments $arguments
	}
	$archives = @(Get-ChildItem -LiteralPath $workRoot -File -Filter '*.tgz' -Force)
	if ($archives.Count -ne 1) { throw "remote chart '$($Chart.Release)' did not produce exactly one packaged Helm chart" }
	[IO.File]::Move($archives[0].FullName, $destination)
	return $destination
}

function Initialize-ToolchainDeploymentRemoteCharts {
	param([Parameter(Mandatory)]$Definition, [object[]]$Charts)
	if ($null -eq $Charts) { $Charts = @($Definition.Charts) }
	$remoteCharts = @($Charts | Where-Object { $_.Remote })
	if ($remoteCharts.Count -eq 0) { return $null }
	$temporaryRoot = $null
	try {
		$helm = $null
		foreach ($chart in $remoteCharts) {
			if ($chart.ResolvedPath -and (Test-Path -LiteralPath $chart.ResolvedPath -PathType Leaf)) { continue }
			$bundledPath = Resolve-ToolchainChildPath -Root $Definition.Root -RelativePath $chart.Path -RejectReparsePoints -RejectRootReparsePoint
			if (Test-Path -LiteralPath $bundledPath -PathType Leaf) {
				$chart.ResolvedPath = $bundledPath
				continue
			}
			if (-not $helm) { $helm = Get-ToolchainClusterExecutable -Name helm -Package helm -InstallHint 'Install Helm and ensure its executable is available on PATH.' }
			if (-not $temporaryRoot) { $temporaryRoot = New-ToolchainDeploymentChartTemporaryRoot }
			Write-ToolchainInfo "Downloading remote Helm chart '$($chart.Release):$($chart.Version)'."
			$chart.ResolvedPath = Get-ToolchainDeploymentDownloadedChart -Chart $chart -TemporaryRoot $temporaryRoot -Helm $helm
		}
		return $temporaryRoot
	} catch {
		if ($temporaryRoot) { Remove-ToolchainDeploymentChartTemporaryRoot -Path $temporaryRoot }
		throw
	}
}

function New-ToolchainDeploymentImageTemporaryRoot {
	$path = Join-Path ([IO.Path]::GetTempPath()) "toolchain-images-$([guid]::NewGuid().ToString('n'))"
	[void][IO.Directory]::CreateDirectory($path)
	return $path
}

function Remove-ToolchainDeploymentImageTemporaryRoot {
	param([Parameter(Mandatory)][string]$Path)
	$fullPath = [IO.Path]::GetFullPath($Path).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
	$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
	if ((Split-Path -Parent $fullPath) -ne $tempRoot -or [IO.Path]::GetFileName($fullPath) -notmatch '^toolchain-images-[0-9a-f]{32}$') {
		throw "refusing to remove unexpected Toolchain image temporary path: $fullPath"
	}
	if (Test-Path -LiteralPath $fullPath -PathType Container) { [IO.Directory]::Delete($fullPath, $true) }
}

function Resolve-ToolchainDeploymentImageEngine {
	if (-not (Get-Command Resolve-ToolchainContainerEngine -CommandType Function -ErrorAction SilentlyContinue)) {
		throw 'container image packaging requires Toolchain cluster engine support'
	}
	try { return (Resolve-ToolchainContainerEngine -Provider kind) }
	catch { throw "container image packaging requires a ready Linux Docker, Podman, or nerdctl engine: $($_.Exception.Message)" }
}

function Add-ToolchainDeploymentImageBlob {
	param(
		[Parameter(Mandatory)][string]$SourcePath,
		[Parameter(Mandatory)][string]$LayoutRoot,
		[Parameter(Mandatory)][Collections.Generic.Dictionary[string,string]]$Files,
		[Parameter(Mandatory)][string]$MediaType
	)
	$item = Get-Item -LiteralPath $SourcePath -Force
	if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "container image archive contains an invalid blob: $SourcePath" }
	$digestHex = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
	$relative = "$script:ToolchainDeploymentImageRoot/blobs/sha256/$digestHex"
	if (-not $Files.ContainsKey($relative)) {
		$destination = Resolve-ToolchainChildPath -Root $LayoutRoot -RelativePath $relative -RejectReparsePoints -RejectRootReparsePoint
		[void][IO.Directory]::CreateDirectory((Split-Path -Parent $destination))
		[IO.File]::Copy($item.FullName, $destination, $false)
		$Files.Add($relative, $destination)
	}
	return [ordered]@{
		mediaType = $MediaType
		size = [int64]$item.Length
		digest = "sha256:$digestHex"
	}
}

function New-ToolchainDeploymentImageLayout {
	param(
		[Parameter(Mandatory)][object[]]$Images,
		[Parameter(Mandatory)][string]$LayoutRoot,
		[ValidateSet('amd64', 'arm64')][string]$Architecture
	)
	$files = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
	$artifacts = [Collections.ArrayList]::new()
	$unique = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
	foreach ($image in $Images) {
		$source = [string]$image.Source
		if (-not $unique.ContainsKey($source)) { $unique.Add($source, [Collections.ArrayList]::new()) }
		if (-not $unique[$source].Contains([string]$image.Component)) { [void]$unique[$source].Add([string]$image.Component) }
	}
	if ($unique.Count -eq 0) { return [pscustomobject]@{ Files = $files; Images = @() } }
	[void][IO.Directory]::CreateDirectory($LayoutRoot)
	$engine = Resolve-ToolchainDeploymentImageEngine
	$tar = Get-ToolchainClusterExecutable -Name tar -InstallHint 'Install tar and ensure its executable is available on PATH.'
	$workRoot = Join-Path $LayoutRoot 'work'
	[void][IO.Directory]::CreateDirectory($workRoot)
	try {
		foreach ($source in @($unique.Keys | Sort-Object)) {
			$key = Get-ToolchainDeploymentStringSha256 -Value $source
			$archivePath = Join-Path $workRoot "$key.tar"
			$extractRoot = Join-Path $workRoot $key
			[void][IO.Directory]::CreateDirectory($extractRoot)
			Write-ToolchainInfo "Bundling container image '$source'."
			$pullArguments = @('pull')
			if ($Architecture) { $pullArguments += @('--platform', "linux/$Architecture") }
			$pullArguments += $source
			$null = Invoke-ToolchainClusterProcess -FilePath $engine.Path -Arguments $pullArguments
			$saveArguments = @('save')
			if ([string]$engine.Name -eq 'podman') { $saveArguments += @('--format', 'docker-archive') }
			$saveArguments += @('--output', $archivePath, $source)
			$null = Invoke-ToolchainClusterProcess -FilePath $engine.Path -Arguments $saveArguments
			$null = Invoke-ToolchainClusterProcess -FilePath $tar -Arguments @('-xf', $archivePath, '-C', $extractRoot)

			$archiveManifestPath = Join-Path $extractRoot 'manifest.json'
			if (-not (Test-Path -LiteralPath $archiveManifestPath -PathType Leaf)) { throw "container engine archive for '$source' is missing manifest.json" }
			try { $archiveManifest = @(Get-Content -LiteralPath $archiveManifestPath -Raw | ConvertFrom-Json) }
			catch { throw "container engine archive for '$source' has invalid manifest.json: $($_.Exception.Message)" }
			if ($archiveManifest.Count -ne 1) { throw "container engine archive for '$source' must contain exactly one image manifest" }
			$entry = $archiveManifest[0]
			$configRelative = [string]$entry.Config
			$configPath = Resolve-ToolchainChildPath -Root $extractRoot -RelativePath $configRelative -RejectReparsePoints -RejectRootReparsePoint
			if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) { throw "container engine archive for '$source' is missing its image config" }
			$config = Add-ToolchainDeploymentImageBlob -SourcePath $configPath -LayoutRoot $LayoutRoot -Files $files -MediaType 'application/vnd.docker.container.image.v1+json'
			$layers = [Collections.ArrayList]::new()
			foreach ($layerRelativeValue in @($entry.Layers)) {
				$layerRelative = [string]$layerRelativeValue
				$layerPath = Resolve-ToolchainChildPath -Root $extractRoot -RelativePath $layerRelative -RejectReparsePoints -RejectRootReparsePoint
				if (-not (Test-Path -LiteralPath $layerPath -PathType Leaf)) { throw "container engine archive for '$source' is missing layer '$layerRelative'" }
				[void]$layers.Add((Add-ToolchainDeploymentImageBlob -SourcePath $layerPath -LayoutRoot $LayoutRoot -Files $files -MediaType 'application/vnd.docker.image.rootfs.diff.tar'))
			}
			$registryManifest = [ordered]@{
				schemaVersion = 2
				mediaType = 'application/vnd.docker.distribution.manifest.v2+json'
				config = $config
				layers = @($layers.ToArray())
			}
			$manifestRelative = "$script:ToolchainDeploymentImageRoot/manifests/$key.json"
			$manifestPath = Resolve-ToolchainChildPath -Root $LayoutRoot -RelativePath $manifestRelative -RejectReparsePoints -RejectRootReparsePoint
			[void][IO.Directory]::CreateDirectory((Split-Path -Parent $manifestPath))
			[IO.File]::WriteAllText($manifestPath, ($registryManifest | ConvertTo-Json -Depth 20 -Compress), [Text.UTF8Encoding]::new($false))
			$files.Add($manifestRelative, $manifestPath)
			$manifestDigest = 'sha256:' + (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
			[void]$artifacts.Add([ordered]@{
				source = $source
				components = @($unique[$source])
				manifest = $manifestRelative
				manifestDigest = $manifestDigest
			})
		}
	} finally {
		if (Test-Path -LiteralPath $workRoot -PathType Container) { [IO.Directory]::Delete($workRoot, $true) }
	}
	return [pscustomobject]@{ Files = $files; Images = @($artifacts.ToArray()) }
}

function Resolve-ToolchainDeploymentImageArtifact {
	param(
		[Parameter(Mandatory)][string]$Root,
		[Parameter(Mandatory)]$Artifact
	)
	$source = [string]$Artifact.source
	if ([string]::IsNullOrWhiteSpace($source)) { throw 'deployment package image artifact has no source reference' }
	$key = Get-ToolchainDeploymentStringSha256 -Value $source
	$expectedManifest = "$script:ToolchainDeploymentImageRoot/manifests/$key.json"
	if (-not [string]::Equals([string]$Artifact.manifest, $expectedManifest, [StringComparison]::Ordinal)) {
		throw "deployment package image artifact has an invalid manifest path for '$source'"
	}
	$manifestPath = Resolve-ToolchainChildPath -Root $Root -RelativePath $expectedManifest -RejectReparsePoints -RejectRootReparsePoint
	if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw "deployment package image manifest is missing for '$source'" }
	$manifestItem = Get-Item -LiteralPath $manifestPath -Force
	if ($manifestItem.Length -gt 1MB) { throw "deployment package image manifest is too large for '$source'" }
	$manifestDigest = 'sha256:' + (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
	if ([string]$Artifact.manifestDigest -notmatch '^sha256:[0-9a-f]{64}$' -or
		-not [string]::Equals([string]$Artifact.manifestDigest, $manifestDigest, [StringComparison]::Ordinal)) {
		throw "deployment package image manifest digest verification failed for '$source'"
	}
	try { $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json }
	catch { throw "deployment package image manifest is invalid for '$source': $($_.Exception.Message)" }
	if ([int]$manifest.schemaVersion -ne 2 -or [string]$manifest.mediaType -ne 'application/vnd.docker.distribution.manifest.v2+json') {
		throw "deployment package image manifest has an unsupported schema for '$source'"
	}
	$descriptors = @($manifest.config) + @($manifest.layers)
	if ($null -eq $manifest.config -or $null -eq $manifest.layers) { throw "deployment package image manifest is incomplete for '$source'" }
	$blobs = [Collections.ArrayList]::new()
	foreach ($descriptor in $descriptors) {
		$digest = [string]$descriptor.digest
		if ($digest -cnotmatch '^sha256:[0-9a-f]{64}$' -or [int64]$descriptor.size -lt 0 -or [string]::IsNullOrWhiteSpace([string]$descriptor.mediaType)) {
			throw "deployment package image manifest contains invalid blob metadata for '$source'"
		}
		$blobRelative = "$script:ToolchainDeploymentImageRoot/blobs/sha256/$($digest.Substring(7))"
		$blobPath = Resolve-ToolchainChildPath -Root $Root -RelativePath $blobRelative -RejectReparsePoints -RejectRootReparsePoint
		if (-not (Test-Path -LiteralPath $blobPath -PathType Leaf)) { throw "deployment package image blob is missing for '$source': $digest" }
		$blobItem = Get-Item -LiteralPath $blobPath -Force
		if ($blobItem.Length -ne [int64]$descriptor.size) { throw "deployment package image blob size verification failed for '$source': $digest" }
		$actualDigest = 'sha256:' + (Get-FileHash -LiteralPath $blobPath -Algorithm SHA256).Hash.ToLowerInvariant()
		if (-not [string]::Equals($digest, $actualDigest, [StringComparison]::Ordinal)) { throw "deployment package image blob digest verification failed for '$source': $digest" }
		[void]$blobs.Add([pscustomobject]@{ Digest = $digest; Path = $blobPath; Size = [int64]$blobItem.Length })
	}
	return [pscustomobject]@{
		Source = $source
		ManifestPath = $manifestPath
		ManifestDigest = $manifestDigest
		Blobs = @($blobs.ToArray())
	}
}

function Initialize-ToolchainCompression {
	try { Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop } catch { Write-Debug "System.IO.Compression was already loaded or unavailable: $_" }
	try { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop } catch { Write-Debug "System.IO.Compression.FileSystem was already loaded or unavailable: $_" }
}

function Add-ToolchainZipFile {
	param(
		[Parameter(Mandatory)][object]$Archive,
		[Parameter(Mandatory)][string]$EntryName,
		[Parameter(Mandatory)][string]$SourcePath
	)
	$entry = $Archive.CreateEntry($EntryName, [IO.Compression.CompressionLevel]::Optimal)
	$entry.LastWriteTime = [DateTimeOffset]::new(1980, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
	$sourceStream = [IO.File]::OpenRead($SourcePath)
	$output = $entry.Open()
	try { $sourceStream.CopyTo($output) } finally { $output.Dispose(); $sourceStream.Dispose() }
}

function Add-ToolchainZipText {
	param(
		[Parameter(Mandatory)][object]$Archive,
		[Parameter(Mandatory)][string]$EntryName,
		[Parameter(Mandatory)][string]$Text
	)
	$entry = $Archive.CreateEntry($EntryName, [IO.Compression.CompressionLevel]::Optimal)
	$entry.LastWriteTime = [DateTimeOffset]::new(1980, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
	$stream = $entry.Open()
	$writer = [IO.StreamWriter]::new($stream, [Text.UTF8Encoding]::new($false))
	try { $writer.Write($Text) } finally { $writer.Dispose() }
}

function Test-ToolchainDeploymentCharts {
	param([Parameter(Mandatory)]$Definition)
	if ($Definition.Charts.Count -eq 0) { return }
	$helm = Get-ToolchainClusterExecutable -Name helm -Package helm -InstallHint 'Install Helm and ensure its executable is available on PATH.'
	$conventionalValues = Join-Path $Definition.Root 'toolchain-values.yaml'
	$variables = Get-ToolchainDeploymentBuildVariables -Definition $Definition
	$renderRoot = New-ToolchainDeploymentRenderRoot
	try {
	foreach ($chart in $Definition.Charts) {
		$sourceChartPath = Get-ToolchainDeploymentChartSourcePath -Definition $Definition -Chart $chart
		$chartPath = Get-ToolchainDeploymentRenderedChart -Path $sourceChartPath -Variables $variables -RenderRoot $renderRoot -Context "chart $($chart.Release)"
		if ((Test-Path -LiteralPath $chartPath -PathType Container) -and -not (Test-Path -LiteralPath (Join-Path $chartPath 'Chart.yaml') -PathType Leaf)) {
			throw "Helm chart directory is missing Chart.yaml: $($chart.Path)"
		}
		if ((Test-Path -LiteralPath $chartPath -PathType Leaf) -and [IO.Path]::GetExtension($chartPath) -ine '.tgz') {
			throw "packaged Helm charts must use the .tgz extension: $($chart.Path)"
		}
		$arguments = @('lint', $chartPath)
		foreach ($valuesPath in $chart.Values) {
			$sourceValuesPath = Resolve-ToolchainChildPath -Root $Definition.Root -RelativePath $valuesPath -RejectReparsePoints -RejectRootReparsePoint
			$arguments += @('--values', (Get-ToolchainDeploymentRenderedFile -Path $sourceValuesPath -Variables $variables -RenderRoot $renderRoot -Context "chart values $valuesPath"))
		}
		foreach ($valuesPath in $Definition.GlobalValues) {
			$sourceValuesPath = Resolve-ToolchainChildPath -Root $Definition.Root -RelativePath $valuesPath -RejectReparsePoints -RejectRootReparsePoint
			$arguments += @('--values', (Get-ToolchainDeploymentRenderedFile -Path $sourceValuesPath -Variables $variables -RenderRoot $renderRoot -Context "package values $valuesPath"))
		}
		if (Test-Path -LiteralPath $conventionalValues -PathType Leaf) { $arguments += @('--values', (Get-ToolchainDeploymentRenderedFile -Path $conventionalValues -Variables $variables -RenderRoot $renderRoot -Context 'toolchain-values.yaml')) }
		$chartVariableValues = New-ToolchainDeploymentChartVariableValues -Chart $chart -Variables $variables -RenderRoot $renderRoot
		if ($chartVariableValues) { $arguments += @('--values', $chartVariableValues) }
		if (-not $chart.SchemaValidation) { $arguments += '--skip-schema-validation' }
		$null = Invoke-ToolchainClusterProcess -FilePath $helm -Arguments $arguments
	}
	} finally {
		Remove-ToolchainDeploymentRenderRoot -Path $renderRoot
	}
}

function New-ToolchainDeploymentPackage {
	[CmdletBinding()]
	param(
		[string]$Path = (Get-Location).Path,
		[string]$Output,
		[switch]$Force
	)
	$root = Resolve-ToolchainFileSystemPath -Path $Path
	if (-not (Test-Path -LiteralPath $root -PathType Container)) { throw "deployment package source is not a directory: $root" }
	$rootItem = Get-Item -LiteralPath $root -Force
	if ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "deployment package source cannot be a link or reparse point: $root" }
	$definition = Read-ToolchainDeploymentDefinition -Root $root
	$configPath = Join-Path $root 'toolchain-config.yaml'
	if (Test-Path -LiteralPath $configPath -PathType Leaf) { $null = Read-ToolchainDeploymentConfig -Path $configPath }
	$chartTemporaryRoot = $null
	$imageTemporaryRoot = $null
	$createActionsStarted = $false
	$createActionResults = [Collections.ArrayList]::new()
	$createVariables = Get-ToolchainDeploymentBuildVariables -Definition $definition
	try {
	$createActionsStarted = $true
	foreach ($actionResult in @(Invoke-ToolchainDeploymentActionPhase -Components $definition.Components -Lifecycle OnCreate -Phase before -Root $root -Definition $definition -Variables $createVariables)) { [void]$createActionResults.Add($actionResult) }
	$chartTemporaryRoot = Initialize-ToolchainDeploymentRemoteCharts -Definition $definition
	Test-ToolchainDeploymentCharts -Definition $definition
	$files = Get-ToolchainDeploymentBundleFiles -Definition $definition
	$imageArtifacts = @()
	if ($definition.Images.Count -gt 0) {
		$imageTemporaryRoot = New-ToolchainDeploymentImageTemporaryRoot
		$imageLayoutParameters = @{ Images = $definition.Images; LayoutRoot = $imageTemporaryRoot }
		if ($definition.Architecture) { $imageLayoutParameters.Architecture = $definition.Architecture }
		$imageLayout = New-ToolchainDeploymentImageLayout @imageLayoutParameters
		foreach ($relative in $imageLayout.Files.Keys) {
			if ($files.ContainsKey($relative)) { throw "deployment bundle image path conflicts with package content: $relative" }
			$files.Add($relative, $imageLayout.Files[$relative])
		}
		$imageArtifacts = @($imageLayout.Images)
	}
	if ($files.Count -gt $script:ToolchainDeploymentPackageMaximumFiles) { throw "deployment bundle exceeds the limit of $script:ToolchainDeploymentPackageMaximumFiles files" }
	if (-not $Output) { $Output = Join-Path (Join-Path $root 'dist') "toolchain-package-$($definition.Name)-$($definition.Version).tlcpkg" }
	$outputPath = Resolve-ToolchainFileSystemPath -Path $Output
	if ([IO.Path]::GetExtension($outputPath) -ine '.tlcpkg') { throw "deployment package output must use the .tlcpkg extension: $outputPath" }
	if ((Test-Path -LiteralPath $outputPath) -and -not $Force) { throw "deployment package already exists: $outputPath (use -Force to replace it)" }
	$parent = Split-Path -Parent $outputPath
	[void][IO.Directory]::CreateDirectory($parent)
	$tempPath = Join-Path $parent (".$([IO.Path]::GetFileName($outputPath)).$([guid]::NewGuid().ToString('n')).tmp")
	$entries = [Collections.ArrayList]::new()
	$totalBytes = 0L
	foreach ($relative in @($files.Keys | Sort-Object)) {
		$file = Get-Item -LiteralPath $files[$relative] -Force
		$totalBytes += [int64]$file.Length
		if ($totalBytes -gt $script:ToolchainDeploymentPackageMaximumBytes) { throw 'deployment bundle exceeds the 20 GiB uncompressed size limit' }
		[void]$entries.Add([ordered]@{
			path = $relative.Replace('\', '/')
			digest = 'sha256:' + (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
			size = [int64]$file.Length
		})
	}
	$index = [ordered]@{
		schemaVersion = 1
		name = $definition.Name
		version = $definition.Version
		architecture = $definition.Architecture
		manifest = 'toolchain.yaml'
		components = @($definition.Components | ForEach-Object { $_.Name })
		variables = @($definition.Variables + $definition.ActionVariables | ForEach-Object { $_.Name } | Sort-Object -Unique)
		images = @($imageArtifacts)
		files = @($entries.ToArray())
	}
	Initialize-ToolchainCompression
	$fileStream = $null
	$archive = $null
	try {
		$fileStream = [IO.File]::Open($tempPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
		$archive = [IO.Compression.ZipArchive]::new($fileStream, [IO.Compression.ZipArchiveMode]::Create, $false)
		Add-ToolchainZipText -Archive $archive -EntryName $script:ToolchainDeploymentPackageIndex -Text ($index | ConvertTo-Json -Depth 20)
		foreach ($entry in $entries) { Add-ToolchainZipFile -Archive $archive -EntryName ([string]$entry.path) -SourcePath $files[[string]$entry.path] }
		$archive.Dispose(); $archive = $null
		$fileStream.Dispose(); $fileStream = $null
		foreach ($actionResult in @(Invoke-ToolchainDeploymentActionPhase -Components $definition.Components -Lifecycle OnCreate -Phase after -Root $root -Definition $definition -Variables $createVariables)) { [void]$createActionResults.Add($actionResult) }
		foreach ($actionResult in @(Invoke-ToolchainDeploymentActionPhase -Components $definition.Components -Lifecycle OnCreate -Phase onSuccess -Root $root -Definition $definition -Variables $createVariables)) { [void]$createActionResults.Add($actionResult) }
		if (Test-Path -LiteralPath $outputPath) { [IO.File]::Delete($outputPath) }
		[IO.File]::Move($tempPath, $outputPath)
	} finally {
		if ($archive) { $archive.Dispose() }
		if ($fileStream) { $fileStream.Dispose() }
		if (Test-Path -LiteralPath $tempPath -PathType Leaf) { [IO.File]::Delete($tempPath) }
	}
	$result = [pscustomobject]@{
		PSTypeName = 'Toolchain.DeploymentPackage'
		Name = $definition.Name
		Version = $definition.Version
		Architecture = $definition.Architecture
		Path = $outputPath
		Digest = 'sha256:' + (Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash.ToLowerInvariant()
		Files = $entries.Count
		Components = @($definition.Components | ForEach-Object { $_.Name })
		Variables = @($definition.Variables + $definition.ActionVariables | ForEach-Object { $_.Name } | Sort-Object -Unique)
		Charts = $definition.Charts.Count
		Manifests = $definition.Manifests.Count
		Images = $definition.Images.Count
		Actions = @($createActionResults.ToArray())
	}
	Write-ToolchainInfo "Created Toolchain deployment package '$($result.Name):$($result.Version)' at $outputPath."
	return $result
	} catch {
		$originalError = $_
		if ($createActionsStarted) {
			try { $null = Invoke-ToolchainDeploymentActionPhase -Components $definition.Components -Lifecycle OnCreate -Phase onFailure -Root $root -Definition $definition -Variables $createVariables }
			catch { Write-Warning "Package onCreate failure action also failed: $($_.Exception.Message)" }
		}
		throw $originalError
	} finally {
		if ($imageTemporaryRoot) { Remove-ToolchainDeploymentImageTemporaryRoot -Path $imageTemporaryRoot }
		if ($chartTemporaryRoot) { Remove-ToolchainDeploymentChartTemporaryRoot -Path $chartTemporaryRoot }
	}
}

function Read-ToolchainZipEntryText {
	param([Parameter(Mandatory)][object]$Entry, [int]$MaximumBytes = 1MB)
	if ($Entry.Length -gt $MaximumBytes) { throw "package index exceeds $MaximumBytes bytes" }
	$stream = $Entry.Open()
	$reader = [IO.StreamReader]::new($stream, [Text.Encoding]::UTF8, $true)
	try { return $reader.ReadToEnd() } finally { $reader.Dispose() }
}

function Remove-ToolchainDeploymentTemporaryRoot {
	param([Parameter(Mandatory)][string]$Path)
	$fullPath = [IO.Path]::GetFullPath($Path).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
	$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
	if ((Split-Path -Parent $fullPath) -ne $tempRoot -or [IO.Path]::GetFileName($fullPath) -notmatch '^toolchain-package-[0-9a-f]{32}$') {
		throw "refusing to remove unexpected Toolchain package temporary path: $fullPath"
	}
	if (Test-Path -LiteralPath $fullPath -PathType Container) { [IO.Directory]::Delete($fullPath, $true) }
}

function Expand-ToolchainDeploymentPackage {
	param([Parameter(Mandatory)][string]$Path)
	$packagePath = Resolve-ToolchainFileSystemPath -Path $Path
	if (-not (Test-Path -LiteralPath $packagePath -PathType Leaf)) { throw "deployment package is not a file: $packagePath" }
	$packageItem = Get-Item -LiteralPath $packagePath -Force
	if ($packageItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "deployment package cannot be a link or reparse point: $packagePath" }
	Initialize-ToolchainCompression
	$tempRoot = Join-Path ([IO.Path]::GetTempPath()) "toolchain-package-$([guid]::NewGuid().ToString('n'))"
	[void][IO.Directory]::CreateDirectory($tempRoot)
	$fileStream = $null
	$archive = $null
	try {
		$fileStream = [IO.File]::OpenRead($packagePath)
		$archive = [IO.Compression.ZipArchive]::new($fileStream, [IO.Compression.ZipArchiveMode]::Read, $false)
		if ($archive.Entries.Count -gt ($script:ToolchainDeploymentPackageMaximumFiles + 1)) { throw 'deployment package contains too many files' }
		$entryMap = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
		foreach ($entry in $archive.Entries) {
			if (-not $entry.FullName -or $entry.FullName.Contains('\') -or $entryMap.ContainsKey($entry.FullName)) { throw "deployment package contains an invalid or duplicate entry: $($entry.FullName)" }
			$entryMap.Add($entry.FullName, $entry)
		}
		if (-not $entryMap.ContainsKey($script:ToolchainDeploymentPackageIndex)) { throw 'deployment package index is missing' }
		try { $index = Read-ToolchainZipEntryText -Entry $entryMap[$script:ToolchainDeploymentPackageIndex] | ConvertFrom-Json }
		catch { throw "deployment package index is invalid: $($_.Exception.Message)" }
		if ([int]$index.schemaVersion -ne 1 -or -not $index.name -or -not $index.version -or -not $index.manifest) { throw 'deployment package index has an unsupported schema' }
		Assert-ToolchainDeploymentIdentifier -Value ([string]$index.name) -Kind 'name'
		Assert-ToolchainDeploymentVersion -Version ([string]$index.version)
		$expected = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
		$totalBytes = 0L
		foreach ($file in @($index.files)) {
			$relative = [string]$file.path
			if ($expected.ContainsKey($relative) -or -not $entryMap.ContainsKey($relative)) { throw "deployment package index contains a missing or duplicate file: $relative" }
			if ([string]$file.digest -notmatch '^sha256:[0-9a-f]{64}$' -or [int64]$file.size -lt 0) { throw "deployment package index contains invalid metadata for: $relative" }
			$destination = Resolve-ToolchainChildPath -Root $tempRoot -RelativePath $relative -RejectReparsePoints -RejectRootReparsePoint
			$totalBytes += [int64]$file.size
			if ($totalBytes -gt $script:ToolchainDeploymentPackageMaximumBytes) { throw 'deployment package exceeds the 20 GiB uncompressed size limit' }
			if ($entryMap[$relative].Length -ne [int64]$file.size) { throw "deployment package size verification failed for: $relative" }
			$expected.Add($relative, $file)
			$parent = Split-Path -Parent $destination
			[void][IO.Directory]::CreateDirectory($parent)
			$sourceStream = $entryMap[$relative].Open()
			$output = [IO.File]::Open($destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
			try { $sourceStream.CopyTo($output) } finally { $output.Dispose(); $sourceStream.Dispose() }
			$digest = 'sha256:' + (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
			if (-not [string]::Equals($digest, [string]$file.digest, [StringComparison]::Ordinal)) { throw "deployment package digest verification failed for: $relative" }
		}
		if ($entryMap.Count -ne ($expected.Count + 1)) { throw 'deployment package contains files that are not covered by its integrity index' }
		$manifestPath = Resolve-ToolchainChildPath -Root $tempRoot -RelativePath ([string]$index.manifest) -RejectReparsePoints -RejectRootReparsePoint
		if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'deployment package manifest is missing' }
		$definition = Read-ToolchainDeploymentDefinition -Root $tempRoot
		if (-not [string]::Equals($definition.Name, [string]$index.name, [StringComparison]::Ordinal) -or
			-not [string]::Equals($definition.Version, [string]$index.version, [StringComparison]::Ordinal) -or
			-not [string]::Equals([string]$definition.Architecture, [string]$index.architecture, [StringComparison]::Ordinal)) {
			throw 'deployment package index identity does not match toolchain.yaml'
		}
		$declaredImages = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
		foreach ($image in $definition.Images) { [void]$declaredImages.Add([string]$image.Source) }
		$indexedImages = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
		foreach ($artifact in @($index.images)) {
			$source = [string]$artifact.source
			if (-not $declaredImages.Contains($source) -or -not $indexedImages.Add($source)) { throw "deployment package index contains an undeclared or duplicate image: $source" }
			$null = Resolve-ToolchainDeploymentImageArtifact -Root $tempRoot -Artifact $artifact
		}
		if ($indexedImages.Count -ne $declaredImages.Count) { throw 'deployment package index does not contain every declared image' }
		$archive.Dispose(); $archive = $null
		$fileStream.Dispose(); $fileStream = $null
		return [pscustomobject]@{ Root = $tempRoot; Index = $index; PackagePath = $packagePath }
	} catch {
		if ($archive) { $archive.Dispose(); $archive = $null }
		if ($fileStream) { $fileStream.Dispose(); $fileStream = $null }
		Remove-ToolchainDeploymentTemporaryRoot -Path $tempRoot
		throw
	} finally {
		if ($archive) { $archive.Dispose() }
		if ($fileStream) { $fileStream.Dispose() }
	}
}

function Resolve-ToolchainDeploymentKubeconfig {
	param([string]$Cluster, [string]$Kubeconfig)
	if ($Cluster -and $Kubeconfig) { throw 'package deploy accepts either -Cluster or -Kubeconfig, not both' }
	if ($Cluster -or $Kubeconfig) { return (Resolve-ToolchainBootstrapKubeconfig -Name $Cluster -Kubeconfig $Kubeconfig) }
	$context = Resolve-ToolchainCurrentClusterContext -SelectSingle
	if ($context) { return (Resolve-ToolchainBootstrapKubeconfig -Name ([string]$context.Name)) }
	return $null
}

function Merge-ToolchainDeploymentConfig {
	param(
		[Parameter(Mandatory)][hashtable]$Settings,
		[Parameter(Mandatory)][hashtable]$Variables,
		[Parameter(Mandatory)][string]$Path
	)
	$config = Read-ToolchainDeploymentConfig -Path $Path
	foreach ($key in @('namespace', 'wait', 'waitSeconds', 'createNamespace')) {
		if ($null -ne $config[$key]) { $Settings[$key] = $config[$key] }
	}
	if ($config.variables) {
		foreach ($name in $config.variables.Keys) { $Variables[[string]$name] = $config.variables[$name] }
	}
}

function Resolve-ToolchainDeploymentComponentSelection {
	param(
		[Parameter(Mandatory)]$Definition,
		[string[]]$Components
	)
	$selected = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
	foreach ($component in $Definition.Components) {
		if ($component.Required -or $component.Default) { [void]$selected.Add([string]$component.Name) }
	}
	$requests = @($Components | ForEach-Object { @([string]$_ -split ',') } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
	foreach ($request in $requests) {
		$exclude = $request.StartsWith('-')
		$pattern = if ($exclude) { $request.Substring(1) } else { $request }
		if ([string]::IsNullOrWhiteSpace($pattern)) { throw "invalid component selection '$request'" }
		$matchedComponents = @($Definition.Components | Where-Object { [string]$_.Name -like $pattern })
		if ($matchedComponents.Count -eq 0) { throw "component selection '$request' did not match any package component" }
		foreach ($component in $matchedComponents) {
			if ($exclude) {
				if (-not $component.Required) { [void]$selected.Remove([string]$component.Name) }
			} else {
				[void]$selected.Add([string]$component.Name)
			}
		}
	}
	$resolved = @($Definition.Components | Where-Object { $selected.Contains([string]$_.Name) })
	if ($resolved.Count -eq 0) { throw 'no required, default, or explicitly selected package components remain' }
	return $resolved
}

function ConvertTo-ToolchainDeploymentNativeArgument {
	param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
	if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') { return $Value }
	$builder = New-Object Text.StringBuilder
	[void]$builder.Append('"')
	$slashes = 0
	foreach ($character in $Value.ToCharArray()) {
		if ($character -eq '\') { $slashes++; continue }
		if ($character -eq '"') {
			[void]$builder.Append(('\' * (($slashes * 2) + 1))).Append('"')
			$slashes = 0
			continue
		}
		if ($slashes -gt 0) { [void]$builder.Append(('\' * $slashes)); $slashes = 0 }
		[void]$builder.Append($character)
	}
	if ($slashes -gt 0) { [void]$builder.Append(('\' * ($slashes * 2))) }
	[void]$builder.Append('"')
	return $builder.ToString()
}

function Expand-ToolchainDeploymentActionText {
	param(
		[Parameter(Mandatory)][AllowEmptyString()][string]$Text,
		[Parameter(Mandatory)][hashtable]$Variables,
		[Parameter(Mandatory)]$Definition,
		[Parameter(Mandatory)]$Component,
		[Parameter(Mandatory)][string]$Context
	)
	$expanded = Expand-ToolchainDeploymentVariableText -Text $Text -Variables $Variables -Context $Context
	return $expanded.Replace('###TOOLCHAIN_COMPONENT_NAME###', [string]$Component.Name).
		Replace('###TOOLCHAIN_PKG_NAME###', [string]$Definition.Name).
		Replace('###TOOLCHAIN_PKG_VERSION###', [string]$Definition.Version)
}

function Get-ToolchainDeploymentActionShellCommand {
	param([Parameter(Mandatory)]$Action)
	$runningOnWindows = [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::Windows)
	$runningOnLinux = [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::Linux)
	$shellName = if ($runningOnWindows) { [string]$Action.Shell.Windows } elseif ($runningOnLinux) { [string]$Action.Shell.Linux } else { [string]$Action.Shell.Darwin }
	if (-not $shellName) { $shellName = if ($runningOnWindows) { 'powershell' } else { 'sh' } }
	$command = Get-Command -Name $shellName -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
	if (-not $command) { throw "package action shell '$shellName' was not found on PATH" }
	$prefix = switch ($shellName) {
		'powershell' { @('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command') }
		'pwsh' { @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command') }
		'cmd' { @('/d', '/s', '/c') }
		default { @('-c') }
	}
	return [pscustomobject]@{ Path = [string]$command.Source; Arguments = [string[]]$prefix; Name = $shellName }
}

function Protect-ToolchainDeploymentActionOutput {
	param([AllowEmptyString()][string]$Text, [Parameter(Mandatory)][hashtable]$Variables)
	$protected = [string]$Text
	foreach ($variable in $Variables.Values) {
		if ($variable.Sensitive -and -not [string]::IsNullOrEmpty([string]$variable.Value)) { $protected = $protected.Replace([string]$variable.Value, '***') }
	}
	return $protected
}

function Set-ToolchainDeploymentActionVariables {
	param(
		[Parameter(Mandatory)]$Action,
		[Parameter(Mandatory)][hashtable]$Variables,
		[Parameter(Mandatory)][AllowEmptyString()][string]$Output,
		[Parameter(Mandatory)][string]$WorkingDirectory,
		[Parameter(Mandatory)][string]$Root
	)
	if ($Action.SetVariables.Count -eq 0) { return }
	$value = $Output.TrimEnd([char[]]@("`r", "`n"))
	foreach ($variable in $Action.SetVariables) {
		$resolvedValue = $value
		if ($variable.Type -eq 'file') {
			if ([string]::IsNullOrWhiteSpace($resolvedValue)) { throw "package action output variable '$($variable.Name)' requires a file path" }
			$candidate = if ([IO.Path]::IsPathRooted($resolvedValue)) { [IO.Path]::GetFullPath($resolvedValue) } else { [IO.Path]::GetFullPath((Join-Path $WorkingDirectory $resolvedValue)) }
			$relative = Get-ToolchainDeploymentRelativePath -Root $Root -Path $candidate
			$filePath = Resolve-ToolchainChildPath -Root $Root -RelativePath $relative -RejectReparsePoints -RejectRootReparsePoint
			if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) { throw "package action output variable '$($variable.Name)' file is not a file: $filePath" }
			$fileItem = Get-Item -LiteralPath $filePath -Force
			if ($fileItem.Length -gt 1MB) { throw "package action output variable '$($variable.Name)' file exceeds the 1 MiB limit" }
			$resolvedValue = Get-Content -LiteralPath $filePath -Raw
		}
		if ($variable.Pattern) {
			$matcher = [Text.RegularExpressions.Regex]::new([string]$variable.Pattern, [Text.RegularExpressions.RegexOptions]::None, [TimeSpan]::FromSeconds(1))
			if (-not $matcher.IsMatch([string]$resolvedValue)) { throw "package action output variable '$($variable.Name)' does not match its required pattern" }
		}
		$Variables[[string]$variable.Name] = [pscustomobject]@{
			Name = [string]$variable.Name; Value = [string]$resolvedValue; Sensitive = [bool]$variable.Sensitive
			AutoIndent = [bool]$variable.AutoIndent; Source = 'action'
		}
	}
}

function Invoke-ToolchainDeploymentCommandAction {
	param(
		[Parameter(Mandatory)]$Action,
		[Parameter(Mandatory)][string]$Root,
		[Parameter(Mandatory)]$Definition,
		[Parameter(Mandatory)]$Component,
		[Parameter(Mandatory)][hashtable]$Variables,
		[string]$Kubeconfig,
		[Parameter(Mandatory)][string]$Context
	)
	$commandText = Expand-ToolchainDeploymentActionText -Text ([string]$Action.Cmd) -Variables $Variables -Definition $Definition -Component $Component -Context $Context
	$directoryText = Expand-ToolchainDeploymentActionText -Text ([string]$Action.Dir) -Variables $Variables -Definition $Definition -Component $Component -Context "$Context directory"
	$workingDirectory = if ($directoryText) { Resolve-ToolchainChildPath -Root $Root -RelativePath $directoryText -RejectReparsePoints -RejectRootReparsePoint } else { $Root }
	if (-not (Test-Path -LiteralPath $workingDirectory -PathType Container)) { throw "$Context working directory does not exist: $directoryText" }
	$shell = Get-ToolchainDeploymentActionShellCommand -Action $Action
	$deadline = if ($Action.MaxTotalSeconds -gt 0) { [DateTime]::UtcNow.AddSeconds([int]$Action.MaxTotalSeconds) } else { [DateTime]::MaxValue }
	$lastFailure = $null
	for ($attempt = 0; $attempt -le [int]$Action.MaxRetries; $attempt++) {
		$startInfo = [Diagnostics.ProcessStartInfo]::new()
		$startInfo.FileName = $shell.Path
		$arguments = @($shell.Arguments) + @($commandText)
		$startInfo.Arguments = (@($arguments | ForEach-Object { ConvertTo-ToolchainDeploymentNativeArgument -Value ([string]$_) }) -join ' ')
		$startInfo.WorkingDirectory = $workingDirectory
		$startInfo.UseShellExecute = $false
		$startInfo.CreateNoWindow = $true
		$startInfo.RedirectStandardOutput = $true
		$startInfo.RedirectStandardError = $true
		foreach ($variable in $Variables.Values) { $startInfo.EnvironmentVariables["TOOLCHAIN_VAR_$($variable.Name)"] = [string]$variable.Value }
		$startInfo.EnvironmentVariables['TOOLCHAIN_PACKAGE_NAME'] = [string]$Definition.Name
		$startInfo.EnvironmentVariables['TOOLCHAIN_PACKAGE_VERSION'] = [string]$Definition.Version
		$startInfo.EnvironmentVariables['TOOLCHAIN_COMPONENT_NAME'] = [string]$Component.Name
		$startInfo.EnvironmentVariables['TOOLCHAIN_PACKAGE_ROOT'] = $Root
		if ($Kubeconfig) { $startInfo.EnvironmentVariables['KUBECONFIG'] = $Kubeconfig }
		foreach ($entry in $Action.Env) {
			$separator = $entry.IndexOf('=')
			$name = $entry.Substring(0, $separator)
			$value = Expand-ToolchainDeploymentActionText -Text $entry.Substring($separator + 1) -Variables $Variables -Definition $Definition -Component $Component -Context "$Context environment"
			$startInfo.EnvironmentVariables[$name] = $value
		}
		$process = [Diagnostics.Process]::new()
		$process.StartInfo = $startInfo
		try {
			if (-not $process.Start()) { throw "$Context did not start" }
			$outputTask = $process.StandardOutput.ReadToEndAsync()
			$errorTask = $process.StandardError.ReadToEndAsync()
			$remainingMilliseconds = if ($deadline -eq [DateTime]::MaxValue) { -1 } else { [Math]::Max(0, [int][Math]::Ceiling(($deadline - [DateTime]::UtcNow).TotalMilliseconds)) }
			$completed = if ($remainingMilliseconds -lt 0) { $process.WaitForExit(); $true } else { $process.WaitForExit($remainingMilliseconds) }
			if (-not $completed) { try { $process.Kill() } catch { Write-Debug "Failed to stop timed-out package action: $($_.Exception.Message)" }; $null = $process.WaitForExit(5000) }
			$output = $outputTask.GetAwaiter().GetResult()
			$errorOutput = $errorTask.GetAwaiter().GetResult()
			if ($completed -and $process.ExitCode -eq 0) {
				if (-not $Action.Mute -and $output) { Write-ToolchainInfo (Protect-ToolchainDeploymentActionOutput -Text $output.TrimEnd() -Variables $Variables) }
				Set-ToolchainDeploymentActionVariables -Action $Action -Variables $Variables -Output $output -WorkingDirectory $workingDirectory -Root $Root
				return [pscustomobject]@{ State = 'succeeded'; Output = $output; Attempts = $attempt + 1 }
			}
			$reason = if (-not $completed) { "timed out after $($Action.MaxTotalSeconds) seconds" } elseif ($errorOutput) { "exited with code $($process.ExitCode): $($errorOutput.Trim())" } else { "exited with code $($process.ExitCode)" }
			$lastFailure = Protect-ToolchainDeploymentActionOutput -Text $reason -Variables $Variables
		} finally { $process.Dispose() }
		if ([DateTime]::UtcNow -ge $deadline) { break }
	}
	throw "$Context failed after $([int]$Action.MaxRetries + 1) attempt(s): $lastFailure"
}

function Invoke-ToolchainDeploymentWaitAction {
	param(
		[Parameter(Mandatory)]$Action,
		[string]$Kubectl,
		[string]$Kubeconfig,
		[Parameter(Mandatory)][string]$Context
	)
	$seconds = if ($Action.MaxTotalSeconds -gt 0) { [int]$Action.MaxTotalSeconds } else { 300 }
	if ($Action.Wait.Type -eq 'cluster') {
		if (-not $Kubectl) { throw "$Context requires a Kubernetes deployment context" }
		$resource = "$($Action.Wait.Kind)/$($Action.Wait.Name)"
		$arguments = @()
		if ($Action.Wait.Namespace) { $arguments += @('--namespace', [string]$Action.Wait.Namespace) }
		$condition = [string]$Action.Wait.Condition
		if ($condition -and $condition -ne 'exist') {
			$for = if ($condition.StartsWith('jsonpath=')) { $condition } else { "condition=$condition" }
			$arguments += @('wait', "--for=$for", $resource, '--timeout', "${seconds}s")
			$null = Invoke-ToolchainBootstrapKubectl -Kubectl $Kubectl -Kubeconfig $Kubeconfig -Arguments $arguments
			return [pscustomobject]@{ State = 'succeeded'; Attempts = 1 }
		}
		$deadline = [DateTime]::UtcNow.AddSeconds($seconds)
		do {
			$result = Invoke-ToolchainBootstrapKubectl -Kubectl $Kubectl -Kubeconfig $Kubeconfig -Arguments ($arguments + @('get', $resource, '--request-timeout=5s')) -AllowFailure
			if ($result.ExitCode -eq 0) { return [pscustomobject]@{ State = 'succeeded'; Attempts = 1 } }
			Start-Sleep -Milliseconds 250
		} while ([DateTime]::UtcNow -lt $deadline)
		throw "$Context timed out waiting for $resource to exist"
	}
	$deadline = [DateTime]::UtcNow.AddSeconds($seconds)
	do {
		try {
			if ($Action.Wait.Protocol -eq 'tcp') {
				if ([string]$Action.Wait.Address -notmatch '^\[?(?<host>[^\]]+)\]?:(?<port>[0-9]+)$') { throw 'expected HOST:PORT' }
				$client = [Net.Sockets.TcpClient]::new()
				try {
					$task = $client.ConnectAsync($Matches.host, [int]$Matches.port)
					if ($task.Wait(2000) -and $client.Connected) { return [pscustomobject]@{ State = 'succeeded'; Attempts = 1 } }
				} finally { $client.Dispose() }
			} else {
				Add-Type -AssemblyName System.Net.Http
				$uri = if ([string]$Action.Wait.Address -match '^https?://') { [string]$Action.Wait.Address } else { "$($Action.Wait.Protocol)://$($Action.Wait.Address)" }
				$client = [Net.Http.HttpClient]::new()
				try { $client.Timeout = [TimeSpan]::FromSeconds(2); $response = $client.GetAsync($uri).GetAwaiter().GetResult(); if ([int]$response.StatusCode -eq [int]$Action.Wait.Code) { return [pscustomobject]@{ State = 'succeeded'; Attempts = 1 } } }
				finally { if ($response) { $response.Dispose() }; $client.Dispose() }
			}
		} catch { Write-Debug "$Context is still waiting: $($_.Exception.Message)" }
		Start-Sleep -Milliseconds 250
	} while ([DateTime]::UtcNow -lt $deadline)
	throw "$Context timed out waiting for $($Action.Wait.Protocol)://$($Action.Wait.Address)"
}

function Invoke-ToolchainDeploymentActionPhase {
	param(
		[Parameter(Mandatory)][object[]]$Components,
		[Parameter(Mandatory)][ValidateSet('OnCreate', 'OnDeploy', 'OnRemove')][string]$Lifecycle,
		[Parameter(Mandatory)][ValidateSet('before', 'after', 'onSuccess', 'onFailure')][string]$Phase,
		[Parameter(Mandatory)][string]$Root,
		[Parameter(Mandatory)]$Definition,
		[Parameter(Mandatory)][hashtable]$Variables,
		[string]$Kubectl,
		[string]$Kubeconfig
	)
	$results = [Collections.ArrayList]::new()
	foreach ($component in $Components) {
		$set = $component.Actions.$Lifecycle
		$actions = @($set.$Phase)
		for ($index = 0; $index -lt $actions.Count; $index++) {
			$action = $actions[$index]
			$context = "component '$($component.Name)' $Lifecycle.$Phase action $($index + 1)"
			$label = if ($action.Description) { [string]$action.Description } elseif ($action.Cmd) { [string]$action.Cmd } else { 'wait action' }
			Write-ToolchainInfo "Running package action: $label"
			$outcome = if ($action.Cmd) {
				Invoke-ToolchainDeploymentCommandAction -Action $action -Root $Root -Definition $Definition -Component $component -Variables $Variables -Kubeconfig $Kubeconfig -Context $context
			} else { Invoke-ToolchainDeploymentWaitAction -Action $action -Kubectl $Kubectl -Kubeconfig $Kubeconfig -Context $context }
			[void]$results.Add([pscustomobject]@{ Component = $component.Name; Lifecycle = $Lifecycle; Phase = $Phase; Description = $label; State = $outcome.State; Attempts = $outcome.Attempts })
		}
	}
	return @($results.ToArray())
}

function Get-ToolchainDeploymentAvailableTcpPort {
	$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
	try {
		$listener.Start()
		return ([Net.IPEndPoint]$listener.LocalEndpoint).Port
	} finally { $listener.Stop() }
}

function New-ToolchainDeploymentRegistryTunnel {
	param(
		[Parameter(Mandatory)][string]$Kubectl,
		[string]$Kubeconfig
	)
	Add-Type -AssemblyName System.Net.Http
	$localPort = Get-ToolchainDeploymentAvailableTcpPort
	$arguments = @()
	if ($Kubeconfig) { $arguments += @('--kubeconfig', $Kubeconfig) }
	$arguments += @('port-forward', '-n', 'toolchain-system', 'service/toolchain-registry-gateway', "${localPort}:5000", '--address', '127.0.0.1')
	$startInfo = [Diagnostics.ProcessStartInfo]::new()
	$startInfo.FileName = $Kubectl
	$startInfo.Arguments = (@($arguments | ForEach-Object { ConvertTo-ToolchainDeploymentNativeArgument -Value ([string]$_) }) -join ' ')
	$startInfo.UseShellExecute = $false
	$startInfo.CreateNoWindow = $true
	$startInfo.RedirectStandardOutput = $true
	$startInfo.RedirectStandardError = $true
	$process = [Diagnostics.Process]::new()
	$process.StartInfo = $startInfo
	$baseUri = "http://127.0.0.1:$localPort"
	$handler = $null
	$client = $null
	try {
		if (-not $process.Start()) { throw 'kubectl port-forward did not start' }
		$handler = [Net.Http.HttpClientHandler]::new()
		$handler.UseProxy = $false
		$client = [Net.Http.HttpClient]::new($handler)
		$client.Timeout = [TimeSpan]::FromSeconds(1)
		$deadline = [DateTime]::UtcNow.AddSeconds(15)
		while ([DateTime]::UtcNow -lt $deadline) {
			if ($process.HasExited) { break }
			$request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get, "$baseUri/v2/")
			$response = $null
			try {
				$response = $client.SendAsync($request).GetAwaiter().GetResult()
				if ($response.IsSuccessStatusCode) {
					return [pscustomobject]@{ Process = $process; BaseUri = $baseUri; LocalPort = $localPort }
				}
			} catch { Write-Debug "Waiting for Toolchain registry tunnel: $($_.Exception.Message)" }
			finally { if ($response) { $response.Dispose() }; $request.Dispose() }
			Start-Sleep -Milliseconds 100
		}
		$errorText = ''
		if ($process.HasExited) { $errorText = $process.StandardError.ReadToEnd().Trim() }
		if (-not $errorText) { $errorText = 'the registry endpoint did not become ready within 15 seconds' }
		throw "could not connect to the Toolchain registry through Kubernetes: $errorText"
	} catch {
		if (-not $process.HasExited) { try { $process.Kill() } catch { Write-Debug "Failed to stop registry tunnel: $($_.Exception.Message)" } }
		$process.Dispose()
		throw
	} finally {
		if ($client) { $client.Dispose() }
		if ($handler) { $handler.Dispose() }
	}
}

function Remove-ToolchainDeploymentRegistryTunnel {
	param([Parameter(Mandatory)]$Tunnel)
	$process = $Tunnel.Process
	if (-not $process) { return }
	try {
		if (-not $process.HasExited) {
			$process.Kill()
			$null = $process.WaitForExit(5000)
		}
	} catch { Write-Debug "Failed to stop Toolchain registry tunnel: $($_.Exception.Message)" }
	finally { $process.Dispose() }
}

function Invoke-ToolchainDeploymentRegistryRequest {
	param(
		[Parameter(Mandatory)][ValidateSet('HEAD', 'POST', 'PUT')][string]$Method,
		[Parameter(Mandatory)][string]$Uri,
		[Parameter(Mandatory)][string]$AuthHeader,
		[string]$FilePath,
		[byte[]]$Body,
		[string]$ContentType = 'application/octet-stream',
		[switch]$AllowNotFound
	)
	Add-Type -AssemblyName System.Net.Http
	$handler = [Net.Http.HttpClientHandler]::new()
	$handler.UseProxy = $false
	$client = [Net.Http.HttpClient]::new($handler)
	$client.Timeout = [Threading.Timeout]::InfiniteTimeSpan
	$request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::new($Method), [Uri]::new($Uri))
	$stream = $null
	$response = $null
	try {
		$request.Headers.TryAddWithoutValidation('Authorization', $AuthHeader) | Out-Null
		if ($FilePath) {
			$stream = [IO.File]::Open($FilePath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
			$request.Content = [Net.Http.StreamContent]::new($stream)
		} elseif ($null -ne $Body) {
			$request.Content = [Net.Http.ByteArrayContent]::new($Body)
		} elseif ($Method -in @('POST', 'PUT')) {
			$request.Content = [Net.Http.ByteArrayContent]::new([byte[]]@())
		}
		if ($request.Content) { $request.Content.Headers.ContentType = [Net.Http.Headers.MediaTypeHeaderValue]::new($ContentType) }
		$response = $client.SendAsync($request, [Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
		$statusCode = [int]$response.StatusCode
		if (-not $response.IsSuccessStatusCode -and -not ($AllowNotFound -and $statusCode -eq 404)) {
			$detail = if ($response.Content) { $response.Content.ReadAsStringAsync().GetAwaiter().GetResult() } else { '' }
			if ($detail.Length -gt 500) { $detail = $detail.Substring(0, 500) }
			throw "registry request $Method $Uri failed with HTTP $statusCode$(if ($detail) { ": $detail" })"
		}
		$location = if ($response.Headers.Location) { [string]$response.Headers.Location } else { $null }
		$digest = if ($response.Headers.Contains('Docker-Content-Digest')) { [string](@($response.Headers.GetValues('Docker-Content-Digest'))[0]) } else { $null }
		return [pscustomobject]@{ StatusCode = $statusCode; Location = $location; Digest = $digest }
	} finally {
		if ($response) { $response.Dispose() }
		$request.Dispose()
		if ($stream) { $stream.Dispose() }
		$client.Dispose()
		$handler.Dispose()
	}
}

function Send-ToolchainDeploymentRegistryBlob {
	param(
		[Parameter(Mandatory)][string]$BaseUri,
		[Parameter(Mandatory)][string]$Repository,
		[Parameter(Mandatory)][string]$Digest,
		[Parameter(Mandatory)][string]$Path,
		[Parameter(Mandatory)][string]$AuthHeader
	)
	$head = Invoke-ToolchainDeploymentRegistryRequest -Method HEAD -Uri "$BaseUri/v2/$Repository/blobs/$Digest" -AuthHeader $AuthHeader -AllowNotFound
	if ($head.StatusCode -eq 200) { return }
	$started = Invoke-ToolchainDeploymentRegistryRequest -Method POST -Uri "$BaseUri/v2/$Repository/blobs/uploads/" -AuthHeader $AuthHeader
	if (-not $started.Location) { throw "Toolchain registry did not return an upload location for $Digest" }
	$location = [Uri]::new([Uri]::new("$BaseUri/"), $started.Location)
	$base = [Uri]::new($BaseUri)
	if ($location.Host -ne $base.Host -or $location.Port -ne $base.Port) { throw 'Toolchain registry returned an unsafe cross-host upload location' }
	$builder = [UriBuilder]::new($location)
	$digestQuery = 'digest=' + [Uri]::EscapeDataString($Digest)
	$builder.Query = if ($builder.Query.TrimStart('?')) { $builder.Query.TrimStart('?') + '&' + $digestQuery } else { $digestQuery }
	$null = Invoke-ToolchainDeploymentRegistryRequest -Method PUT -Uri $builder.Uri.AbsoluteUri -AuthHeader $AuthHeader -FilePath $Path
}

function Publish-ToolchainDeploymentImages {
	param(
		[Parameter(Mandatory)]$Definition,
		[Parameter(Mandatory)][object[]]$Components,
		[Parameter(Mandatory)][string]$Root,
		[AllowNull()]$PackageIndex,
		[Parameter(Mandatory)][string]$Kubectl,
		[string]$Kubeconfig,
		[switch]$DryRun
	)
	$selectedImages = @($Components | ForEach-Object { $_.Images })
	if ($selectedImages.Count -eq 0) { return @() }
	if ($DryRun) {
		return @($selectedImages | ForEach-Object { [pscustomobject]@{ Component = $_.Component; Source = $_.Source; Target = $null; State = 'planned' } })
	}

	$imageTemporaryRoot = $null
	$tunnel = $null
	try {
		$artifacts = @()
		$artifactRoot = $Root
		if ($null -ne $PackageIndex) {
			$artifacts = @($PackageIndex.images)
		} else {
			$imageTemporaryRoot = New-ToolchainDeploymentImageTemporaryRoot
			$imageLayoutParameters = @{ Images = $selectedImages; LayoutRoot = $imageTemporaryRoot }
			if ($Definition.Architecture) { $imageLayoutParameters.Architecture = $Definition.Architecture }
			$layout = New-ToolchainDeploymentImageLayout @imageLayoutParameters
			$artifacts = @($layout.Images)
			$artifactRoot = $imageTemporaryRoot
		}
		$artifactsBySource = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
		foreach ($artifact in $artifacts) { $artifactsBySource.Add([string]$artifact.source, $artifact) }

		$stateJson = Get-ToolchainBootstrapSecretValue -Kubectl $Kubectl -Kubeconfig $Kubeconfig -Secret 'toolchain-state' -Key 'state.json'
		if (-not $stateJson) { throw "Toolchain cluster services are not initialized; run 'tlc cluster init -Confirm' before deploying package images" }
		try { $state = $stateJson | ConvertFrom-Json }
		catch { throw "Toolchain cluster state is invalid: $($_.Exception.Message)" }
		$registryAddress = [string]$state.registryAddress
		if ($registryAddress -cnotmatch '^127\.0\.0\.1:(?:3[01][0-9]{3}|32[0-6][0-9]{2}|327(?:[0-5][0-9]|6[0-7]))$') { throw "Toolchain cluster state contains an unsupported registry address: $registryAddress" }
		$username = Get-ToolchainBootstrapSecretValue -Kubectl $Kubectl -Kubeconfig $Kubeconfig -Secret 'toolchain-registry-credentials' -Key 'username'
		$password = Get-ToolchainBootstrapSecretValue -Kubectl $Kubectl -Kubeconfig $Kubeconfig -Secret 'toolchain-registry-credentials' -Key 'password'
		if (-not $username -or -not $password) { throw 'Toolchain registry credentials are missing; rerun cluster init to repair cluster services' }
		$authHeader = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("${username}:${password}"))
		$tunnel = New-ToolchainDeploymentRegistryTunnel -Kubectl $Kubectl -Kubeconfig $Kubeconfig

		$published = [Collections.ArrayList]::new()
		$targets = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
		foreach ($image in $selectedImages) {
			$source = [string]$image.Source
			if ($targets.ContainsKey($source)) {
				[void]$published.Add([pscustomobject]@{ Component = $image.Component; Source = $source; Target = $targets[$source]; State = 'published' })
				continue
			}
			if (-not $artifactsBySource.ContainsKey($source)) { throw "deployment package has no bundled content for image '$source'" }
			$resolved = Resolve-ToolchainDeploymentImageArtifact -Root $artifactRoot -Artifact $artifactsBySource[$source]
			$key = Get-ToolchainDeploymentStringSha256 -Value $source
			$repository = "toolchain/packages/$($Definition.Name)/$key"
			foreach ($blob in $resolved.Blobs) {
				Send-ToolchainDeploymentRegistryBlob -BaseUri $tunnel.BaseUri -Repository $repository -Digest $blob.Digest -Path $blob.Path -AuthHeader $authHeader
			}
			$manifestBytes = [IO.File]::ReadAllBytes($resolved.ManifestPath)
			$manifestResult = Invoke-ToolchainDeploymentRegistryRequest -Method PUT -Uri "$($tunnel.BaseUri)/v2/$repository/manifests/$key" -AuthHeader $authHeader -Body $manifestBytes -ContentType 'application/vnd.docker.distribution.manifest.v2+json'
			if ($manifestResult.Digest -and -not [string]::Equals($manifestResult.Digest, $resolved.ManifestDigest, [StringComparison]::Ordinal)) {
				throw "Toolchain registry returned an unexpected manifest digest for '$source'"
			}
			$target = "$registryAddress/$repository@$($resolved.ManifestDigest)"
			$targets.Add($source, $target)
			[void]$published.Add([pscustomobject]@{ Component = $image.Component; Source = $source; Target = $target; State = 'published' })
			Write-ToolchainInfo "Published package image '$source' to the Toolchain cluster registry."
		}

		$mappingResult = Invoke-ToolchainBootstrapKubectl -Kubectl $Kubectl -Kubeconfig $Kubeconfig -Arguments @('get', 'configmap/toolchain-image-mappings', '-n', 'toolchain-system', '-o', 'jsonpath={.data.mappings\.json}')
		$mappingJson = ($mappingResult.Output -join '').Trim()
		try { $mappingObject = if ($mappingJson) { $mappingJson | ConvertFrom-Json } else { [pscustomobject]@{} } }
		catch { throw "Toolchain image mappings are invalid: $($_.Exception.Message)" }
		$mappings = [ordered]@{}
		if ($null -eq $mappingObject -or $mappingObject -is [array] -or $mappingObject -is [string] -or $mappingObject -is [ValueType]) { throw 'Toolchain image mappings must be a JSON object' }
		foreach ($property in $mappingObject.PSObject.Properties) {
			$existingSource = [string]$property.Name
			$existingTarget = [string]$property.Value
			if ([string]::IsNullOrWhiteSpace($existingSource) -or [string]::IsNullOrWhiteSpace($existingTarget) -or ($existingSource + $existingTarget) -match '[\s\x00-\x1f]') {
				throw 'Toolchain image mappings contain an invalid existing entry'
			}
			$mappings[$existingSource] = $existingTarget
		}
		foreach ($source in $targets.Keys) { $mappings[$source] = $targets[$source] }
		$updatedMappings = $mappings | ConvertTo-Json -Compress
		if ([Text.Encoding]::UTF8.GetByteCount($updatedMappings) -gt 900KB) { throw 'Toolchain image mappings exceed the safe ConfigMap size limit' }
		$patch = [ordered]@{ data = [ordered]@{ 'mappings.json' = $updatedMappings } } | ConvertTo-Json -Depth 5 -Compress
		$null = Invoke-ToolchainBootstrapKubectl -Kubectl $Kubectl -Kubeconfig $Kubeconfig -Arguments @('patch', 'configmap/toolchain-image-mappings', '-n', 'toolchain-system', '--type', 'merge', '--patch', $patch)
		$null = Invoke-ToolchainBootstrapKubectl -Kubectl $Kubectl -Kubeconfig $Kubeconfig -Arguments @('rollout', 'restart', 'deployment/toolchain-agent', '-n', 'toolchain-system')
		$null = Invoke-ToolchainBootstrapKubectl -Kubectl $Kubectl -Kubeconfig $Kubeconfig -Arguments @('rollout', 'status', 'deployment/toolchain-agent', '-n', 'toolchain-system', '--timeout=120s')
		return @($published.ToArray())
	} finally {
		if ($tunnel) { Remove-ToolchainDeploymentRegistryTunnel -Tunnel $tunnel }
		if ($imageTemporaryRoot) { Remove-ToolchainDeploymentImageTemporaryRoot -Path $imageTemporaryRoot }
	}
}

function Invoke-ToolchainDeploymentBundle {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)][string]$Root,
		[AllowNull()]$PackageIndex,
		[string]$Cluster,
		[string]$Kubeconfig,
		[string[]]$Components,
		[string[]]$Set,
		[string[]]$Values,
		[string]$Config,
		[string]$Namespace,
		[int]$WaitSeconds,
		[switch]$OverrideWaitSeconds,
		[switch]$DryRun,
		[switch]$PassThru
	)
	$definition = Read-ToolchainDeploymentDefinition -Root $Root
	$selectedComponents = @(Resolve-ToolchainDeploymentComponentSelection -Definition $definition -Components $Components)
	$settings = @{
		namespace = if ($definition.Namespace) { $definition.Namespace } else { 'default' }
		wait = $true
		waitSeconds = 300
		createNamespace = $true
	}
	$configuredVariables = @{}
	$internalConfig = Join-Path $Root 'toolchain-config.yaml'
	if (Test-Path -LiteralPath $internalConfig -PathType Leaf) { Merge-ToolchainDeploymentConfig -Settings $settings -Variables $configuredVariables -Path $internalConfig }
	if ($Config) { Merge-ToolchainDeploymentConfig -Settings $settings -Variables $configuredVariables -Path (Resolve-ToolchainFileSystemPath -Path $Config) }
	if ($Namespace) { Assert-ToolchainDeploymentIdentifier -Value $Namespace -Kind 'namespace'; $settings.namespace = $Namespace }
	if ($OverrideWaitSeconds) { $settings.waitSeconds = $WaitSeconds }
	$overrides = ConvertFrom-ToolchainDeploymentSet -Set $Set
	$resolvedVariables = Resolve-ToolchainDeploymentVariables -Definition $definition -Root $Root -Configured $configuredVariables -Overrides $overrides
	$externalValues = @()
	foreach ($valuesPath in @($Values | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })) {
		$fullValuesPath = Resolve-ToolchainFileSystemPath -Path ([string]$valuesPath)
		if (-not (Test-Path -LiteralPath $fullValuesPath -PathType Leaf)) { throw "Helm values file is not a file: $fullValuesPath" }
		$externalValues += $fullValuesPath
	}
	$globalValues = @()
	foreach ($valuesPath in $definition.GlobalValues) {
		$globalValues += Resolve-ToolchainChildPath -Root $Root -RelativePath $valuesPath -RejectReparsePoints -RejectRootReparsePoint
	}

	$selectedCharts = @($selectedComponents | ForEach-Object { $_.Charts })
	$chartTemporaryRoot = Initialize-ToolchainDeploymentRemoteCharts -Definition $definition -Charts $selectedCharts
	$renderRoot = New-ToolchainDeploymentRenderRoot
	$deployActionsStarted = $false
	$deployActionResults = [Collections.ArrayList]::new()
	try {
	$kubeconfigPath = Resolve-ToolchainDeploymentKubeconfig -Cluster $Cluster -Kubeconfig $Kubeconfig
	$kubectl = Get-ToolchainClusterExecutable -Name kubectl -Package kubectl -InstallHint 'Install kubectl and ensure its executable is available on PATH.'
	$apiServer = Get-ToolchainBootstrapApiServer -Kubeconfig $kubeconfigPath
	try { $null = Invoke-ToolchainBootstrapKubectl -Kubectl $kubectl -Kubeconfig $kubeconfigPath -Arguments @('get', '--request-timeout=10s', '--raw=/readyz') }
	catch { throw "Kubernetes API preflight failed for package deployment at $apiServer. kubectl reported: $($_.Exception.Message)" }
	if (-not $DryRun) {
		$deployActionsStarted = $true
		foreach ($actionResult in @(Invoke-ToolchainDeploymentActionPhase -Components $selectedComponents -Lifecycle OnDeploy -Phase before -Root $Root -Definition $definition -Variables $resolvedVariables -Kubectl $kubectl -Kubeconfig $kubeconfigPath)) { [void]$deployActionResults.Add($actionResult) }
	}

	$appliedManifests = [Collections.ArrayList]::new()
	$releases = [Collections.ArrayList]::new()
	$publishedImages = @(Publish-ToolchainDeploymentImages -Definition $definition -Components $selectedComponents -Root $Root -PackageIndex $PackageIndex -Kubectl $kubectl -Kubeconfig $kubeconfigPath -DryRun:$DryRun)
	$helm = $null
	$conventionalValues = Join-Path $Root 'toolchain-values.yaml'
	foreach ($component in $selectedComponents) {
		foreach ($manifestSet in $component.ManifestSets) {
			foreach ($manifestPath in $manifestSet.Files) {
				foreach ($file in @(Get-ToolchainDeploymentSourceFiles -Root $Root -RelativePath $manifestPath -YamlOnly)) {
					$renderedManifestPath = Get-ToolchainDeploymentRenderedFile -Path $file.FullName -Variables $resolvedVariables -RenderRoot $renderRoot -Context "manifest $($manifestSet.Name)"
					$arguments = @('apply', '--server-side', '--field-manager=toolchain-package')
					if ($DryRun) { $arguments += '--dry-run=server' }
					$manifestNamespace = if ($Namespace) { [string]$settings.namespace } else { [string]$manifestSet.Namespace }
					if ($manifestNamespace) { $arguments += @('--namespace', $manifestNamespace) }
					$arguments += @('-f', $renderedManifestPath)
					$null = Invoke-ToolchainBootstrapKubectl -Kubectl $kubectl -Kubeconfig $kubeconfigPath -Arguments $arguments
					[void]$appliedManifests.Add([pscustomobject]@{
						Component = $component.Name
						Name = $manifestSet.Name
						Path = Get-ToolchainDeploymentRelativePath -Root $Root -Path $file.FullName
						Namespace = $manifestNamespace
					})
				}
			}
		}
		if ($component.Charts.Count -gt 0 -and -not $helm) {
			$helm = Get-ToolchainClusterExecutable -Name helm -Package helm -InstallHint 'Install Helm and ensure its executable is available on PATH.'
		}
		foreach ($chart in $component.Charts) {
			$sourceChartPath = Get-ToolchainDeploymentChartSourcePath -Definition $definition -Chart $chart
			$chartPath = Get-ToolchainDeploymentRenderedChart -Path $sourceChartPath -Variables $resolvedVariables -RenderRoot $renderRoot -Context "chart $($chart.Release)"
			$releaseNamespace = if ($Namespace) { [string]$settings.namespace } elseif ($chart.Namespace) { $chart.Namespace } else { [string]$settings.namespace }
			$arguments = @('upgrade', '--install', $chart.Release, $chartPath, '--namespace', $releaseNamespace)
			if ([bool]$settings.createNamespace) { $arguments += '--create-namespace' }
			foreach ($valuesPath in $chart.Values) {
				$sourceValuesPath = Resolve-ToolchainChildPath -Root $Root -RelativePath $valuesPath -RejectReparsePoints -RejectRootReparsePoint
				$arguments += @('--values', (Get-ToolchainDeploymentRenderedFile -Path $sourceValuesPath -Variables $resolvedVariables -RenderRoot $renderRoot -Context "chart values $valuesPath"))
			}
			foreach ($valuesPath in $globalValues) { $arguments += @('--values', (Get-ToolchainDeploymentRenderedFile -Path $valuesPath -Variables $resolvedVariables -RenderRoot $renderRoot -Context "package values $valuesPath")) }
			if (Test-Path -LiteralPath $conventionalValues -PathType Leaf) { $arguments += @('--values', (Get-ToolchainDeploymentRenderedFile -Path $conventionalValues -Variables $resolvedVariables -RenderRoot $renderRoot -Context 'toolchain-values.yaml')) }
			$chartVariableValues = New-ToolchainDeploymentChartVariableValues -Chart $chart -Variables $resolvedVariables -RenderRoot $renderRoot
			if ($chartVariableValues) { $arguments += @('--values', $chartVariableValues) }
			foreach ($valuesPath in $externalValues) { $arguments += @('--values', (Get-ToolchainDeploymentRenderedFile -Path $valuesPath -Variables $resolvedVariables -RenderRoot $renderRoot -Context "external values $valuesPath")) }
			if (-not $chart.SchemaValidation) { $arguments += '--skip-schema-validation' }
			if ($DryRun) { $arguments += '--dry-run' }
			elseif ([bool]$settings.wait -and $chart.Wait) { $arguments += @('--wait', '--timeout', "$($settings.waitSeconds)s") }
			if ($kubeconfigPath) { $arguments += @('--kubeconfig', $kubeconfigPath) }
			$null = Invoke-ToolchainClusterProcess -FilePath $helm -Arguments $arguments
			[void]$releases.Add([pscustomobject]@{ Component = $component.Name; Name = $chart.Release; Namespace = $releaseNamespace; Chart = $chart.Path })
		}
	}
	if (-not $DryRun) {
		foreach ($actionResult in @(Invoke-ToolchainDeploymentActionPhase -Components $selectedComponents -Lifecycle OnDeploy -Phase after -Root $Root -Definition $definition -Variables $resolvedVariables -Kubectl $kubectl -Kubeconfig $kubeconfigPath)) { [void]$deployActionResults.Add($actionResult) }
		foreach ($actionResult in @(Invoke-ToolchainDeploymentActionPhase -Components $selectedComponents -Lifecycle OnDeploy -Phase onSuccess -Root $Root -Definition $definition -Variables $resolvedVariables -Kubectl $kubectl -Kubeconfig $kubeconfigPath)) { [void]$deployActionResults.Add($actionResult) }
	}
	$result = [pscustomobject]@{
		PSTypeName = 'Toolchain.DeploymentResult'
		Name = $definition.Name
		Version = $definition.Version
		Architecture = $definition.Architecture
		Cluster = if ($Cluster) { $Cluster } else { 'current-context' }
		Kubeconfig = $kubeconfigPath
		Namespace = [string]$settings.namespace
		DryRun = [bool]$DryRun
		Components = @($selectedComponents | ForEach-Object { $_.Name })
		Variables = @($resolvedVariables.Keys | Sort-Object)
		Actions = @($deployActionResults.ToArray())
		Images = $publishedImages
		Releases = @($releases.ToArray())
		Manifests = @($appliedManifests.ToArray() | ForEach-Object { $_.Path })
		ManifestDetails = @($appliedManifests.ToArray())
	}
	$suffix = if ($DryRun) { ' (dry run)' } else { '' }
	Write-ToolchainInfo "Deployed Toolchain package '$($result.Name):$($result.Version)' to $($result.Cluster)$suffix."
	if ($PassThru) { return $result }
	} catch {
		$originalError = $_
		if ($deployActionsStarted -and -not $DryRun) {
			try { $null = Invoke-ToolchainDeploymentActionPhase -Components $selectedComponents -Lifecycle OnDeploy -Phase onFailure -Root $Root -Definition $definition -Variables $resolvedVariables -Kubectl $kubectl -Kubeconfig $kubeconfigPath }
			catch { Write-Warning "Package onDeploy failure action also failed: $($_.Exception.Message)" }
		}
		throw $originalError
	} finally {
		Remove-ToolchainDeploymentRenderRoot -Path $renderRoot
		if ($chartTemporaryRoot) { Remove-ToolchainDeploymentChartTemporaryRoot -Path $chartTemporaryRoot }
	}
}

function Invoke-ToolchainDeploymentPackage {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory, Position = 0)][ValidateSet('create', 'deploy')][string]$Command,
		[Parameter(Position = 1)][string]$Path,
		[string]$Output,
		[string]$Cluster,
		[string]$Kubeconfig,
		[string[]]$Components,
		[string[]]$Set,
		[string[]]$Values,
		[string]$Config,
		[string]$Namespace,
		[ValidateRange(1, 3600)][int]$WaitSeconds = 300,
		[switch]$Confirm,
		[switch]$Force,
		[switch]$DryRun,
		[switch]$PassThru
	)
	if ($Command -eq 'create') {
		if ($Cluster -or $Kubeconfig -or $Components -or $Set -or $Values -or $Config -or $Namespace -or $DryRun) { throw 'package create does not accept deployment target options' }
		$source = if ($Path) { $Path } else { (Get-Location).Path }
		return (New-ToolchainDeploymentPackage -Path $source -Output $Output -Force:$Force)
	}
	if (-not $Path) { throw 'package deploy requires a .tlcpkg file or source directory' }
	if ($Output -or $Force) { throw 'package deploy does not accept -Output or -Force' }
	if (-not $Confirm -and -not $DryRun) { throw "package deploy changes Kubernetes cluster state; rerun with -Confirm after reviewing 'tlc package deploy help'" }
	$root = $null
	$temporaryRoot = $null
	$packageIndex = $null
	try {
		$fullPath = Resolve-ToolchainFileSystemPath -Path $Path
		if (Test-Path -LiteralPath $fullPath -PathType Container) {
			$root = $fullPath
		} else {
			$expanded = Expand-ToolchainDeploymentPackage -Path $fullPath
			$root = $expanded.Root
			$temporaryRoot = $expanded.Root
			$packageIndex = $expanded.Index
		}
		$params = @{
			Root = $root
			PackageIndex = $packageIndex
			Cluster = $Cluster
			Kubeconfig = $Kubeconfig
			Components = $Components
			Set = $Set
			Values = $Values
			Config = $Config
			DryRun = $DryRun
			PassThru = $PassThru
		}
		if ($PSBoundParameters.ContainsKey('Namespace')) { $params.Namespace = $Namespace }
		if ($PSBoundParameters.ContainsKey('WaitSeconds')) { $params.WaitSeconds = $WaitSeconds; $params.OverrideWaitSeconds = $true }
		return (Invoke-ToolchainDeploymentBundle @params)
	} finally {
		if ($temporaryRoot) { Remove-ToolchainDeploymentTemporaryRoot -Path $temporaryRoot }
	}
}
