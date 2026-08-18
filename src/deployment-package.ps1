<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

$script:ToolchainDeploymentPackageIndex = 'toolchain.package.json'
$script:ToolchainDeploymentPackageMaximumFiles = 10000
$script:ToolchainDeploymentPackageMaximumBytes = 2GB

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
	if ($Value -is [string]) {
		$path = [string]$Value
	} elseif ($Value -is [Collections.IDictionary]) {
		foreach ($key in $Value.Keys) {
			if ([string]$key -notin @('path', 'release', 'namespace', 'values', 'name', 'version', 'url', 'repoName', 'gitPath', 'localPath', 'releaseName', 'noWait', 'valuesFiles', 'variables', 'schemaValidation', 'serverSideApply')) {
				throw "deployment chart $Index contains unsupported key '$key'"
			}
		}
		$path = if ($Value['path']) { [string]$Value['path'] } else { [string]$Value['localPath'] }
		$release = if ($Value['release']) { [string]$Value['release'] } else { [string]$Value['releaseName'] }
		$namespace = [string]$Value['namespace']
		$chartName = [string]$Value['name']
		if ($null -ne $Value['values']) { $values += @($Value['values']) }
		if ($null -ne $Value['valuesFiles']) { $values += @($Value['valuesFiles']) }
		if ($Value['url'] -or $Value['repoName'] -or $Value['gitPath']) {
			throw "deployment chart $Index is remote; Toolchain packages currently require localPath so the chart can be integrity-indexed for offline deployment"
		}
		if ($null -ne $Value['variables'] -and @($Value['variables']).Count -gt 0) {
			throw "deployment chart $Index uses chart variables that Toolchain does not support; use valuesFiles or toolchain-values.yaml"
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
		Release = $release
		Namespace = $namespace
		Values = [string[]]$normalizedValues
		Wait = $wait
		SchemaValidation = $schemaValidation
		Component = $ComponentName
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
	foreach ($unsupported in @('only', 'group', 'import', 'images', 'imageArchives', 'repos', 'files', 'dataInjections', 'actions', 'scripts', 'healthChecks')) {
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
	if ($charts.Count -eq 0 -and $manifestSets.Count -eq 0) { throw "deployment component '$name' must declare at least one chart or manifest" }
	return [pscustomobject]@{
		Name = $name
		Description = [string]$Value['description']
		Required = [bool]$Value['required']
		Default = [bool]$Value['default']
		Charts = [object[]]$charts
		ManifestSets = [object[]]$manifestSets
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
	foreach ($unsupportedTopLevel in @('constants', 'variables', 'build')) {
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
	Assert-ToolchainDeploymentIdentifier -Value $name -Kind 'name'
	Assert-ToolchainDeploymentVersion -Version $version
	if ($namespace) { Assert-ToolchainDeploymentIdentifier -Value $namespace -Kind 'namespace' }

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
	$allManifestSets = @($components | ForEach-Object { $_.ManifestSets })
	$allManifests = @($allManifestSets | ForEach-Object { $_.Files })
	return [pscustomobject]@{
		Root = $rootPath
		ManifestPath = $manifestPath
		Name = $name
		Version = $version
		Description = $description
		Namespace = $namespace
		Components = [object[]]$components
		Charts = [object[]]$allCharts
		ManifestSets = [object[]]$allManifestSets
		Manifests = [string[]]$allManifests
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
		if ([string]$key -notin @('schemaVersion', 'namespace', 'wait', 'waitSeconds', 'createNamespace')) {
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
	return $config
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
		param([Parameter(Mandatory)][IO.FileInfo]$File)
		$relative = Get-ToolchainDeploymentRelativePath -Root $Definition.Root -Path $File.FullName
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
		foreach ($file in @(Get-ToolchainDeploymentSourceFiles -Root $Definition.Root -RelativePath $chart.Path)) { AddBundleFile -File $file }
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
	foreach ($chart in $Definition.Charts) {
		$chartPath = Resolve-ToolchainChildPath -Root $Definition.Root -RelativePath $chart.Path -RejectReparsePoints -RejectRootReparsePoint
		if ((Test-Path -LiteralPath $chartPath -PathType Container) -and -not (Test-Path -LiteralPath (Join-Path $chartPath 'Chart.yaml') -PathType Leaf)) {
			throw "Helm chart directory is missing Chart.yaml: $($chart.Path)"
		}
		if ((Test-Path -LiteralPath $chartPath -PathType Leaf) -and [IO.Path]::GetExtension($chartPath) -ine '.tgz') {
			throw "packaged Helm charts must use the .tgz extension: $($chart.Path)"
		}
		$arguments = @('lint', $chartPath)
		foreach ($valuesPath in $chart.Values) {
			$arguments += @('--values', (Resolve-ToolchainChildPath -Root $Definition.Root -RelativePath $valuesPath -RejectReparsePoints -RejectRootReparsePoint))
		}
		foreach ($valuesPath in $Definition.GlobalValues) {
			$arguments += @('--values', (Resolve-ToolchainChildPath -Root $Definition.Root -RelativePath $valuesPath -RejectReparsePoints -RejectRootReparsePoint))
		}
		if (Test-Path -LiteralPath $conventionalValues -PathType Leaf) { $arguments += @('--values', $conventionalValues) }
		if (-not $chart.SchemaValidation) { $arguments += '--skip-schema-validation' }
		$null = Invoke-ToolchainClusterProcess -FilePath $helm -Arguments $arguments
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
	Test-ToolchainDeploymentCharts -Definition $definition
	$files = Get-ToolchainDeploymentBundleFiles -Definition $definition
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
		if ($totalBytes -gt $script:ToolchainDeploymentPackageMaximumBytes) { throw 'deployment bundle exceeds the 2 GiB uncompressed size limit' }
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
		manifest = 'toolchain.yaml'
		components = @($definition.Components | ForEach-Object { $_.Name })
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
		Path = $outputPath
		Digest = 'sha256:' + (Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash.ToLowerInvariant()
		Files = $entries.Count
		Components = @($definition.Components | ForEach-Object { $_.Name })
		Charts = $definition.Charts.Count
		Manifests = $definition.Manifests.Count
	}
	Write-ToolchainInfo "Created Toolchain deployment package '$($result.Name):$($result.Version)' at $outputPath."
	return $result
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
			if ($totalBytes -gt $script:ToolchainDeploymentPackageMaximumBytes) { throw 'deployment package exceeds the 2 GiB uncompressed size limit' }
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
			-not [string]::Equals($definition.Version, [string]$index.version, [StringComparison]::Ordinal)) {
			throw 'deployment package index identity does not match toolchain.yaml'
		}
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
	param([Parameter(Mandatory)][hashtable]$Settings, [Parameter(Mandatory)][string]$Path)
	$config = Read-ToolchainDeploymentConfig -Path $Path
	foreach ($key in @('namespace', 'wait', 'waitSeconds', 'createNamespace')) {
		if ($null -ne $config[$key]) { $Settings[$key] = $config[$key] }
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

function Invoke-ToolchainDeploymentBundle {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)][string]$Root,
		[string]$Cluster,
		[string]$Kubeconfig,
		[string[]]$Components,
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
	$internalConfig = Join-Path $Root 'toolchain-config.yaml'
	if (Test-Path -LiteralPath $internalConfig -PathType Leaf) { Merge-ToolchainDeploymentConfig -Settings $settings -Path $internalConfig }
	if ($Config) { Merge-ToolchainDeploymentConfig -Settings $settings -Path (Resolve-ToolchainFileSystemPath -Path $Config) }
	if ($Namespace) { Assert-ToolchainDeploymentIdentifier -Value $Namespace -Kind 'namespace'; $settings.namespace = $Namespace }
	if ($OverrideWaitSeconds) { $settings.waitSeconds = $WaitSeconds }
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

	$kubeconfigPath = Resolve-ToolchainDeploymentKubeconfig -Cluster $Cluster -Kubeconfig $Kubeconfig
	$kubectl = Get-ToolchainClusterExecutable -Name kubectl -Package kubectl -InstallHint 'Install kubectl and ensure its executable is available on PATH.'
	$apiServer = Get-ToolchainBootstrapApiServer -Kubeconfig $kubeconfigPath
	try { $null = Invoke-ToolchainBootstrapKubectl -Kubectl $kubectl -Kubeconfig $kubeconfigPath -Arguments @('get', '--request-timeout=10s', '--raw=/readyz') }
	catch { throw "Kubernetes API preflight failed for package deployment at $apiServer. kubectl reported: $($_.Exception.Message)" }

	$appliedManifests = [Collections.ArrayList]::new()
	$releases = [Collections.ArrayList]::new()
	$helm = $null
	$conventionalValues = Join-Path $Root 'toolchain-values.yaml'
	foreach ($component in $selectedComponents) {
		foreach ($manifestSet in $component.ManifestSets) {
			foreach ($manifestPath in $manifestSet.Files) {
				foreach ($file in @(Get-ToolchainDeploymentSourceFiles -Root $Root -RelativePath $manifestPath -YamlOnly)) {
					$arguments = @('apply', '--server-side', '--field-manager=toolchain-package')
					if ($DryRun) { $arguments += '--dry-run=server' }
					$manifestNamespace = if ($Namespace) { [string]$settings.namespace } else { [string]$manifestSet.Namespace }
					if ($manifestNamespace) { $arguments += @('--namespace', $manifestNamespace) }
					$arguments += @('-f', $file.FullName)
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
			$chartPath = Resolve-ToolchainChildPath -Root $Root -RelativePath $chart.Path -RejectReparsePoints -RejectRootReparsePoint
			$releaseNamespace = if ($Namespace) { [string]$settings.namespace } elseif ($chart.Namespace) { $chart.Namespace } else { [string]$settings.namespace }
			$arguments = @('upgrade', '--install', $chart.Release, $chartPath, '--namespace', $releaseNamespace)
			if ([bool]$settings.createNamespace) { $arguments += '--create-namespace' }
			foreach ($valuesPath in $chart.Values) {
				$arguments += @('--values', (Resolve-ToolchainChildPath -Root $Root -RelativePath $valuesPath -RejectReparsePoints -RejectRootReparsePoint))
			}
			foreach ($valuesPath in $globalValues) { $arguments += @('--values', $valuesPath) }
			if (Test-Path -LiteralPath $conventionalValues -PathType Leaf) { $arguments += @('--values', $conventionalValues) }
			foreach ($valuesPath in $externalValues) { $arguments += @('--values', $valuesPath) }
			if (-not $chart.SchemaValidation) { $arguments += '--skip-schema-validation' }
			if ($DryRun) { $arguments += '--dry-run' }
			elseif ([bool]$settings.wait -and $chart.Wait) { $arguments += @('--wait', '--timeout', "$($settings.waitSeconds)s") }
			if ($kubeconfigPath) { $arguments += @('--kubeconfig', $kubeconfigPath) }
			$null = Invoke-ToolchainClusterProcess -FilePath $helm -Arguments $arguments
			[void]$releases.Add([pscustomobject]@{ Component = $component.Name; Name = $chart.Release; Namespace = $releaseNamespace; Chart = $chart.Path })
		}
	}
	$result = [pscustomobject]@{
		PSTypeName = 'Toolchain.DeploymentResult'
		Name = $definition.Name
		Version = $definition.Version
		Cluster = if ($Cluster) { $Cluster } else { 'current-context' }
		Kubeconfig = $kubeconfigPath
		Namespace = [string]$settings.namespace
		DryRun = [bool]$DryRun
		Components = @($selectedComponents | ForEach-Object { $_.Name })
		Releases = @($releases.ToArray())
		Manifests = @($appliedManifests.ToArray() | ForEach-Object { $_.Path })
		ManifestDetails = @($appliedManifests.ToArray())
	}
	$suffix = if ($DryRun) { ' (dry run)' } else { '' }
	Write-ToolchainInfo "Deployed Toolchain package '$($result.Name):$($result.Version)' to $($result.Cluster)$suffix."
	if ($PassThru) { return $result }
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
		if ($Cluster -or $Kubeconfig -or $Components -or $Values -or $Config -or $Namespace -or $DryRun) { throw 'package create does not accept deployment target options' }
		$source = if ($Path) { $Path } else { (Get-Location).Path }
		return (New-ToolchainDeploymentPackage -Path $source -Output $Output -Force:$Force)
	}
	if (-not $Path) { throw 'package deploy requires a .tlcpkg file or source directory' }
	if ($Output -or $Force) { throw 'package deploy does not accept -Output or -Force' }
	if (-not $Confirm -and -not $DryRun) { throw "package deploy changes Kubernetes cluster state; rerun with -Confirm after reviewing 'tlc package deploy help'" }
	$root = $null
	$temporaryRoot = $null
	try {
		$fullPath = Resolve-ToolchainFileSystemPath -Path $Path
		if (Test-Path -LiteralPath $fullPath -PathType Container) {
			$root = $fullPath
		} else {
			$expanded = Expand-ToolchainDeploymentPackage -Path $fullPath
			$root = $expanded.Root
			$temporaryRoot = $expanded.Root
		}
		$params = @{
			Root = $root
			Cluster = $Cluster
			Kubeconfig = $Kubeconfig
			Components = $Components
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
