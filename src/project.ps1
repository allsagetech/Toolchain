<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

function Remove-ToolchainYamlComment {
	param([Parameter(Mandatory)][AllowEmptyString()][string]$Line)
	$single = $false
	$double = $false
	for ($i = 0; $i -lt $Line.Length; $i++) {
		$character = $Line[$i]
		if ($character -eq "'" -and -not $double) {
			if ($single -and $i + 1 -lt $Line.Length -and $Line[$i + 1] -eq "'") { $i++; continue }
			$single = -not $single
		} elseif ($character -eq '"' -and -not $single) {
			$escaped = $false
			for ($j = $i - 1; $j -ge 0 -and $Line[$j] -eq '\'; $j--) { $escaped = -not $escaped }
			if (-not $escaped) { $double = -not $double }
		} elseif ($character -eq '#' -and -not $single -and -not $double) {
			if ($i -eq 0 -or [char]::IsWhiteSpace($Line[$i - 1])) { return $Line.Substring(0, $i).TrimEnd() }
		}
	}
	if ($single -or $double) { throw 'unterminated quoted YAML scalar' }
	return $Line.TrimEnd()
}

function ConvertFrom-ToolchainYamlScalar {
	param([Parameter(Mandatory)][string]$Value)
	$valueText = $Value.Trim()
	if ($valueText -eq '[]') { return ,@() }
	if ($valueText -eq '{}') { return @{} }
	if ($valueText -match '^"(?:[^"\\]|\\.)*"$') {
		try { return ($valueText | ConvertFrom-Json) }
		catch { throw "invalid double-quoted YAML scalar '$valueText': $($_.Exception.Message)" }
	}
	if ($valueText -match "^'(.*)'$") { return $Matches[1].Replace("''", "'") }
	if ($valueText -match '^(?i:true|false)$') { return ($valueText -ieq 'true') }
	if ($valueText -match '^(?i:null|~)$') { return $null }
	$number = 0
	if ([int]::TryParse($valueText, [ref]$number)) { return $number }
	if ($valueText -match '[\[\]{},&*!|>@`]') {
		throw "unsupported YAML scalar '$valueText'; quote values containing YAML control characters"
	}
	return $valueText
}

function ConvertFrom-ToolchainYaml {
	param(
		[Parameter(Mandatory)][string]$Text,
		[string]$Context = 'toolchain.yaml'
	)

	$tokens = [Collections.ArrayList]::new()
	$rawLines = @($Text -split "`r?`n")
	for ($lineIndex = 0; $lineIndex -lt $rawLines.Count; $lineIndex++) {
		$lineNumber = $lineIndex + 1
		$rawLine = $rawLines[$lineIndex]
		if ($rawLine -match "`t") { throw "${Context}:$lineNumber`: tabs are not allowed for indentation" }
		try { $line = Remove-ToolchainYamlComment -Line $rawLine }
		catch { throw "${Context}:$lineNumber`: $($_.Exception.Message)" }
		if ([string]::IsNullOrWhiteSpace($line) -or $line.TrimStart().StartsWith('---')) { continue }
		$indent = $line.Length - $line.TrimStart(' ').Length
		if (($indent % 2) -ne 0) { throw "${Context}:$lineNumber`: indentation must use multiples of two spaces" }
		$tokenText = $line.Trim()
		if ($tokenText -match '^(?<prefix>(?:-\s+)?[A-Za-z][A-Za-z0-9_-]*\s*:)\s*(?<style>[|>])(?<chomp>[-+]?)$') {
			$prefix = [string]$Matches.prefix
			$style = [string]$Matches.style
			$chomp = [string]$Matches.chomp
			$blockLines = [Collections.ArrayList]::new()
			$contentIndent = $null
			$nextIndex = $lineIndex + 1
			while ($nextIndex -lt $rawLines.Count) {
				$blockLine = $rawLines[$nextIndex]
				if ($blockLine -match "`t") { throw "${Context}:$($nextIndex + 1)`: tabs are not allowed for indentation" }
				if ([string]::IsNullOrWhiteSpace($blockLine)) { [void]$blockLines.Add(''); $nextIndex++; continue }
				$blockIndent = $blockLine.Length - $blockLine.TrimStart(' ').Length
				if ($blockIndent -le $indent) { break }
				if ($null -ne $contentIndent -and $blockIndent -lt $contentIndent) { break }
				if ($null -eq $contentIndent) { $contentIndent = $blockIndent }
				[void]$blockLines.Add($blockLine)
				$nextIndex++
			}
			if ($blockLines.Count -eq 0 -or $null -eq $contentIndent) { throw "${Context}:$lineNumber`: block scalar requires indented content" }
			# A final empty item from -split represents the document's terminating line
			# break, not an additional blank block-scalar line.
			if ($nextIndex -eq $rawLines.Count -and $rawLines[-1] -eq '' -and $blockLines[-1] -eq '') {
				$blockLines.RemoveAt($blockLines.Count - 1)
			}
			$normalizedLines = @($blockLines | ForEach-Object { if ($_ -eq '') { '' } else { $_.Substring([int]$contentIndent) } })
			if ($style -eq '|') {
				$scalar = $normalizedLines -join "`n"
			} else {
				$paragraphs = [Collections.ArrayList]::new()
				$currentParagraph = [Collections.ArrayList]::new()
				foreach ($blockValue in $normalizedLines) {
					if ($blockValue -eq '') {
						if ($currentParagraph.Count -gt 0) { [void]$paragraphs.Add(($currentParagraph -join ' ')); $currentParagraph.Clear() }
						[void]$paragraphs.Add('')
					} else { [void]$currentParagraph.Add($blockValue) }
				}
				if ($currentParagraph.Count -gt 0) { [void]$paragraphs.Add(($currentParagraph -join ' ')) }
				$scalar = $paragraphs -join "`n"
			}
			$hasFinalLineBreak = $nextIndex -lt $rawLines.Count -or $Text -match "`r?`n$"
			if ($hasFinalLineBreak) { $scalar += "`n" }
			switch ($chomp) {
				'-' { $scalar = $scalar.TrimEnd("`n") }
				'' { $scalar = $scalar.TrimEnd("`n") + "`n" }
			}
			$tokenText = "$prefix $($scalar | ConvertTo-Json -Compress)"
			$lineIndex = $nextIndex - 1
		}
		[void]$tokens.Add([pscustomobject]@{ Indent = $indent; Text = $tokenText; Line = $lineNumber })
	}
	if ($tokens.Count -eq 0) { throw "${Context}: manifest is empty" }

	function ReadYamlEntry {
		param(
			[Parameter(Mandatory)][hashtable]$Map,
			[Parameter(Mandatory)][string]$EntryText,
			[Parameter(Mandatory)][int]$LogicalIndent,
			[Parameter(Mandatory)][ref]$Position
		)
		if ($EntryText -notmatch '^([A-Za-z][A-Za-z0-9_-]*)\s*:(?:\s+(.*))?$') {
			throw "${Context}:$($tokens[$Position.Value - 1].Line)`: expected a mapping entry"
		}
		$key = $Matches[1]
		$rawValue = [string]$Matches[2]
		if ($Map.ContainsKey($key)) { throw "${Context}: duplicate key '$key'" }
		if ($rawValue.Length -gt 0) {
			$Map[$key] = ConvertFrom-ToolchainYamlScalar -Value $rawValue
			return
		}
		if ($Position.Value -ge $tokens.Count -or $tokens[$Position.Value].Indent -le $LogicalIndent) {
			$Map[$key] = $null
			return
		}
		$childIndent = $tokens[$Position.Value].Indent
		$Map[$key] = (ReadYamlBlock -Indent $childIndent -Position $Position).Value
	}

	function ReadYamlBlock {
		param(
			[Parameter(Mandatory)][int]$Indent,
			[Parameter(Mandatory)][ref]$Position
		)
		if ($Position.Value -ge $tokens.Count) { throw "${Context}: unexpected end of YAML document" }
		$isSequence = $tokens[$Position.Value].Text -match '^-($|\s+)'
		if ($isSequence) {
			$list = [Collections.ArrayList]::new()
			while ($Position.Value -lt $tokens.Count -and $tokens[$Position.Value].Indent -eq $Indent) {
				$token = $tokens[$Position.Value]
				if ($token.Text -notmatch '^-(?:\s+(.*))?$') { break }
				$itemText = [string]$Matches[1]
				$Position.Value++
				if ([string]::IsNullOrWhiteSpace($itemText)) {
					if ($Position.Value -ge $tokens.Count -or $tokens[$Position.Value].Indent -le $Indent) {
						throw "${Context}:$($token.Line)`: sequence item has no value"
					}
					[void]$list.Add((ReadYamlBlock -Indent $tokens[$Position.Value].Indent -Position $Position).Value)
					continue
				}
				if ($itemText -match '^([A-Za-z][A-Za-z0-9_-]*)\s*:(?:\s+(.*))?$') {
					$map = @{}
					ReadYamlEntry -Map $map -EntryText $itemText -LogicalIndent ($Indent + 2) -Position $Position
					while ($Position.Value -lt $tokens.Count -and $tokens[$Position.Value].Indent -eq ($Indent + 2) -and $tokens[$Position.Value].Text -notmatch '^-($|\s+)') {
						$entry = $tokens[$Position.Value]
						$Position.Value++
						ReadYamlEntry -Map $map -EntryText $entry.Text -LogicalIndent ($Indent + 2) -Position $Position
					}
					[void]$list.Add($map)
				} else {
					[void]$list.Add((ConvertFrom-ToolchainYamlScalar -Value $itemText))
				}
			}
			return [pscustomobject]@{ Kind = 'sequence'; Value = @($list.ToArray()) }
		}

		$map = @{}
		while ($Position.Value -lt $tokens.Count -and $tokens[$Position.Value].Indent -eq $Indent) {
			$token = $tokens[$Position.Value]
			if ($token.Text -match '^-($|\s+)') { break }
			$Position.Value++
			ReadYamlEntry -Map $map -EntryText $token.Text -LogicalIndent $Indent -Position $Position
		}
		return [pscustomobject]@{ Kind = 'mapping'; Value = $map }
	}

	$position = 0
	$result = ReadYamlBlock -Indent $tokens[0].Indent -Position ([ref]$position)
	if ($result.Kind -ne 'mapping') { throw "${Context}: document root must be a mapping" }
	if ($position -ne $tokens.Count) {
		throw "${Context}:$($tokens[$position].Line)`: invalid indentation or trailing content"
	}
	return $result.Value
}

function Find-ToolchainProjectConfig {
	param([string]$StartPath = (Get-Location).Path)
	$path = [IO.Path]::GetFullPath($StartPath)
	while ($true) {
		foreach ($name in @('toolchain.yaml', 'toolchain.yml', 'Toolchain.yaml', 'Toolchain.yml', 'Toolchain.ps1')) {
			$candidate = Join-Path $path $name
			if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
		}
		$parent = Split-Path $path -Parent
		if (-not $parent -or $parent -eq $path) { return $null }
		$path = $parent
	}
}

function Find-ToolchainScriptConfig {
	param([string]$StartPath = (Get-Location).Path)
	$path = [IO.Path]::GetFullPath($StartPath)
	while ($true) {
		$candidate = Join-Path $path 'Toolchain.ps1'
		if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
		$parent = Split-Path $path -Parent
		if (-not $parent -or $parent -eq $path) { return $null }
		$path = $parent
	}
}

function ConvertTo-ToolchainProjectPackageSpec {
	param(
		[Parameter(Mandatory)][object]$Value,
		[string]$Context = 'package'
	)
	if ($Value -is [string]) {
		$reference = [string]$Value
		if ($reference.StartsWith('file:///')) {
			return @{ Reference = $reference; Name = $reference; Constraint = $null; Configuration = 'default'; Dependencies = @() }
		}
		$parsed = $reference | AsPackage
		$constraint = if ($parsed.Digest) { [string]$parsed.Digest } else { [string]($parsed.Tag | AsTagString) }
		return @{
			Name = [string]$parsed.Package
			Constraint = $constraint
			Configuration = if ($parsed.Config) { [string]$parsed.Config } else { 'default' }
			Dependencies = @()
		}
	}
	if ($Value -isnot [Collections.IDictionary]) { throw "$Context must be a string or mapping" }
	$allowed = @('name', 'version', 'configuration', 'dependencies', 'dependsOn')
	foreach ($key in $Value.Keys) {
		if ([string]$key -notin $allowed) { throw "$Context contains unsupported key '$key'" }
	}
	$name = [string]$Value.name
	if ($name -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') { throw "$Context has invalid package name '$name'" }
	$configuration = if ($Value.configuration) { [string]$Value.configuration } else { 'default' }
	if ($configuration -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') { throw "$Context has invalid configuration '$configuration'" }
	$constraint = if ($null -ne $Value.version -and -not [string]::IsNullOrWhiteSpace([string]$Value.version)) { [string]$Value.version } else { 'latest' }
	$dependencyValues = @()
	if ($null -ne $Value.dependencies) { $dependencyValues += @($Value.dependencies) }
	if ($null -ne $Value.dependsOn) { $dependencyValues += @($Value.dependsOn) }
	$dependencies = @()
	for ($index = 0; $index -lt $dependencyValues.Count; $index++) {
		$dependencies += ConvertTo-ToolchainProjectPackageSpec -Value $dependencyValues[$index] -Context "$Context dependency $($index + 1)"
	}
	return @{
		Name = $name
		Constraint = $constraint.Trim()
		Configuration = $configuration
		Dependencies = @($dependencies)
	}
}

function ConvertTo-ToolchainComparableVersion {
	param([Parameter(Mandatory)][string]$Version)
	if ($Version -notmatch '^v?([0-9]+)(?:\.([0-9]+))?(?:\.([0-9]+))?(?:(?:\+|_)([0-9]+))?$') { return $null }
	$parts = @([int64]$Matches[1], 0L, 0L, 0L)
	$count = 1
	for ($index = 2; $index -le 4; $index++) {
		if ($Matches[$index]) { $parts[$index - 1] = [int64]$Matches[$index]; $count = $index }
	}
	return [pscustomobject]@{ Parts = $parts; Count = $count; Text = $Version }
}

function Compare-ToolchainComparableVersion {
	param([Parameter(Mandatory)][object]$Left, [Parameter(Mandatory)][object]$Right)
	for ($index = 0; $index -lt 4; $index++) {
		if ($Left.Parts[$index] -lt $Right.Parts[$index]) { return -1 }
		if ($Left.Parts[$index] -gt $Right.Parts[$index]) { return 1 }
	}
	return 0
}

function Test-ToolchainVersionConstraint {
	param(
		[Parameter(Mandatory)][string]$Version,
		[Parameter(Mandatory)][string]$Constraint
	)
	if ([string]::IsNullOrWhiteSpace($Constraint) -or $Constraint -ieq 'latest' -or $Constraint -eq '*') { return $true }
	$candidate = ConvertTo-ToolchainComparableVersion -Version $Version
	if (-not $candidate) { return [string]::Equals($Version, $Constraint, [StringComparison]::OrdinalIgnoreCase) }

	foreach ($alternative in @($Constraint -split '\s*\|\|\s*')) {
		$matchesAlternative = $true
		$tokens = @($alternative -split '[,\s]+' | Where-Object { $_ })
		if ($tokens.Count -eq 0) { continue }
		foreach ($token in $tokens) {
			if ($token -notmatch '^(>=|<=|>|<|=|\^|~)?(v?[0-9]+(?:\.(?:[0-9]+|x|X|\*)){0,3}(?:(?:\+|_)[0-9]+)?)$') {
				throw "invalid version constraint '$Constraint'"
			}
			$operator = [string]$Matches[1]
			$versionText = [string]$Matches[2]
			if ($versionText -match '(?i)(?:^|\.)(?:x|\*)') {
				$prefix = @($versionText.TrimStart('v','V') -split '\.')
				for ($index = 0; $index -lt $prefix.Count; $index++) {
					if ($prefix[$index] -match '^(?i:x|\*)$') { break }
					if ($candidate.Parts[$index] -ne [int64]$prefix[$index]) { $matchesAlternative = $false; break }
				}
				if (-not $matchesAlternative) { break }
				continue
			}
			$target = ConvertTo-ToolchainComparableVersion -Version $versionText
			if (-not $target) { throw "invalid version constraint '$Constraint'" }
			$comparison = Compare-ToolchainComparableVersion -Left $candidate -Right $target
			switch ($operator) {
				'>' { if ($comparison -le 0) { $matchesAlternative = $false } }
				'>=' { if ($comparison -lt 0) { $matchesAlternative = $false } }
				'<' { if ($comparison -ge 0) { $matchesAlternative = $false } }
				'<=' { if ($comparison -gt 0) { $matchesAlternative = $false } }
				'^' {
					if ($comparison -lt 0) { $matchesAlternative = $false; break }
					$upperParts = @($target.Parts[0], $target.Parts[1], $target.Parts[2], $target.Parts[3])
					$firstNonZero = 0
					while ($firstNonZero -lt 3 -and $upperParts[$firstNonZero] -eq 0) { $firstNonZero++ }
					$upperParts[$firstNonZero]++
					for ($reset = $firstNonZero + 1; $reset -lt 4; $reset++) { $upperParts[$reset] = 0 }
					$upper = [pscustomobject]@{ Parts = $upperParts }
					if ((Compare-ToolchainComparableVersion -Left $candidate -Right $upper) -ge 0) { $matchesAlternative = $false }
				}
				'~' {
					if ($comparison -lt 0) { $matchesAlternative = $false; break }
					$upperParts = @($target.Parts[0], $target.Parts[1], $target.Parts[2], $target.Parts[3])
					$increment = if ($target.Count -le 1) { 0 } else { 1 }
					$upperParts[$increment]++
					for ($reset = $increment + 1; $reset -lt 4; $reset++) { $upperParts[$reset] = 0 }
					$upper = [pscustomobject]@{ Parts = $upperParts }
					if ((Compare-ToolchainComparableVersion -Left $candidate -Right $upper) -ge 0) { $matchesAlternative = $false }
				}
				default {
					if ($operator -eq '=') {
						if ($comparison -ne 0) { $matchesAlternative = $false }
					} else {
						for ($index = 0; $index -lt $target.Count; $index++) {
							if ($candidate.Parts[$index] -ne $target.Parts[$index]) { $matchesAlternative = $false; break }
						}
					}
				}
			}
			if (-not $matchesAlternative) { break }
		}
		if ($matchesAlternative) { return $true }
	}
	return $false
}

function Test-ToolchainConstraintExpression {
	param([Parameter(Mandatory)][string]$Value)
	return ($Value -match '^(?:[<>=~^]|.*(?:\s|\|\||\*|(?:^|\.)[xX](?:\.|$)))')
}

function Select-ToolchainPackageVersion {
	param(
		[Parameter(Mandatory)][string]$Name,
		[Parameter(Mandatory)][string[]]$Constraints,
		[Parameter(Mandatory)][object]$Catalog
	)
	$property = $Catalog.PSObject.Properties | Where-Object { $_.Name -ieq $Name } | Select-Object -First 1
	if (-not $property) { throw "no such package: $Name" }
	$candidates = @()
	foreach ($tag in @($property.Value)) {
		$versionText = [string]$tag.ToString()
		if (-not $versionText -or $versionText -eq 'latest') { continue }
		$matchesAllConstraints = $true
		foreach ($constraint in @($Constraints)) {
			if (-not (Test-ToolchainVersionConstraint -Version $versionText -Constraint $constraint)) { $matchesAllConstraints = $false; break }
		}
		if ($matchesAllConstraints) {
			$candidates += [pscustomobject]@{ Text = $versionText; Comparable = ConvertTo-ToolchainComparableVersion -Version $versionText }
		}
	}
	if ($candidates.Count -eq 0) { throw "no version of '$Name' satisfies constraints: $($Constraints -join ', ')" }
	$selected = $candidates[0]
	foreach ($candidate in $candidates) {
		if ($candidate.Comparable -and (-not $selected.Comparable -or (Compare-ToolchainComparableVersion -Left $candidate.Comparable -Right $selected.Comparable) -gt 0)) { $selected = $candidate }
	}
	return [string]$selected.Text
}

function Resolve-ToolchainProjectPackages {
	param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$PackageSpecs)
	$nodes = @{}
	$order = [Collections.ArrayList]::new()

	function AddProjectNode {
		param([Parameter(Mandatory)][hashtable]$Spec)
		if ($Spec.Reference) {
			if (-not $nodes.ContainsKey($Spec.Name)) {
				$nodes[$Spec.Name] = @{ Name = $Spec.Name; Reference = $Spec.Reference; Constraints = @(); Configuration = 'default'; Dependencies = @() }
				[void]$order.Add($Spec.Name)
			}
			return
		}
		$nameKey = $Spec.Name.ToLowerInvariant()
		if (-not $nodes.ContainsKey($nameKey)) {
			$nodes[$nameKey] = @{ Name = $Spec.Name; Constraints = @(); Configuration = $Spec.Configuration; Dependencies = @() }
			[void]$order.Add($nameKey)
		}
		$node = $nodes[$nameKey]
		if ($node.Configuration -ne $Spec.Configuration) { throw "package '$($Spec.Name)' requests conflicting configurations '$($node.Configuration)' and '$($Spec.Configuration)'" }
		$node.Constraints += [string]$Spec.Constraint
		foreach ($dependency in @($Spec.Dependencies)) {
			if ($dependency.Reference) { throw "local package references cannot be declared as dependencies of '$($Spec.Name)'" }
			$dependencyKey = $dependency.Name.ToLowerInvariant()
			if ($dependencyKey -notin $node.Dependencies) { $node.Dependencies += $dependencyKey }
			AddProjectNode -Spec $dependency
		}
	}
	foreach ($spec in $PackageSpecs) { AddProjectNode -Spec $spec }

	$topologicalOrder = [Collections.ArrayList]::new()
	$visiting = @{}
	$visited = @{}
	function VisitProjectNode {
		param([Parameter(Mandatory)][string]$Key)
		if ($visited.ContainsKey($Key)) { return }
		if ($visiting.ContainsKey($Key)) { throw "dependency cycle detected at package '$($nodes[$Key].Name)'" }
		$visiting[$Key] = $true
		foreach ($dependencyKey in @($nodes[$Key].Dependencies)) { VisitProjectNode -Key $dependencyKey }
		$null = $visiting.Remove($Key)
		$visited[$Key] = $true
		[void]$topologicalOrder.Add($Key)
	}
	foreach ($key in @($order)) { VisitProjectNode -Key $key }

	$catalog = $null
	$result = [Collections.ArrayList]::new()
	foreach ($key in @($topologicalOrder)) {
		$node = $nodes[$key]
		if ($node.Reference) {
			[void]$result.Add([string]$node.Reference)
			continue
		}
		if ($node.Constraints.Count -eq 1 -and $node.Constraints[0] -match '^sha256:[0-9a-fA-F]{64}$') {
			[void]$result.Add("$($node.Name)@$($node.Constraints[0].ToLowerInvariant())::$($node.Configuration)")
			continue
		}
		if (-not $catalog) { $catalog = GetDockerTags -Kind All }
		$selectedVersion = Select-ToolchainPackageVersion -Name $node.Name -Constraints $node.Constraints -Catalog $catalog
		[void]$result.Add("$($node.Name):$($selectedVersion)::$($node.Configuration)")
	}
	return @($result.ToArray())
}

function Get-ToolchainProjectDigest {
	param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$PackageSpecs)
	function NormalizeSpec {
		param([Parameter(Mandatory)][hashtable]$Spec)
		return [ordered]@{
			name = [string]$Spec.Name
			reference = [string]$Spec.Reference
			constraint = [string]$Spec.Constraint
			configuration = [string]$Spec.Configuration
			dependencies = @($Spec.Dependencies | ForEach-Object { NormalizeSpec -Spec $_ })
		}
	}
	$json = if ($PackageSpecs.Count -eq 0) { '[]' } else { @($PackageSpecs | ForEach-Object { NormalizeSpec -Spec $_ }) | ConvertTo-Json -Depth 30 -Compress }
	$bytes = [Text.Encoding]::UTF8.GetBytes($json)
	return Get-ToolchainBytesSha256Digest -Bytes $bytes
}

function Get-ToolchainProjectPackageNames {
	param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$PackageSpecs)
	$names = [Collections.ArrayList]::new()
	function AddSpecName {
		param([Parameter(Mandatory)][hashtable]$Spec)
		if ($Spec.Reference) {
			[void]$names.Add([string]$Spec.Name)
			return
		}
		if ([string]$Spec.Name -notin @($names)) { [void]$names.Add([string]$Spec.Name) }
		foreach ($dependency in @($Spec.Dependencies)) { AddSpecName -Spec $dependency }
	}
	foreach ($spec in $PackageSpecs) { AddSpecName -Spec $spec }
	return @($names.ToArray())
}

function Read-ToolchainProject {
	param(
		[string]$Path,
		[switch]$NoResolve
	)
	$configPath = if ($Path) {
		if (Get-Command Resolve-ToolchainFileSystemPath -ErrorAction SilentlyContinue) { Resolve-ToolchainFileSystemPath -Path $Path }
		else { [IO.Path]::GetFullPath($Path) }
	} else { Find-ToolchainProjectConfig }
	if (-not $configPath) { throw 'toolchain.yaml or Toolchain.ps1 not found from current directory upward' }
	if ($configPath -match '(?i)\.ya?ml$') {
		$manifest = ConvertFrom-ToolchainYaml -Text (Get-Content -LiteralPath $configPath -Raw) -Context $configPath
		foreach ($key in $manifest.Keys) {
			if ([string]$key -notin @('schemaVersion', 'packages', 'deployment', 'apiVersion', 'kind', 'metadata', 'components', 'values', 'documentation', 'constants', 'variables', 'build')) { throw "$configPath contains unsupported top-level key '$key'" }
		}
		if ($null -ne $manifest['schemaVersion'] -and [int]$manifest['schemaVersion'] -ne 1) { throw "$configPath requires schemaVersion: 1" }
		if ($manifest['kind'] -and [string]$manifest['kind'] -ne 'ToolchainPackageConfig') { throw "$configPath supports only kind: ToolchainPackageConfig" }
		if ($manifest['apiVersion'] -and [string]$manifest['apiVersion'] -ne 'toolchain.allsagetech.com/v1alpha1') { throw "$configPath supports only apiVersion: toolchain.allsagetech.com/v1alpha1" }
		$values = @()
		if ($null -ne $manifest['packages']) { $values = @($manifest['packages']) }
		if ($values.Count -eq 0 -and $null -eq $manifest['deployment'] -and $null -eq $manifest['components']) { throw "$configPath must declare at least one package, a deployment, or components" }
		$specs = @()
		for ($index = 0; $index -lt $values.Count; $index++) {
			$specs += ConvertTo-ToolchainProjectPackageSpec -Value $values[$index] -Context "package $($index + 1)"
		}
		$packages = if ($NoResolve) { @() } else { Resolve-ToolchainProjectPackages -PackageSpecs $specs }
		return [pscustomobject]@{
			Path = $configPath
			Root = Split-Path -Parent $configPath
			Format = 'yaml'
			PackageSpecs = @($specs)
			PackageNames = @(Get-ToolchainProjectPackageNames -PackageSpecs $specs)
			Packages = @($packages)
			Digest = Get-ToolchainProjectDigest -PackageSpecs $specs
			Deployment = $manifest['deployment']
			Components = @($manifest['components'])
			Variables = @($manifest['variables'])
		}
	}

	$legacyPackages = @(& {
		param($LegacyPath)
		. $LegacyPath
		[string[]]$ToolchainPackages
	} $configPath)
	$legacySpecs = @($legacyPackages | ForEach-Object { ConvertTo-ToolchainProjectPackageSpec -Value ([string]$_) })
	return [pscustomobject]@{
		Path = $configPath
		Root = Split-Path -Parent $configPath
		Format = 'powershell'
		PackageSpecs = @($legacySpecs)
		PackageNames = @(Get-ToolchainProjectPackageNames -PackageSpecs $legacySpecs)
		Packages = @($legacyPackages)
		Digest = Get-ToolchainProjectDigest -PackageSpecs $legacySpecs
	}
}
