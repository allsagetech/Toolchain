<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

$script:ToolchainProfileStartMarker = '# >>> Toolchain managed packages >>>'
$script:ToolchainProfileEndMarker = '# <<< Toolchain managed packages <<<'
$script:ToolchainProfileHeader = @(
	'Set-ExecutionPolicy -Scope CurrentUser Unrestricted'
	'Write-Host "Toolchain by AllSageTech" -ForegroundColor Green'
)

function Get-ToolchainPowerShellProfilePath {
	[CmdletBinding()]
	param ()

	$path = if ($PROFILE -and $PROFILE.PSObject.Properties['CurrentUserCurrentHost']) {
		[string]$PROFILE.CurrentUserCurrentHost
	} else {
		[string]$PROFILE
	}
	if ([string]::IsNullOrWhiteSpace($path)) {
		throw 'PowerShell did not provide a CurrentUserCurrentHost profile path'
	}
	return [IO.Path]::GetFullPath($path)
}

function Initialize-ToolchainPowerShellProfile {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[string]$Path
	)

	$fullPath = [IO.Path]::GetFullPath($Path)
	if (Test-Path -LiteralPath $fullPath -PathType Container) {
		throw "PowerShell profile path is a directory: $fullPath"
	}
	$parent = Split-Path -Parent $fullPath
	if (-not [string]::IsNullOrWhiteSpace($parent)) {
		[void][IO.Directory]::CreateDirectory($parent)
	}
	if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
		$content = ($script:ToolchainProfileHeader -join [Environment]::NewLine) + [Environment]::NewLine
		[IO.File]::WriteAllText($fullPath, $content, [Text.UTF8Encoding]::new($false))
	}
	return $fullPath
}

function Assert-ToolchainProfilePackage {
	param (
		[Parameter(Mandatory)]
		[string]$Package
	)

	if ([string]::IsNullOrWhiteSpace($Package)) {
		throw 'profile package references cannot be empty'
	}
	if ($Package.IndexOfAny([char[]]"`r`n`0") -ge 0) {
		throw 'profile package references cannot contain line breaks or null characters'
	}
}

function ConvertTo-ToolchainProfileLoadLine {
	param (
		[Parameter(Mandatory)]
		[string]$Package
	)

	Assert-ToolchainProfilePackage -Package $Package
	$literal = $Package.Replace("'", "''")
	return "toolchain load '$literal' *> `$null"
}

function Read-ToolchainProfileState {
	param (
		[Parameter(Mandatory)]
		[string]$Path
	)

	$encoding = [Text.UTF8Encoding]::new($false)
	$content = ''
	if (Test-Path -LiteralPath $Path -PathType Leaf) {
		$reader = [IO.StreamReader]::new($Path, $encoding, $true)
		try {
			$content = $reader.ReadToEnd()
			$encoding = $reader.CurrentEncoding
		} finally {
			$reader.Dispose()
		}
	}

	$newLineMatch = [regex]::Match($content, "`r`n|`n|`r")
	$newLine = if ($newLineMatch.Success) { $newLineMatch.Value } else { [Environment]::NewLine }
	$lines = if ($content.Length -eq 0) { @() } else { @([regex]::Split($content, "`r`n|`n|`r")) }
	$starts = @()
	$ends = @()
	for ($i = 0; $i -lt $lines.Count; $i++) {
		if ($lines[$i].Trim() -ceq $script:ToolchainProfileStartMarker) { $starts += $i }
		if ($lines[$i].Trim() -ceq $script:ToolchainProfileEndMarker) { $ends += $i }
	}

	if ($starts.Count -eq 0 -and $ends.Count -eq 0) {
		return [pscustomobject]@{
			Path = $Path
			Content = $content
			Encoding = $encoding
			NewLine = $newLine
			Lines = $lines
			Start = -1
			End = -1
			Packages = @()
		}
	}
	if ($starts.Count -ne 1 -or $ends.Count -ne 1 -or $starts[0] -ge $ends[0]) {
		throw "PowerShell profile contains a malformed Toolchain managed block: $Path"
	}

	$packages = @()
	for ($i = $starts[0] + 1; $i -lt $ends[0]; $i++) {
		if ([string]::IsNullOrWhiteSpace($lines[$i])) { continue }
		$match = [regex]::Match($lines[$i], "^[ `t]*toolchain[ `t]+load[ `t]+'(?<Package>(?:[^']|'')*)'(?:[ `t]+\*>[ `t]+\`$null)?[ `t]*$")
		if (-not $match.Success) {
			throw "PowerShell profile contains an unrecognized line in the Toolchain managed block: $($lines[$i])"
		}
		$package = $match.Groups['Package'].Value.Replace("''", "'")
		Assert-ToolchainProfilePackage -Package $package
		$packages += $package
	}

	return [pscustomobject]@{
		Path = $Path
		Content = $content
		Encoding = $encoding
		NewLine = $newLine
		Lines = $lines
		Start = $starts[0]
		End = $ends[0]
		Packages = $packages
	}
}

function Set-ToolchainProfilePackages {
	param (
		[Parameter(Mandatory)]
		[string]$Path,
		[AllowEmptyCollection()]
		[string[]]$Packages
	)

	$state = Read-ToolchainProfileState -Path $Path
	$block = @()
	if ($Packages.Count -gt 0) {
		$block = @($script:ToolchainProfileStartMarker)
		$block += @($Packages | ForEach-Object { ConvertTo-ToolchainProfileLoadLine -Package $_ })
		$block += $script:ToolchainProfileEndMarker
	}

	if ($state.Start -ge 0) {
		$before = if ($state.Start -gt 0) { @($state.Lines[0..($state.Start - 1)]) } else { @() }
		$after = if ($state.End + 1 -lt $state.Lines.Count) { @($state.Lines[($state.End + 1)..($state.Lines.Count - 1)]) } else { @() }
		$updatedLines = @($before) + @($block) + @($after)
	} elseif ($block.Count -gt 0) {
		$updatedLines = @($state.Lines)
		if ($updatedLines.Count -gt 0 -and $updatedLines[-1] -eq '') {
			$updatedLines = @($updatedLines[0..($updatedLines.Count - 2)])
		}
		$updatedLines += $block
		$updatedLines += ''
	} else {
		return
	}

	$newContent = $updatedLines -join $state.NewLine
	[IO.File]::WriteAllText($Path, $newContent, $state.Encoding)
}

function Invoke-ToolchainProfile {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory, Position = 0)]
		[ValidateSet('init', 'add', 'remove', 'list', 'path')]
		[string]$Command,
		[Parameter(Position = 1, ValueFromRemainingArguments)]
		[string[]]$Packages
	)

	$path = Get-ToolchainPowerShellProfilePath
	switch ($Command) {
		'path' {
			if ($Packages) { throw 'profile path does not accept package references' }
			return $path
		}
		'init' {
			if ($Packages) { throw 'profile init does not accept package references; use profile add instead' }
			$null = Initialize-ToolchainPowerShellProfile -Path $path
			Write-ToolchainInfo "PowerShell profile is ready: $path"
		}
		'list' {
			if ($Packages) { throw 'profile list does not accept package references' }
			if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return }
			return @((Read-ToolchainProfileState -Path $path).Packages)
		}
		'add' {
			if (-not $Packages) { throw 'profile add requires at least one package reference (example: toolchain profile add node)' }
			$null = Initialize-ToolchainPowerShellProfile -Path $path
			$state = Read-ToolchainProfileState -Path $path
			$updated = [Collections.Generic.List[string]]::new()
			foreach ($existing in $state.Packages) { $updated.Add($existing) }
			foreach ($package in $Packages) {
				Assert-ToolchainProfilePackage -Package $package
				if (-not ($updated | Where-Object { $_ -ieq $package })) {
					$updated.Add($package)
				}
			}
			Set-ToolchainProfilePackages -Path $path -Packages $updated.ToArray()
			Write-ToolchainInfo "Updated Toolchain packages in PowerShell profile: $path"
		}
		'remove' {
			if (-not $Packages) { throw 'profile remove requires at least one package reference (example: toolchain profile remove node)' }
			if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return }
			foreach ($package in $Packages) { Assert-ToolchainProfilePackage -Package $package }
			$state = Read-ToolchainProfileState -Path $path
			$updated = @($state.Packages | Where-Object { $existing = $_; -not ($Packages | Where-Object { $_ -ieq $existing }) })
			if ($updated.Count -ne $state.Packages.Count) {
				Set-ToolchainProfilePackages -Path $path -Packages $updated
				Write-ToolchainInfo "Updated Toolchain packages in PowerShell profile: $path"
			}
		}
	}
}
