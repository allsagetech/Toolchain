<#
Toolchains
Copyright (c) 2021 - 02-08-2026 U.S. Federal Government
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

function ConvertTo-HashTable {
	param (
		[Parameter(ValueFromPipeline)]
		[PSCustomObject]$Object
	)
	if ($null -eq $Object) {
		return
	}
	$Table = @{}
	$Object.PSObject.Properties | ForEach-Object {
		$V = $_.Value
		if ($V -is [Array]) {
			$alist = [System.Collections.ArrayList]::new()
			[void]$alist.AddRange($V)
			$V = $alist
		} elseif ($V -is [PSCustomObject]) {
			$V = ($V | ConvertTo-HashTable)
		}
		$Table.($_.Name) = $V
	}
	return $Table
}

function GetToolchainPath {
	if ($ToolchainPath) {
		$ToolchainPath
	} elseif ($env:ToolchainPath) {
		$env:ToolchainPath
	} elseif ($env:LocalAppData) {
		Join-Path $env:LocalAppData 'Toolchain'
	} elseif ($HOME) {
		Join-Path $HOME '.toolchain'
	} else {
		Join-Path ([IO.Path]::GetTempPath()) 'Toolchain'
	}
}

function GetToolchainRepo {
	if ($ToolchainRepo) {
		$ToolchainRepo
	} elseif ($env:ToolchainRepo) {
		$env:ToolchainRepo
	}
}

function GetToolchainPullPolicy {
	if ($ToolchainPullPolicy) {
		$ToolchainPullPolicy
	} elseif ($env:ToolchainPullPolicy) {
		$env:ToolchainPullPolicy
	} else {
		"IfNotPresent"
	}
}

function GetToolchainAutoprune {
	if ($ToolchainAutoprune) {
		$ToolchainAutoprune
	} elseif ($env:ToolchainAutoprune) {
		$env:ToolchainAutoprune
	}
}

function GetToolchainAutoupdate {
	if ($ToolchainAutoupdate) {
		$ToolchainAutoupdate
	} elseif ($env:ToolchainAutoupdate) {
		$env:ToolchainAutoupdate
	}
}

function GetPwrDBPath {
	Join-Path (GetToolchainPath) 'cache'
}

function GetPwrTempPath {
	Join-Path (GetToolchainPath) 'temp'
}

function GetPwrContentPath {
	Join-Path (GetToolchainPath) 'content'
}

function ResolvePackagePath {
	param (
		[Parameter(Mandatory, ValueFromPipeline)]
		[string]$Digest
	)
	if ($Digest -notmatch '^sha256:([0-9a-fA-F]{64})$') {
		throw "invalid sha256 digest: $Digest"
	}

	$digestHex = $Matches[1].ToLowerInvariant()
	$contentRoot = GetPwrContentPath
	# Legacy releases used only the first twelve characters here. Those
	# directories carry no authoritative ownership marker, so never assign one
	# to a requested digest: a colliding digest could otherwise claim another
	# package's bytes. PullPackage performs a verified re-pull into this full
	# path when upgrading an existing installation.
	return (Join-Path $contentRoot $digestHex)
}

function Resolve-ToolchainChildPath {
	param(
		[Parameter(Mandatory)][string]$Root,
		[Parameter(Mandatory)][string]$RelativePath,
		[switch]$RejectReparsePoints,
		[switch]$RejectRootReparsePoint
	)

	if ([string]::IsNullOrWhiteSpace($RelativePath) -or
		[IO.Path]::IsPathRooted($RelativePath) -or
		$RelativePath -match '^[\\/]' -or
		$RelativePath -match ':') {
		throw "unsafe relative path '$RelativePath'"
	}

	$segments = @($RelativePath -split '[\\/]' | Where-Object { $_ -ne '' })
	if ($segments.Count -eq 0 -or $segments -contains '..') {
		throw "unsafe relative path '$RelativePath'"
	}
	foreach ($segment in $segments) {
		if ($segment -eq '.' -or $segment -match '[\x00-\x1f]' -or $segment.EndsWith('.') -or $segment.EndsWith(' ')) {
			throw "unsafe relative path '$RelativePath'"
		}
	}

	$rootFull = [IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
	$rootPrefix = $rootFull + [IO.Path]::DirectorySeparatorChar
	$dest = [IO.Path]::GetFullPath((Join-Path $rootFull ($segments -join [IO.Path]::DirectorySeparatorChar)))
	if (-not $dest.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
		throw "path escapes root: '$RelativePath'"
	}

	if ($RejectReparsePoints) {
		if ($RejectRootReparsePoint) {
			$rootItem = Get-Item -LiteralPath $rootFull -Force -ErrorAction SilentlyContinue
			if ($rootItem -and ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
				throw "root path is a link or reparse point: '$rootFull'"
			}
		}
		$current = $rootFull
		foreach ($segment in $segments) {
			$current = Join-Path $current $segment
			$item = Get-Item -LiteralPath $current -Force -ErrorAction SilentlyContinue
			if ($item -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
				throw "path traverses a link or reparse point: '$RelativePath'"
			}
		}
	}

	return $dest
}

function MakeDirIfNotExist {
	param (
		[Parameter(Mandatory, ValueFromPipeline)]
		[string]$Path
	)
	New-Item -Path $Path -ItemType Directory -ErrorAction Ignore
}

function FindConfig {
	if (Get-Command Find-ToolchainScriptConfig -ErrorAction SilentlyContinue) {
		return Find-ToolchainScriptConfig
	}
	$path = (Get-Location).Path
	while ($true) {
		$cfg = Join-Path $path 'Toolchain.ps1'
		if (Test-Path -LiteralPath $cfg -PathType Leaf) { return $cfg }
		$parent = Split-Path $path -Parent
		if (-not $parent -or $parent -eq $path) { return $null }
		$path = $parent
	}
}

