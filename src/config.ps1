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
	} else {
		"$env:LocalAppData\Toolchain"
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
	"$(GetToolchainPath)\cache"
}

function GetPwrTempPath {
	"$(GetToolchainPath)\temp"
}

function GetPwrContentPath {
	"$(GetToolchainPath)\content"
}

function ResolvePackagePath {
	param (
		[Parameter(Mandatory, ValueFromPipeline)]
		[string]$Digest
	)
	return "$(GetPwrContentPath)\$($digest.Substring('sha256:'.Length).Substring(0, 12))"
}

function MakeDirIfNotExist {
	param (
		[Parameter(Mandatory, ValueFromPipeline)]
		[string]$Path
	)
	New-Item -Path $Path -ItemType Directory -ErrorAction Ignore
}

function FindConfig {
	$path = (Get-Location).Path
	while ($true) {
		$cfg = Join-Path $path 'Toolchain.ps1'
		if (Test-Path -LiteralPath $cfg -PathType Leaf) {
			return $cfg
		}
		$parent = Split-Path $path -Parent
		if (-not $parent -or $parent -eq $path) {
			return $null
		}
		$path = $parent
	}
}

