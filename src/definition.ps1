<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

. $PSScriptRoot\log.ps1

function Assert-ToolchainDefinition {
	param(
		[Parameter(Mandatory)][Collections.Hashtable]$Definition,
		[string]$Context = 'definition'
	)

	if (-not $Definition.ContainsKey('env') -or ($null -eq $Definition.env)) {
		throw "$Context is missing required top-level 'env' object"
	}

	Assert-ToolchainEnvMap -EnvMap $Definition.env -Context "$Context.env"

	foreach ($k in $Definition.Keys) {
		if ($k -eq 'env') { continue }
		$v = $Definition[$k]
		if ($null -eq $v) { continue }
		if ($v -isnot [Collections.Hashtable]) {
			throw "$Context.$k must be an object with an 'env' property"
		}
		if (-not $v.ContainsKey('env') -or ($null -eq $v.env)) {
			throw "$Context.$k is missing required 'env' object"
		}
		Assert-ToolchainEnvMap -EnvMap $v.env -Context "$Context.$k.env"
	}

}

function Assert-ToolchainEnvMap {
	param(
		[Parameter(Mandatory)][object]$EnvMap,
		[string]$Context = 'env'
	)
	if ($EnvMap -isnot [Collections.Hashtable]) {
		throw "$Context must be an object/map"
	}

	foreach ($name in $EnvMap.Keys) {
		$val = $EnvMap[$name]
		if ($name -match '^\s*$') { throw "$Context contains an empty variable name" }

		if ($null -eq $val) { continue }

		if ($val -is [string]) { continue }

		if ($val -is [System.Collections.IEnumerable] -and $val -isnot [string]) {
			foreach ($x in $val) {
				if ($null -eq $x) { continue }
				if ($x -isnot [string]) {
					throw "$Context.$name must contain only strings"
				}
			}
			continue
		}

		throw "$Context.$name must be a string or an array of strings"
	}
}

function ConvertTo-SemicolonString {
	[CmdletBinding()]
	param(
		[Parameter(ValueFromPipeline)][object]$Value
	)
	begin {
		$parts = [System.Collections.Generic.List[string]]::new()
	}
	process {
		if ($null -eq $Value) { return }

		if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
			foreach ($x in $Value) {
				if ($null -eq $x) { continue }
				$s = ([string]$x).Trim()
				if ($s) { $parts.Add($s) }
			}
			return
		}

		$s = ([string]$Value).Trim()
		if ($s) { $parts.Add($s) }
	}
	end {
		return ($parts.ToArray() -join ';')
	}
}
