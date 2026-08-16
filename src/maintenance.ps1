<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

$script:ToolchainDeferredUpdateCheckPending = $false

function Request-ToolchainDeferredUpdateCheck {
	$script:ToolchainDeferredUpdateCheckPending = $true
}

function Invoke-ToolchainDeferredUpdateCheck {
	if (-not $script:ToolchainDeferredUpdateCheckPending) { return }
	$script:ToolchainDeferredUpdateCheckPending = $false
	CheckForUpdates
}

function Get-ToolchainUpdateCheckTtl {
	$value = if ($env:TOOLCHAIN_UPDATE_CHECK_TTL) { [string]$env:TOOLCHAIN_UPDATE_CHECK_TTL } else { '1.00:00:00' }
	try { $ttl = [timespan]::Parse($value) } catch { throw "TOOLCHAIN_UPDATE_CHECK_TTL must be a TimeSpan value: $value" }
	if ($ttl -lt [timespan]::Zero) { throw 'TOOLCHAIN_UPDATE_CHECK_TTL cannot be negative.' }
	return $ttl
}

function Get-ToolchainUpdateCheckPath {
	return (Join-Path (GetPwrDBPath) 'last-update-check.txt')
}

function Test-ToolchainUpdateCheckDue {
	if (Test-TruthyValue $env:TOOLCHAIN_DISABLE_UPDATE_CHECK) { return $false }
	$ttl = Get-ToolchainUpdateCheckTtl
	if ($ttl -eq [timespan]::Zero) { return $true }
	$path = Get-ToolchainUpdateCheckPath
	if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $true }
	try {
		$last = [datetime]::Parse((Get-Content -LiteralPath $path -Raw).Trim()).ToUniversalTime()
		return (([datetime]::UtcNow - $last) -ge $ttl)
	} catch {
		return $true
	}
}

function Set-ToolchainUpdateCheckTime {
	try {
		$path = Get-ToolchainUpdateCheckPath
		MakeDirIfNotExist (Split-Path -Parent $path) | Out-Null
		[IO.File]::WriteAllText($path, [datetime]::UtcNow.ToString('o'))
	} catch {
		Write-Debug "failed to persist update-check time: $_"
	}
}
