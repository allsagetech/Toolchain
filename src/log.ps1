<#
Toolchains
Copyright (c) 2021 - 02-08-2026 U.S. Federal Government
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

$script:ToolchainLogLevel = 'info'
$script:ToolchainLogFormat = 'console'

function Set-ToolchainLogConfiguration {
	param(
		[Parameter(Mandatory)][ValidateSet('warn', 'info', 'debug', 'trace')][string]$Level,
		[Parameter(Mandatory)][ValidateSet('console', 'json', 'dev')][string]$Format
	)
	$previous = [pscustomobject]@{ Level = $script:ToolchainLogLevel; Format = $script:ToolchainLogFormat }
	$script:ToolchainLogLevel = $Level
	$script:ToolchainLogFormat = $Format
	return $previous
}

function Reset-ToolchainLogConfiguration {
	param([Parameter(Mandatory)]$Configuration)
	$script:ToolchainLogLevel = [string]$Configuration.Level
	$script:ToolchainLogFormat = [string]$Configuration.Format
}

function Write-ToolchainInfo {
	param (
		[Parameter(Mandatory)][string]$Line
	)
	if ($script:ToolchainLogLevel -eq 'warn') { return }
	$message = switch ($script:ToolchainLogFormat) {
		'json' { [ordered]@{ timestamp = [DateTime]::UtcNow.ToString('o'); level = 'info'; message = $Line } | ConvertTo-Json -Compress }
		'dev' { "INFO`t$Line" }
		default { $Line }
	}
	Write-Information $message -InformationAction Continue -Tags @('Toolchain','Info')
}
