<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

. $PSScriptRoot\cluster.ps1

function Invoke-ToolchainK9s {
	[CmdletBinding()]
	param(
		[string]$Cluster,
		[string]$Kubeconfig,
		[Parameter(ValueFromRemainingArguments)]
		[object[]]$ArgumentList
	)

	if ($Cluster -and $Kubeconfig) {
		throw '-Cluster and -Kubeconfig cannot be used together'
	}

	if ($Cluster) {
		$Kubeconfig = Invoke-ToolchainCluster -Command kubeconfig -Name $Cluster
	} elseif ($Kubeconfig) {
		$resolved = Resolve-Path -LiteralPath $Kubeconfig -ErrorAction Stop
		if (-not (Test-Path -LiteralPath $resolved.Path -PathType Leaf)) {
			throw "kubeconfig is not a file: $Kubeconfig"
		}
		$Kubeconfig = $resolved.Path
	}

	$k9s = Get-ToolchainClusterExecutable `
		-Name 'k9s' `
		-Package 'k9s' `
		-InstallHint 'Install K9s or publish the k9s Toolchains package for this platform.'
	$arguments = @()
	if ($Kubeconfig) { $arguments += @('--kubeconfig', $Kubeconfig) }
	$arguments += @($ArgumentList | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })

	& $k9s @arguments
	$exitCode = $LASTEXITCODE
	if ($null -ne $exitCode -and [int]$exitCode -ne 0) {
		throw "k9s exited with code $exitCode"
	}
}
