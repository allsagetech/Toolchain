<#
Toolchains
Copyright (c) 2021 - 02-08-2026 U.S. Federal Government
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

function Write-ToolchainInfo {
	param (
		[Parameter(Mandatory)][string]$Line
	)
	Write-Information $Line -InformationAction Continue -Tags @('Toolchain','Info')
}
