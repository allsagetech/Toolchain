<#
Toolchains
Copyright (c) 2021 - 02-08-2026 U.S. Federal Government
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

function BuildPsm1 {
	$file = "$PSScriptRoot\src\tlc.ps1"
	$script:seen = @($file)
	$parse = {
		param (
			[string]$path
		)
		$content = ''
		foreach ($line in (Get-Content $path)) {
			if ($line -match '^\. \$PSScriptRoot\\(.+)\.ps1$') {
				$file = ".\src\$($Matches[1]).ps1"
				if ($file -notin $seen) {
					$script:seen += $file
					$content += & $parse $file
				}
			} else {
				$content += $line + "`r`n"
			}
		}
		return $content
	}
	return & $parse $file
}

function GetModuleVersion {
	$verFile = Join-Path $PSScriptRoot 'VERSION'
	if (Test-Path -LiteralPath $verFile -PathType Leaf) {
		return (Get-Content -LiteralPath $verFile -Raw).Trim()
	}
	return "0.0.0"
}

$buildDir = "$PSScriptRoot\build\Toolchain"
if (-not (Test-Path $buildDir -PathType Container)) {
	New-Item -Path $buildDir -ItemType Directory | Out-Null
}

Out-File "$buildDir\Toolchain.psm1" -Encoding ascii -Force -InputObject (BuildPsm1)
Out-File "$buildDir\Toolchain.psd1" -Encoding ascii -Force -InputObject @"
@{
	RootModule = 'Toolchain.psm1'
	ModuleVersion = '$(GetModuleVersion)'
	CompatiblePSEditions = @('Desktop','Core')
	GUID = '12d99217-b208-4995-8cdf-26e4cf695588'
	PowerShellVersion = '5.1'
	Author = 'AllSageTech'
	CompanyName = 'AllSageTech, LLC'
	Copyright = 'Mozilla Public License Version 2.0'
	Description = 'A package manager and environment to provide consistent tooling for software teams.'
	FunctionsToExport = @('Invoke-Toolchain')
	FormatsToProcess = @('Toolchain.Format.ps1xml')
	CmdletsToExport = @()
	VariablesToExport = ''
	AliasesToExport = @('toolchain', 'tool', 'tlc')
	PrivateData = @{
		PSData = @{
			Tags = @('windows', 'docker', 'package-manager', 'package', 'development', 'powershell', 'container', 'configuration', 'toolchain', 'toolchains')
			LicenseUri = 'https://github.com/allsagetech/toolchain/blob/main/LICENSE.md'
			ProjectUri = 'https://github.com/allsagetech/toolchain'
		}
	}
}
"@
Out-File "$buildDir\Toolchain.Format.ps1xml" -Encoding ascii -Force -InputObject @"
<?xml version="1.0" encoding="utf-8"?>
<Configuration>
	<ViewDefinitions>
		<View>
			<Name>Toolchain.LocalPackage</Name>
				<ViewSelectedBy>
					<TypeName>LocalPackage</TypeName>
				</ViewSelectedBy>
				<TableControl>
					<TableHeaders />
					<TableRowEntries>
						<TableRowEntry>
							<TableColumnItems>
								<TableColumnItem>
									<PropertyName>Package</PropertyName>
								</TableColumnItem>
								<TableColumnItem>
									<PropertyName>Tag</PropertyName>
								</TableColumnItem>
								<TableColumnItem>
									<PropertyName>Version</PropertyName>
								</TableColumnItem>
								<TableColumnItem>
									<PropertyName>Digest</PropertyName>
								</TableColumnItem>
								<TableColumnItem>
									<PropertyName>Size</PropertyName>
								</TableColumnItem>
							</TableColumnItems>
						</TableRowEntry>
					</TableRowEntries>
				</TableControl>
			</View>
	</ViewDefinitions>
</Configuration>
"@
