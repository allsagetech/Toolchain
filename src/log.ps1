function Write-ToolchainInfo {
	param (
		[Parameter(Mandatory)][string]$Line
	)
	Write-Information $Line -InformationAction Continue -Tags @('Toolchain','Info')
}
