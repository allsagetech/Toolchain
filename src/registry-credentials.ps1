<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

function Get-ToolchainRegistryCredentialServer {
	param([string]$RegistryUrl = (GetRegistryBaseUrl))
	$uri = [Uri]::new($RegistryUrl)
	if ($uri.Host -in @('registry-1.docker.io', 'index.docker.io')) { return 'https://index.docker.io/v1/' }
	return $(if ($uri.IsDefaultPort) { $uri.Host } else { "$($uri.Host):$($uri.Port)" })
}

function Get-ToolchainRegistryAuthFiles {
	$paths = [Collections.ArrayList]::new()
	foreach ($explicit in @($env:TOOLCHAIN_AUTH_FILE, $env:REGISTRY_AUTH_FILE)) {
		if ($explicit) { [void]$paths.Add([IO.Path]::GetFullPath($explicit)) }
	}
	# An explicitly selected auth file is authoritative. This also makes it
	# possible to intentionally test or use anonymous access without leaking
	# credentials from a user's default Docker configuration.
	if ($paths.Count -gt 0) { return @($paths | Select-Object -Unique) }
	if ($env:DOCKER_CONFIG) { [void]$paths.Add((Join-Path ([IO.Path]::GetFullPath($env:DOCKER_CONFIG)) 'config.json')) }
	$homePath = if ($HOME) { [string]$HOME } elseif ($env:USERPROFILE) { [string]$env:USERPROFILE } else { $null }
	if ($homePath) {
		[void]$paths.Add((Join-Path $homePath '.docker/config.json'))
		[void]$paths.Add((Join-Path $homePath '.config/containers/auth.json'))
	}
	return @($paths | Select-Object -Unique)
}

function Get-ToolchainRegistryCredentialKeys {
	param([Parameter(Mandatory)][string]$RegistryUrl)
	$uri = [Uri]::new($RegistryUrl)
	$hostPort = if ($uri.IsDefaultPort) { $uri.Host } else { "$($uri.Host):$($uri.Port)" }
	$keys = @($hostPort, $uri.Host, "$($uri.Scheme)://$hostPort", "$($uri.Scheme)://$hostPort/")
	if ($uri.Host -in @('registry-1.docker.io', 'index.docker.io')) {
		$keys += @('https://index.docker.io/v1/', 'index.docker.io', 'registry-1.docker.io', 'docker.io')
	}
	return @($keys | Select-Object -Unique)
}

function Get-ToolchainObjectPropertyValue {
	param(
		[AllowNull()][object]$Object,
		[Parameter(Mandatory)][string[]]$Names
	)
	if ($null -eq $Object) { return $null }
	foreach ($name in $Names) {
		$property = $Object.PSObject.Properties | Where-Object { $_.Name -ieq $name } | Select-Object -First 1
		if ($property) { return $property.Value }
	}
	return $null
}

function Invoke-ToolchainCredentialHelper {
	param(
		[Parameter(Mandatory)][string]$Helper,
		[Parameter(Mandatory)][string]$Server
	)
	if ($Helper -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') { throw "invalid registry credential helper name '$Helper'" }
	$commandName = "docker-credential-$Helper"
	$command = Get-Command $commandName -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
	if (-not $command) { throw "registry credential helper '$commandName' was configured but not found in PATH" }
	$startInfo = [Diagnostics.ProcessStartInfo]::new()
	$startInfo.FileName = $command.Source
	$startInfo.Arguments = 'get'
	$startInfo.UseShellExecute = $false
	$startInfo.CreateNoWindow = $true
	$startInfo.RedirectStandardInput = $true
	$startInfo.RedirectStandardOutput = $true
	$startInfo.RedirectStandardError = $true
	$process = [Diagnostics.Process]::new()
	$process.StartInfo = $startInfo
	try {
		if (-not $process.Start()) { throw "credential helper '$commandName' did not start" }
		$process.StandardInput.WriteLine($Server)
		$process.StandardInput.Close()
		$output = $process.StandardOutput.ReadToEnd()
		$null = $process.StandardError.ReadToEnd()
		if (-not $process.WaitForExit(10000)) {
			try { $process.Kill() } catch { Write-Debug "Failed to stop timed-out credential helper: $($_.Exception.Message)" }
			throw "registry credential helper '$commandName' timed out"
		}
		if ($process.ExitCode -ne 0) { throw "registry credential helper '$commandName' failed with exit code $($process.ExitCode)" }
		try { $credential = $output | ConvertFrom-Json }
		catch { throw "registry credential helper '$commandName' returned invalid JSON" }
		$username = [string]$credential.Username
		$secret = [string]$credential.Secret
		if (-not $secret) { return $null }
		if ($username -in @('<token>', '<identitytoken>')) {
			return [pscustomobject]@{ IdentityToken = $secret; Source = "helper:$Helper" }
		}
		if (-not $username) { throw "registry credential helper '$commandName' returned no username" }
		return [pscustomobject]@{ Username = $username; Secret = $secret; Source = "helper:$Helper" }
	} finally {
		$process.Dispose()
	}
}

function Get-ToolchainRegistryCredential {
	param([string]$RegistryUrl = (GetRegistryBaseUrl))
	if ($env:TOOLCHAIN_USERNAME -or $env:TOOLCHAIN_PASSWORD) {
		if (-not ($env:TOOLCHAIN_USERNAME -and $env:TOOLCHAIN_PASSWORD)) { throw 'TOOLCHAIN_USERNAME and TOOLCHAIN_PASSWORD must be set together' }
		return [pscustomobject]@{ Username = $env:TOOLCHAIN_USERNAME; Secret = $env:TOOLCHAIN_PASSWORD; Source = 'environment' }
	}
	$keys = Get-ToolchainRegistryCredentialKeys -RegistryUrl $RegistryUrl
	$helperCandidate = $null
	foreach ($path in Get-ToolchainRegistryAuthFiles) {
		if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
		try { $config = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json }
		catch { throw "failed to parse registry auth file '$path': $($_.Exception.Message)" }
		$entry = Get-ToolchainObjectPropertyValue -Object $config.auths -Names $keys
		if ($entry) {
			$identityToken = [string](Get-ToolchainObjectPropertyValue -Object $entry -Names @('identitytoken', 'identityToken'))
			if ($identityToken) { return [pscustomobject]@{ IdentityToken = $identityToken; Source = $path } }
			$encoded = [string](Get-ToolchainObjectPropertyValue -Object $entry -Names @('auth'))
			if ($encoded) {
				try { $decoded = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded)) }
				catch { throw "registry auth entry in '$path' is not valid base64" }
				$separator = $decoded.IndexOf(':')
				if ($separator -le 0) { throw "registry auth entry in '$path' is malformed" }
				return [pscustomobject]@{
					Username = $decoded.Substring(0, $separator)
					Secret = $decoded.Substring($separator + 1)
					Source = $path
				}
			}
		}
		if (-not (Test-TruthyValue $env:TOOLCHAIN_DISABLE_CREDENTIAL_HELPERS)) {
			$helper = [string](Get-ToolchainObjectPropertyValue -Object $config.credHelpers -Names $keys)
			if (-not $helper) { $helper = [string]$config.credsStore }
			if ($helper -and -not $helperCandidate) { $helperCandidate = $helper }
		}
	}
	if ($helperCandidate) {
		try {
			return Invoke-ToolchainCredentialHelper -Helper $helperCandidate -Server (Get-ToolchainRegistryCredentialServer -RegistryUrl $RegistryUrl)
		} catch {
			Write-Debug "Ignoring unavailable registry credential helper '$helperCandidate': $($_.Exception.Message)"
		}
	}
	return $null
}
