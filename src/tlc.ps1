<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

. $PSScriptRoot\package.ps1
. $PSScriptRoot\shell.ps1
. $PSScriptRoot\powershell-shell.ps1
. $PSScriptRoot\maintenance.ps1
. $PSScriptRoot\profile.ps1
. $PSScriptRoot\cluster.ps1
. $PSScriptRoot\bootstrap.ps1
. $PSScriptRoot\k9s.ps1
. $PSScriptRoot\health.ps1
. $PSScriptRoot\project.ps1
. $PSScriptRoot\deployment-package.ps1
. $PSScriptRoot\project-lock.ps1
. $PSScriptRoot\environment.ps1
. $PSScriptRoot\audit.ps1
. $PSScriptRoot\help.ps1
. $PSScriptRoot\predictor.ps1
. $PSScriptRoot\completion.ps1

<#
.SYNOPSIS
A package manager and environment to provide consistent tooling for software teams.

.DESCRIPTION
Toolchain manages software packages using container technology and allows users to configure local PowerShell sessions to their need. Toolchain seamlessly integrates common packages with a standardized project script to enable common build commands kept in source control for consistency.

.LINK
For detailed documentation and examples, visit https://github.com/allsagetech/toolchain.
#>
function Invoke-Toolchain {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[ValidateSet('version', 'v', 'remote', 'list', 'load', 'pull', 'exec', 'run', 'shell', 'remove', 'rm', 'save', 'prune', 'update', 'init', 'lock', 'restore', 'sync', 'activate', 'deactivate', 'verify', 'audit', 'profile', 'cluster', 'package', 'k9s', 'doctor', 'completion', 'help', 'h')]
		[string]$Command,
		[Parameter(ValueFromRemainingArguments)]
		[object[]]$ArgumentList
	)
	Invoke-ToolchainDeferredUpdateCheck
	try {
		$helpRequest = Get-ToolchainHelpRequest -Command $Command -ArgumentList $ArgumentList
		if ($helpRequest.Requested) {
			Invoke-ToolchainHelp -CommandPath $helpRequest.CommandPath
			return
		}
		switch ($Command) {
			{ $_ -in 'v', 'version' } {
				Invoke-ToolchainVersion
			}
			'remote' {
				$params, $remaining = ResolveParameters 'Invoke-ToolchainRemote' $ArgumentList
				Invoke-ToolchainRemote @params @remaining
			}
			'list' {
				Invoke-ToolchainList
			}
			'load' {
				$pkgs = @($ArgumentList) | ForEach-Object { [string]$_ }
				Invoke-ToolchainLoad -Packages $pkgs
			}
			'pull' {
				$pkgs = @($ArgumentList) | ForEach-Object { [string]$_ }
				Invoke-ToolchainPull -Packages $pkgs
			}
			'prune' {
				Invoke-ToolchainPrune
			}
			'update' {
				Invoke-ToolchainUpdate
			}
			{ $_ -in 'remove', 'rm' } {
				$pkgs = @($ArgumentList) | ForEach-Object { [string]$_ }
				Invoke-ToolchainRemove -Packages $pkgs
			}
			'save' {
				$params, $remaining = ResolveParameters 'Invoke-ToolchainSave' $ArgumentList
				Invoke-ToolchainSave @params @remaining
			}
			'exec' {
				$params, $remaining = ResolveParameters 'Invoke-ToolchainExec' $ArgumentList
				if (-not $params.ScriptBlock -and $null -ne $remaining -and $remaining.Count -gt 0) {
					if ($remaining[-1] -is [scriptblock]) {
						$params.ScriptBlock = $remaining[-1]
						if ($remaining.Count -gt 1) {
							$params.Packages += @($remaining[0..($remaining.Count - 2)]) | ForEach-Object { [string]$_ }
						}
						$remaining = @()
					} else {
						$params.Packages += @($remaining) | ForEach-Object { [string]$_ }
						$remaining = @()
					}
				}
				Invoke-ToolchainExec @params @remaining
			}
			'run' {
				$runArguments = @($ArgumentList)
				if ($runArguments.Count -lt 1) {
					Write-Error "run requires a function name (example: toolchain run build)"
					break
				}
				$fnName = [string]$runArguments[0]
				$rest = if ($runArguments.Count -gt 1) { $runArguments[1..($runArguments.Count - 1)] } else { @() }
				Invoke-ToolchainRun -FnName $fnName -ArgumentList $rest
			}
			'shell' {
				$params, $remaining = ResolveParameters 'Invoke-ToolchainShell' $ArgumentList
				Invoke-ToolchainShell @params @remaining
			}
			'init' {
				$params, $remaining = ResolveParameters 'Invoke-ToolchainInit' $ArgumentList
				Invoke-ToolchainInit @params @remaining
			}
			'lock' {
				$params, $remaining = ResolveParameters 'Invoke-ToolchainLock' $ArgumentList
				if ($remaining) {
					if ($params.ContainsKey('Update')) { $params.Update = @($params.Update) + @($remaining | ForEach-Object { [string]$_ }) }
					else { $params.Packages = @($remaining | ForEach-Object { [string]$_ }) }
				}
				Invoke-ToolchainLock @params
			}
			'restore' {
				$params, $remaining = ResolveParameters 'Invoke-ToolchainRestore' $ArgumentList
				Invoke-ToolchainRestore @params @remaining
			}
			'sync' {
				$params, $remaining = ResolveParameters 'Invoke-ToolchainSync' $ArgumentList
				Invoke-ToolchainSync @params @remaining
			}
			'activate' {
				$params, $remaining = ResolveParameters 'Invoke-ToolchainActivate' $ArgumentList
				Invoke-ToolchainActivate @params @remaining
			}
			'deactivate' {
				$params, $remaining = ResolveParameters 'Invoke-ToolchainDeactivate' $ArgumentList
				Invoke-ToolchainDeactivate @params @remaining
			}
			'verify' {
				$params, $remaining = ResolveParameters 'Invoke-ToolchainVerify' $ArgumentList
				if ($remaining) { $params.Packages = @($remaining | ForEach-Object { [string]$_ }) }
				Invoke-ToolchainVerify @params
			}
			'audit' {
				$params, $remaining = ResolveParameters 'Invoke-ToolchainAudit' $ArgumentList
				Invoke-ToolchainAudit @params @remaining
			}
			'profile' {
				$params, $remaining = ResolveParameters 'Invoke-ToolchainProfile' $ArgumentList
				Invoke-ToolchainProfile @params @remaining
			}
			'cluster' {
				$params, $remaining = ResolveParameters 'Invoke-ToolchainCluster' $ArgumentList
				Invoke-ToolchainCluster @params @remaining
			}
			'package' {
				$params, $remaining = ResolveParameters 'Invoke-ToolchainDeploymentPackage' $ArgumentList
				Invoke-ToolchainDeploymentPackage @params @remaining
			}
			'k9s' {
				$params, $remaining = ResolveParameters 'Invoke-ToolchainK9s' $ArgumentList
				Invoke-ToolchainK9s @params -ArgumentList $remaining
			}
			'doctor' {
				$params, $remaining = ResolveParameters 'Invoke-ToolchainDoctor' $ArgumentList
				Invoke-ToolchainDoctor @params @remaining
			}
			'completion' {
				$params, $remaining = ResolveParameters 'Invoke-ToolchainPredictiveIntelliSense' $ArgumentList
				Invoke-ToolchainPredictiveIntelliSense @params @remaining
			}
		}
	} catch {
		Write-Error $_
	}
}

function GetConfigPackages {
	$config = Find-ToolchainProjectConfig
	if (-not $config) { return $null }
	$project = Read-ToolchainProject -Path $config
	return @($project.Packages)
}

function ResolveParameters {
	param (
		[Parameter(Mandatory)]
		[string]$FnName,
		[object[]]$ArgumentList
	)
	$fn = Get-Item "function:$FnName"
	$params = @{}
	$remaining = [Collections.ArrayList]@()
	for ($i = 0; $i -lt $ArgumentList.Count; $i++) {
		$arg = [string]$ArgumentList[$i]
		$argMatch = [regex]::Match($arg, '^-([^:]+)(?::(.*))?$')
		if ($fn.parameters.keys -and $argMatch.Success -and ($argMatch.Groups[1].Value -in $fn.parameters.keys)) {
			$name = $argMatch.Groups[1].Value
			$parameter = $fn.parameters[$name]
			$hasInlineValue = $arg.Contains(':')
			$value = if ($hasInlineValue) { $argMatch.Groups[2].Value } else { $null }

			if ($parameter.SwitchParameter) {
				if (-not $hasInlineValue) {
					$params[$name] = $true
				} elseif ($value -match '^(?i:true|1|yes|\$true)$') {
					$params[$name] = $true
				} elseif ($value -match '^(?i:false|0|no|\$false)$') {
					$params[$name] = $false
				} else {
					throw "invalid switch value for -$name`: $value"
				}
			} else {
				if ($hasInlineValue) {
					$params[$name] = $value
				} else {
					if ($i + 1 -ge $ArgumentList.Count) {
						throw "missing value for -$name"
					}
					$next = [string]$ArgumentList[$i + 1]
					$nextMatch = [regex]::Match($next, '^-([^:]+)(?::(.*))?$')
					if ($nextMatch.Success -and ($nextMatch.Groups[1].Value -in $fn.parameters.keys)) {
						throw "missing value for -$name"
					}
					$params[$name] = $ArgumentList[$i + 1]
					$i += 1
				}
			}
		} else {
			[void]$remaining.Add($ArgumentList[$i])
		}
	}
	return $params, $remaining
}

function Invoke-ToolchainVersion {
	[CmdletBinding()]
	param ()
	(Get-Module -Name Toolchain).Version
}

function Invoke-ToolchainList {
	[CmdletBinding()]
	param ()
	GetLocalPackages
}

function Invoke-ToolchainLoad {
	[CmdletBinding()]
	param (
		[string[]]$Packages
	)
	if (-not $Packages) {
		$Packages = GetConfigPackages
	}
	if (-not $Packages) {
		Write-Error 'no packages provided'
		return
	}
	$null = UpdatePackages -Auto -Packages $Packages
	TryEachPackage $Packages { $Input | ResolvePackage | LoadPackage } -ActionDescription 'load'
}

function Invoke-ToolchainRemove {
	[CmdletBinding()]
	param (
		[string[]]$Packages
	)
	TryEachPackage $Packages { $Input | AsPackage | RemovePackage } -ActionDescription 'remove'
}

function Invoke-ToolchainUpdate {
	[CmdletBinding()]
	param ()
	return (UpdatePackages)
}

function Invoke-ToolchainPrune {
	[CmdletBinding()]
	param ()
	PrunePackages
}

function Invoke-ToolchainPull {
	[CmdletBinding()]
	param (
		[string[]]$Packages
	)
	if (-not $Packages) {
		$Packages = GetConfigPackages
	}
	if (-not $Packages) {
		Write-Error "no packages provided"
		return
	}
	TryEachPackage $Packages { Invoke-PullPackageWithRetry -PackageRef $Input | Out-Null } -ActionDescription 'pull'
}

function Invoke-ToolchainRun {
	[CmdletBinding()]
	param (
		[string]$FnName,
		[Parameter(ValueFromRemainingArguments)]
		[object[]]$ArgumentList
	)
	if (-not $FnName) {
		Write-Error "function name is required"
		return
	}

	$cfg = FindConfig
	if (-not $cfg) {
		Write-Error "Toolchain.ps1 not found from current directory upward"
		return
	}
	. $cfg

	$toolchainFnName = "Toolchain$FnName"
	$fn = Get-Command -Name $toolchainFnName -CommandType Function -ErrorAction SilentlyContinue
	if (-not $fn) {
		Write-Error "function '$toolchainFnName' not found in '$cfg'"
		return
	}

	$params, $remaining = ResolveParameters $toolchainFnName $ArgumentList
	$script = { & $fn @params @remaining }
	$projectPackages = GetConfigPackages
	if ($projectPackages) {
		Invoke-ToolchainExec -Packages $projectPackages -ScriptBlock $script
	} else {
		& $script
	}
}

function Invoke-ToolchainExec {
	[CmdletBinding()]
	param (
		[string[]]$Packages,
		[scriptblock]$ScriptBlock = { $Host.EnterNestedPrompt() }
	)
	if (-not $Packages) {
		$Packages = GetConfigPackages
	}
	if (-not $Packages) {
		Write-Error "no packages provided"
		return
	}
	$null = UpdatePackages -Auto -Packages $Packages
	$resolved = TryEachPackage $Packages { $Input | ResolvePackage } -ActionDescription 'resolve'
	ExecuteScript -ScriptBlock $ScriptBlock -Pkgs $resolved
}

function Invoke-ToolchainRemote {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory, Position = 0)]
		[ValidateSet('list', 'models', 'all', 'tags', 'health', 'info')]
		[string]$Command,
		[Parameter(Position = 1)]
		[string]$Package,
		[switch]$Refresh,
		[switch]$Json,
		[switch]$OnlyProblems
	)
	$result = switch ($Command) {
		'list' {
			if ($Package) { GetDockerTags -Kind Tooling -Refresh:$Refresh }
			else { GetDockerTags -Kind All -ToolingDefaultDisplay -Refresh:$Refresh }
		}
		'models' {
			GetDockerTags -Kind Model -Refresh:$Refresh
		}
		'all' {
			GetDockerTags -Kind All -Refresh:$Refresh
		}
		'tags' {
			if ($Package) { throw 'remote tags does not accept a package name' }
			GetRemoteRegistryTags -Refresh:$Refresh
		}
		'health' {
			Get-ToolchainPackageHealth -Package $Package -OnlyProblems:$OnlyProblems -Refresh:$Refresh
		}
		'info' {
			if (-not $Package) { throw 'remote info requires a package name' }
			Get-ToolchainPackageHealth -Package $Package -Refresh:$Refresh
		}
	}
	if ($Package -and $Command -notin @('health', 'info')) {
		$property = $result.PSObject.Properties |
			Where-Object { $_.Name -ieq $Package } |
			Select-Object -First 1
		if (-not $property) { throw "remote package not found in '$Command' catalog: $Package" }
		$versions = @($property.Value | ForEach-Object { $_.ToString() })
		if ($Json) { return (ConvertTo-Json -InputObject $versions -Depth 20) }
		return $versions
	}
	if ($Json) { return ($result | ConvertTo-Json -Depth 20) }
	return $result
}

function Invoke-ToolchainSave {
	[CmdletBinding()]
	param (
		[Alias('Pkg','Package')]
		[string[]]$Packages,
		[Parameter(Mandatory)]
		[string]$Output,
		[switch]$Sign,
		[switch]$Index
	)
	if (-not $Packages) {
		$Packages = GetConfigPackages
	}
	if (-not $Packages) {
		Write-Error "no packages provided"
		return
	}
	if (-not $Output) {
		Write-Error "no output directory provided"
		return
	}
	MakeDirIfNotExist $Output | Out-Null
	$results = TryEachPackage $Packages { Invoke-PullPackageWithRetry -PackageRef $Input -Output $Output -Sign:$Sign } -ActionDescription 'save'
	if ($Index) {
		$idxPath = Join-Path (Resolve-Path $Output) 'toolchain.index.json'
		$idx = @{ 
			generatedAt = [datetime]::UtcNow.ToString('u')
			registry = if (GetToolchainRepo) { 'offline' } else { (GetRegistryBaseUrl) }
			repository = if (GetToolchainRepo) { (GetToolchainRepo) } else { (GetRegistryRepoName) }
			packages = $results
		}
		[IO.File]::WriteAllText($idxPath, (ConvertTo-Json $idx -Depth 50))
		if ($Sign) {
			$null = New-ToolchainFileCmsSignature -Path $idxPath -SignaturePath "${idxPath}.p7s"
		}
	}
}

function Invoke-ToolchainInit {
  [CmdletBinding()]
  param(
    [switch]$Force,
    [switch]$Legacy
  )

  $cfgPath = Join-Path (Get-Location).Path $(if ($Legacy) { 'Toolchain.ps1' } else { 'toolchain.yaml' })
  if ((Test-Path -LiteralPath $cfgPath -PathType Leaf) -and (-not $Force)) {
    Write-ToolchainInfo "Toolchain project already exists at $cfgPath (use -Force to overwrite)"
    return
  }

  $content = if ($Legacy) { @'
# Toolchain project file
#
# Set the packages you want in this repo:
#   $ToolchainPackages = @('cmake:latest','git:latest')
#
# Then run:
#   toolchain pull
#   toolchain load

$ToolchainPackages = @(
  'git:latest'
)

# Example project command:
# function ToolchainBuild { param([string]$Configuration='Release') Write-Host "Build $Configuration" }
'@
  } else { @'
schemaVersion: 1
packages:
  - name: git
    version: latest
'@
  }

  Set-Content -LiteralPath $cfgPath -Value $content -Encoding utf8
  Write-ToolchainInfo "Wrote $cfgPath"
}

function Invoke-ToolchainDoctor {
  [CmdletBinding()]
  param(
    [switch]$Strict,
    [switch]$PassThru,
    [switch]$Json,
    [switch]$Refresh
  )

  $errors = @()
  $toolchainPath = $null
  $repoPath = $null
  $registry = $null
  $repository = $null
  $tagCount = $null
  $platform = $null
  $signatureVerification = $null
  $credentialSource = $null
  $structured = $PassThru -or $Json

  try {
    $toolchainPath = GetToolchainPath
    if (-not $structured) { Write-ToolchainInfo "ToolchainPath: $toolchainPath" }
    MakeDirIfNotExist $toolchainPath | Out-Null
    $test = Join-Path $toolchainPath (".doctor." + [guid]::NewGuid().ToString('n'))
    'ok' | Set-Content -LiteralPath $test -Encoding ascii
    Remove-Item -LiteralPath $test -Force
  } catch {
    $errors += "ToolchainPath is not writable: $_"
  }

  $repoPath = GetToolchainRepo
  try { $platform = "$(GetRegistryPlatformOs)/$(GetRegistryPlatformArch)" } catch { $errors += "Platform detection failed: $_" }
  $signatureVerification = if ($repoPath) { 'offline-policy' } elseif (Get-ToolchainCosignVerifyEnabled) { 'required' } else { 'optional' }
	if ($signatureVerification -eq 'required' -and -not (Find-ToolchainCosignApplication) -and -not (Test-ToolchainCosignBootstrapSupported)) {
		$errors += 'Cosign verification is required, but Cosign was not found and automatic verified bootstrap is unsupported on this platform.'
	}
  if ($repoPath) {
    if (-not $structured) { Write-ToolchainInfo "Offline repository: $repoPath" }
    if (-not (Test-Path -LiteralPath $repoPath -PathType Container)) {
      $errors += "ToolchainRepo not found: $repoPath"
    }
  } else {
    $registry = GetRegistryBaseUrl
    $repository = GetRegistryRepoName
	if ($env:TOOLCHAIN_TOKEN) { $credentialSource = 'environment-token' }
	else {
		try {
			$credential = Get-ToolchainRegistryCredential -RegistryUrl $registry
			if ($credential) { $credentialSource = [string]$credential.Source }
		} catch { $errors += "Registry credential discovery failed: $_" }
	}
    if (-not $structured) {
      Write-ToolchainInfo "Registry: $registry"
      Write-ToolchainInfo "Repository: $repository"
    }
    try {
      $tags = GetTagsList -Refresh:$Refresh
      $tagCount = @($tags.tags).Count
      if (-not $structured) { Write-ToolchainInfo "Registry reachable; tags count: $tagCount" }
    } catch {
      $errors += "Registry check failed: $_"
    }
  }

  $result = [pscustomobject]@{
    PSTypeName = 'Toolchain.DoctorResult'
    Healthy = ($errors.Count -eq 0)
    ToolchainPath = $toolchainPath
    OfflineRepository = $repoPath
    Registry = $registry
    Repository = $repository
    Platform = $platform
    SignatureVerification = $signatureVerification
    CredentialSource = $credentialSource
    TagCount = $tagCount
    Errors = @($errors)
  }
  if ($Json) { $result | ConvertTo-Json -Depth 5 }
  elseif ($PassThru) { $result }

  if ($errors.Count -gt 0) {
    foreach ($e in $errors) { Write-Error $e }
    if ($Strict) { throw "doctor found $($errors.Count) issue(s)" }
  } elseif (-not $structured) {
    Write-ToolchainInfo "doctor: ok"
  }
}

function CheckForUpdates {
	param([switch]$Force)
	if (-not $Force -and -not (Test-ToolchainUpdateCheckDue)) { return }
	try {
		$params = @{
			URL = "https://www.powershellgallery.com/packages/toolchain"
			Method = 'HEAD'
		}
		$resp = HttpRequest @params | HttpSend -NoRedirect -TimeoutSeconds 3
		if ($resp.Headers.Location) {
			$docker = [Version]::new($resp.Headers.Location.OriginalString.Substring('/packages/toolchain/'.Length))
			$local = [Version]::new((Import-PowerShellDataFile -Path "$PSScriptRoot\Toolchain.psd1").ModuleVersion)
			if ($docker -gt $local) {
				Write-ToolchainInfo "$([char]27)[92mA new version of Toolchain is available! [v$docker]$([char]27)[0m"
				Write-ToolchainInfo "$([char]27)[92mUse command ``Update-Module Toolchain`` for the latest version$([char]27)[0m"
			}
		}
	} catch {
		Write-Debug "failed to check for updates: $_"
	} finally {
		Set-ToolchainUpdateCheckTime
	}
}

Set-Alias -Name 'toolchain' -Value 'Invoke-Toolchain' -Scope Global
Set-Alias -Name 'tool' -Value 'Invoke-Toolchain' -Scope Global
Set-Alias -Name 'tlc' -Value 'Invoke-Toolchain' -Scope Global

Register-ToolchainArgumentCompleters


function Invoke-ToolchainModuleEntry {
	[CmdletBinding()]
	param(
		[switch]$Force
	)
	$isModuleEntry = ('Toolchain.psm1' -eq (Split-Path $MyInvocation.ScriptName -Leaf))
	$forceModuleEntry = ($Force -or (Test-TruthyValue $env:TOOLCHAIN_RUN_MODULE_ENTRY))
	if ($isModuleEntry -or $forceModuleEntry) {
		Request-ToolchainDeferredUpdateCheck
		PrunePackages -Auto
		return $true
	}
	return $false
}

# Run module-entry behavior only when imported as Toolchain.psm1 (or forced via env/parameter).
$null = Invoke-ToolchainModuleEntry
