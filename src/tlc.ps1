<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

. $PSScriptRoot\package.ps1
. $PSScriptRoot\shell.ps1

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
		[ValidateSet('version', 'v', 'remote', 'list', 'load', 'pull', 'exec', 'run', 'remove', 'rm', 'save', 'prune', 'update', 'init', 'doctor', 'help', 'h')]
		[string]$Command,
		[Parameter(ValueFromRemainingArguments)]
		[object[]]$ArgumentList
	)
	try {
		switch ($Command) {
			{$_ -in 'v', 'version'} {
				Invoke-ToolchainVersion
			}
		'remote' {
			Invoke-ToolchainRemote @ArgumentList
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
			{$_ -in 'remove', 'rm'} {
			$pkgs = @($ArgumentList) | ForEach-Object { [string]$_ }
			Invoke-ToolchainRemove -Packages $pkgs
		}
			'save' {
				$params, $remaining = ResolveParameters 'Invoke-ToolchainSave' $ArgumentList
				Invoke-ToolchainSave @params @remaining
			}			'exec' {
				$params, $remaining = ResolveParameters 'Invoke-ToolchainExec' $ArgumentList
				if (-not $params.ScriptBlock -and $null -ne $remaining -and $remaining.Count -gt 0) {
					if ($remaining[-1] -is [scriptblock]) {
						$params.ScriptBlock = $remaining[-1]
						if ($remaining.Count -gt 1) {
							$params.Packages += @($remaining[0..($remaining.Count-2)]) | ForEach-Object { [string]$_ }
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
			$args = @($ArgumentList)
			$fnName = if ($args.Count -ge 1) { [string]$args[0] } else { $null }
			$rest = if ($args.Count -gt 1) { $args[1..($args.Count - 1)] } else { @() }
			Invoke-ToolchainRun -FnName $fnName -ArgumentList $rest
		}

			'init' {
				$params, $remaining = ResolveParameters 'Invoke-ToolchainInit' $ArgumentList
				Invoke-ToolchainInit @params @remaining
			}
			'doctor' {
				$params, $remaining = ResolveParameters 'Invoke-ToolchainDoctor' $ArgumentList
				Invoke-ToolchainDoctor @params @remaining
			}

			{$_ -in 'help', 'h'} {
				Invoke-ToolchainHelp
			}
		}
	} catch {
		Write-Error $_
	}
}

function GetConfigPackages {
	$cfg = FindConfig
	if ($cfg) {
		. $cfg
	}
	[string[]]$ToolchainPackages
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
		if ($fn.parameters.keys -and ($ArgumentList[$i] -match '^-([^:]+)(?::(.*))?$') -and ($Matches[1] -in $fn.parameters.keys)) {
			$name = $Matches[1]
			$value = $Matches[2]
			if ($value) {
				$params.$name = $value
			} else {
				if ($fn.parameters.$name.SwitchParameter -and $null -eq $value) {
					$params.$name = $true
				} else {
					$params.$name = $ArgumentList[$i+1]
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
	}
	TryEachPackage $Packages { $Input | AsPackage | PullPackage | Out-Null } -ActionDescription 'pull'
}

function Invoke-ToolchainRun {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[string]$FnName,
		[Parameter(ValueFromRemainingArguments)]
		[object[]]$ArgumentList
	)
	$cfg = FindConfig
	if ($cfg) {
		. $cfg
	}
	$fn = Get-Item "function:Toolchain$FnName"
	if ($fn) {
		$params, $remaining = ResolveParameters "Toolchain$FnName" $ArgumentList
		$script = { & $fn @params @remaining }
		if ($ToolchainPackages) {
			Invoke-ToolchainExec -Packages $ToolchainPackages -ScriptBlock $script
		} else {
			& $script
		}
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
	}
	$null = UpdatePackages -Auto -Packages $Packages
	$resolved = TryEachPackage $Packages { $Input | ResolvePackage } -ActionDescription 'resolve'
	ExecuteScript -ScriptBlock $ScriptBlock -Pkgs $resolved
}

function Invoke-ToolchainRemote {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[ValidateSet('list')]
		[string]$Command
	)
	switch ($Command) {
		'list' {
			GetDockerTags
		}
	}
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
	}
	if (-not $Output) {
		Write-Error "no output directory provided"
	}
	MakeDirIfNotExist $Output | Out-Null
	$results = TryEachPackage $Packages { $Input | AsPackage | PullPackage -Output $Output -Sign:$Sign } -ActionDescription 'save'
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
    [switch]$Force
  )

  $cfgPath = Join-Path (Get-Location).Path 'Toolchain.ps1'
  if ((Test-Path -LiteralPath $cfgPath -PathType Leaf) -and (-not $Force)) {
    Write-ToolchainInfo "Toolchain.ps1 already exists at $cfgPath (use -Force to overwrite)"
    return
  }

  $content = @'
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

  Set-Content -LiteralPath $cfgPath -Value $content -Encoding utf8
  Write-ToolchainInfo "Wrote $cfgPath"
}

function Invoke-ToolchainDoctor {
  [CmdletBinding()]
  param(
    [switch]$Strict
  )

  $errors = @()

  try {
    $p = GetToolchainPath
    Write-ToolchainInfo "ToolchainPath: $p"
    MakeDirIfNotExist $p | Out-Null
    $test = Join-Path $p (".doctor." + [guid]::NewGuid().ToString('n'))
    'ok' | Set-Content -LiteralPath $test -Encoding ascii
    Remove-Item -LiteralPath $test -Force
  } catch {
    $errors += "ToolchainPath is not writable: $_"
  }

  $repoPath = GetToolchainRepo
  if ($repoPath) {
    Write-ToolchainInfo "Offline repository: $repoPath"
    if (-not (Test-Path -LiteralPath $repoPath -PathType Container)) {
      $errors += "ToolchainRepo not found: $repoPath"
    }
  } else {
    Write-ToolchainInfo "Registry: $(GetRegistryBaseUrl)"
    Write-ToolchainInfo "Repository: $(GetRegistryRepoName)"
    try {
      $tags = GetTagsList
      $count = @($tags.tags).Count
      Write-ToolchainInfo "Registry reachable; tags count: $count"
    } catch {
      $errors += "Registry check failed: $_"
    }
  }

  if ($errors.Count -gt 0) {
    foreach ($e in $errors) { Write-Error $e }
    if ($Strict) { throw "doctor found $($errors.Count) issue(s)" }
  } else {
    Write-ToolchainInfo "doctor: ok"
  }
}

function Invoke-ToolchainHelp {
@"

Usage: toolchain COMMAND

Commands:
  version        Outputs the version of the module
  list           Outputs a list of installed packages
  remote list    Outputs an object of remote packages and versions
  pull           Downloads packages
  load           Loads packages into the PowerShell session
  exec           Runs a user-defined scriptblock in a managed PowerShell session
  run            Runs a user-defined scriptblock provided in a project file
  update         Updates all tagged packages
  prune          Deletes unreferenced packages
  remove         Untags and deletes packages
  save           Downloads packages for use in an offline installation
  init           Writes a starter Toolchain.ps1 in the current directory
  doctor         Prints diagnostics for your Toolchain setup
  help           Outputs usage for this command

For detailed documentation and examples, visit https://github.com/allsagetech/toolchain.

"@
}

function CheckForUpdates {
	try {
		$params = @{
			URL = "https://www.powershellgallery.com/packages/toolchain"
			Method = 'HEAD'
		}
		$resp = HttpRequest @params | HttpSend -NoRedirect
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
	}
}

Set-Alias -Name 'toolchain' -Value 'Invoke-Toolchain' -Scope Global
Set-Alias -Name 'tool' -Value 'Invoke-Toolchain' -Scope Global
Set-Alias -Name 'tlc' -Value 'Invoke-Toolchain' -Scope Global


function Invoke-ToolchainModuleEntry {
	[CmdletBinding()]
	param(
		[switch]$Force
	)
	$isModuleEntry = ('Toolchain.psm1' -eq (Split-Path $MyInvocation.ScriptName -Leaf))
	$forceModuleEntry = ($Force -or (Test-TruthyValue $env:TOOLCHAIN_RUN_MODULE_ENTRY))
	if ($isModuleEntry -or $forceModuleEntry) {
		CheckForUpdates
		PrunePackages -Auto
		return $true
	}
	return $false
}

# Run module-entry behavior only when imported as Toolchain.psm1 (or forced via env/parameter).
$null = Invoke-ToolchainModuleEntry
