<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

BeforeAll {
	. $PSCommandPath.Replace('.Tests.ps1', '.ps1')
}

Describe 'GetConfigPackages' {
	It 'Loads ToolchainPackages from config file' {
		$cfg = Join-Path $TestDrive 'Toolchain.ps1'
		Set-Content -LiteralPath $cfg -Value "`$ToolchainPackages = @('a','b')" -Encoding utf8
		Mock FindConfig { return $cfg }
		(GetConfigPackages) | Should -Be @('a','b')
	}

	It 'Returns $null when no config is found' {
		Mock FindConfig { return $null }
		(GetConfigPackages) | Should -Be $null
	}
}

Describe 'ResolveParameters' {
	It 'Parses flags, switch params, and remaining args' {
		$params, $remaining = ResolveParameters 'Invoke-ToolchainSave' @('-Output','out','-Sign','-Index','pkg1','pkg2')
		$params.Output | Should -Be 'out'
		$params.Sign | Should -Be $true
		$params.Index | Should -Be $true
		@($remaining) | Should -Be @('pkg1','pkg2')
	}

	It 'Parses -Name:value syntax' {
		$params, $remaining = ResolveParameters 'Invoke-ToolchainSave' @('-Output:out','pkg1')
		$params.Output | Should -Be 'out'
		@($remaining) | Should -Be @('pkg1')
	}
}

Describe 'Invoke-Toolchain dispatcher' {
	BeforeEach {
		Mock Invoke-ToolchainVersion { '1.0.0' }
		Mock Invoke-ToolchainList { 'list' }
		Mock Invoke-ToolchainRemote { param($Command) "remote:$Command" }
		Mock Invoke-ToolchainLoad { param([string[]]$Packages) $Packages }
		Mock Invoke-ToolchainPull { param([string[]]$Packages) $Packages }
		Mock Invoke-ToolchainPrune { 'prune' }
		Mock Invoke-ToolchainUpdate { 'update' }
		Mock Invoke-ToolchainRemove { param([string[]]$Packages) $Packages }
		Mock Invoke-ToolchainSave { 'save' }
		Mock Invoke-ToolchainExec { param([string[]]$Packages,[scriptblock]$ScriptBlock) @($Packages).Count }
		Mock Invoke-ToolchainRun { param([string]$FnName,[object[]]$ArgumentList) @($FnName) + @($ArgumentList) }
		Mock Invoke-ToolchainInit { 'init' }
		Mock Invoke-ToolchainDoctor { 'doctor' }
		Mock Invoke-ToolchainHelp { 'help' }
	}

	It 'Routes version commands' {
		(Invoke-Toolchain -Command version) | Should -Be '1.0.0'
		(Invoke-Toolchain -Command v) | Should -Be '1.0.0'
	}

	It 'Routes remote list command' {
		(Invoke-Toolchain -Command remote -ArgumentList @('list')) | Should -Be 'remote:list'
	}

	It 'Normalizes load/pull/remove packages to strings' {
		$r = Invoke-Toolchain -Command load -ArgumentList @('a', 1)
		@($r) | Should -Be @('a','1')

		$r = Invoke-Toolchain -Command pull -ArgumentList @('x', 2)
		@($r) | Should -Be @('x','2')

		$r = Invoke-Toolchain -Command remove -ArgumentList @('y', 3)
		@($r) | Should -Be @('y','3')
	}

	It 'Routes exec with and without scriptblock' {
		(Invoke-Toolchain -Command exec -ArgumentList @('a','b',{ 'hi' })) | Should -Be 2
		(Invoke-Toolchain -Command exec -ArgumentList @('a','b')) | Should -Be 2
	}

	It 'Routes run and passes remaining args' {
		$r = Invoke-Toolchain -Command run -ArgumentList @('build','-X',1)
		@($r) | Should -Be @('build','-X',1)
	}

	It 'Routes other commands' {
		(Invoke-Toolchain -Command prune) | Should -Be 'prune'
		(Invoke-Toolchain -Command update) | Should -Be 'update'
		(Invoke-Toolchain -Command save -ArgumentList @('-Output','out')) | Should -Be 'save'
		(Invoke-Toolchain -Command init) | Should -Be 'init'
		(Invoke-Toolchain -Command doctor) | Should -Be 'doctor'
		(Invoke-Toolchain -Command help) | Should -Be 'help'
		(Invoke-Toolchain -Command h) | Should -Be 'help'
	}

	It 'Writes an error when a command throws' {
		Mock Invoke-ToolchainList { throw 'boom' }
		{ Invoke-Toolchain -Command list -ErrorAction SilentlyContinue } | Should -Not -Throw
	}
}

Describe 'Invoke-ToolchainVersion' {
	It 'Returns the module version' {
		Mock Get-Module { return [pscustomobject]@{ Version = [Version]::new('9.9.9') } }
		(Invoke-ToolchainVersion).ToString() | Should -Be '9.9.9'
	}
}

Describe 'Invoke-ToolchainList/Update/Prune' {
	It 'Invoke-ToolchainList returns local packages' {
		Mock GetLocalPackages { return @('a') }
		Invoke-ToolchainList | Should -Be @('a')
	}
	It 'Invoke-ToolchainUpdate calls UpdatePackages' {
		Mock UpdatePackages { return 7 }
		Invoke-ToolchainUpdate | Should -Be 7
	}
	It 'Invoke-ToolchainPrune calls PrunePackages' {
		Mock PrunePackages { return 8 }
		Invoke-ToolchainPrune | Should -Be 8
	}
}

Describe 'Invoke-ToolchainLoad/Pull/Remove/Exec' {
	BeforeEach {
		Mock UpdatePackages { }
		Mock GetConfigPackages { return @('a','b') }
		Mock ResolvePackage { param([Parameter(ValueFromPipeline)]$Ref) return [pscustomobject]@{ Package = [string]$Ref } }
		Mock LoadPackage { }
		Mock AsPackage { param([Parameter(ValueFromPipeline)]$Ref) return [pscustomobject]@{ Package = [string]$Ref } }
		Mock PullPackage { param([Parameter(ValueFromPipeline)]$Pkg) return @{ Package=$Pkg.Package; Digest='sha256:x' } }
		Mock RemovePackage { }
		Mock ExecuteScript { return 'ran' }

		Mock TryEachPackage {
			param($Packages, $ScriptBlock, $ActionDescription)
			$res = @()
			foreach ($p in $Packages) {
				$res += ($p | & $ScriptBlock)
			}
			return $res
		}
	}

	It 'Invoke-ToolchainLoad uses config packages when none provided' {
		Invoke-ToolchainLoad
		Should -Invoke -CommandName UpdatePackages -Times 1 -Exactly
		Should -Invoke -CommandName LoadPackage -Times 2
	}

	It 'Invoke-ToolchainLoad errors when no packages are available' {
		Mock GetConfigPackages { return $null }
		{ Invoke-ToolchainLoad -ErrorAction Stop } | Should -Throw
	}

	It 'Invoke-ToolchainPull uses config packages when none provided' {
		Invoke-ToolchainPull
		Should -Invoke -CommandName PullPackage -Times 2
	}

	It 'Invoke-ToolchainRemove removes each package' {
		Invoke-ToolchainRemove -Packages @('x','y')
		Should -Invoke -CommandName RemovePackage -Times 2
	}

	It 'Invoke-ToolchainExec resolves and executes script' {
		$r = Invoke-ToolchainExec -Packages @('x') -ScriptBlock { 'hello' }
		$r | Should -Be 'ran'
		Should -Invoke -CommandName ExecuteScript -Times 1 -Exactly -ParameterFilter { $Pkgs.Count -eq 1 -and $Pkgs[0].Package -eq 'x' }
	}

	It 'Invoke-ToolchainExec errors when no packages are available' {
		Mock GetConfigPackages { return $null }
		{ Invoke-ToolchainExec -ErrorAction Stop } | Should -Throw
	}
}

Describe 'Invoke-ToolchainRun' {
	It 'Runs a Toolchain function directly when no ToolchainPackages are configured' {
		$cfg = Join-Path $TestDrive 'Toolchain.ps1'
		Set-Content -LiteralPath $cfg -Value @'
function ToolchainHello { param([string]$Name='world') return "hi $Name" }
'@ -Encoding utf8
		Mock FindConfig { return $cfg }
		(Invoke-ToolchainRun -FnName 'Hello' -ArgumentList @('bob')) | Should -Be 'hi bob'
	}

	It 'Runs a Toolchain function inside Invoke-ToolchainExec when ToolchainPackages are configured' {
		$cfg = Join-Path $TestDrive 'Toolchain2.ps1'
		Set-Content -LiteralPath $cfg -Value @'
$ToolchainPackages = @('git')
function ToolchainHello { return 'ok' }
'@ -Encoding utf8
		Mock FindConfig { return $cfg }
		Mock Invoke-ToolchainExec { param([string[]]$Packages,[scriptblock]$ScriptBlock) & $ScriptBlock }
		(Invoke-ToolchainRun -FnName 'Hello') | Should -Be 'ok'
		Should -Invoke -CommandName Invoke-ToolchainExec -Times 1 -Exactly -ParameterFilter { $Packages[0] -eq 'git' }
	}

	It 'No-ops when the requested Toolchain function does not exist' {
		$cfg = Join-Path $TestDrive 'Toolchain3.ps1'
		Set-Content -LiteralPath $cfg -Value "# empty" -Encoding utf8
		Mock FindConfig { return $cfg }
		(Invoke-ToolchainRun -FnName 'Missing') | Should -Be $null
	}
}

Describe 'Invoke-ToolchainSave' {
	BeforeEach {
		Mock MakeDirIfNotExist { param($Path) New-Item -ItemType Directory -Path $Path -Force | Out-Null; return $Path }
		Mock AsPackage { param([Parameter(ValueFromPipeline)]$Ref) return [pscustomobject]@{ Package = [string]$Ref } }
		Mock PullPackage { param([Parameter(ValueFromPipeline)]$Pkg,[string]$Output,[switch]$Sign) return @{ package=$Pkg.Package; digest='sha256:x' } }
		Mock TryEachPackage {
			param($Packages, $ScriptBlock, $ActionDescription)
			$res=@()
			foreach($p in $Packages){ $res += ($p | & $ScriptBlock) }
			return $res
		}
		Mock GetRegistryBaseUrl { 'https://registry.example' }
		Mock GetRegistryRepoName { 'acme/toolchains' }
		Mock New-ToolchainFileCmsSignature { param($Path,$SignaturePath) return $SignaturePath }
	}

	It 'Errors when no output directory is provided' {
		{ Invoke-ToolchainSave -Packages @('a') -ErrorAction Stop } | Should -Throw
	}

	It 'Writes an index in offline mode' {
		$out = Join-Path $TestDrive 'offline'
		Mock GetToolchainRepo { return 'C:\offline' }
		Invoke-ToolchainSave -Packages @('a') -Output $out -Index
		$idx = Join-Path (Resolve-Path $out) 'toolchain.index.json'
		(Test-Path -LiteralPath $idx) | Should -Be $true
		$txt = Get-Content -LiteralPath $idx -Raw
		$txt | Should -Match '"registry"\s*:\s*"offline"'
	}

	It 'Writes an index in registry mode and signs when requested' {
		$out = Join-Path $TestDrive 'online'
		Mock GetToolchainRepo { return $null }
		Invoke-ToolchainSave -Packages @('a') -Output $out -Index -Sign
		$idx = Join-Path (Resolve-Path $out) 'toolchain.index.json'
		(Test-Path -LiteralPath $idx) | Should -Be $true
		Should -Invoke -CommandName New-ToolchainFileCmsSignature -Times 1 -Exactly
	}
}

Describe 'Invoke-ToolchainInit' {
	It 'Does not overwrite without -Force' {
		$cwd = Get-Location
		try {
			Set-Location $TestDrive
			$cfg = Join-Path (Get-Location).Path 'Toolchain.ps1'
			Set-Content -LiteralPath $cfg -Value 'x' -Encoding utf8
			Mock Write-ToolchainInfo { }
			Invoke-ToolchainInit
			(Get-Content -LiteralPath $cfg -Raw) | Should -Be 'x'
		} finally { Set-Location $cwd }
	}

	It 'Writes starter file with -Force' {
		$cwd = Get-Location
		try {
			Set-Location $TestDrive
			$cfg = Join-Path (Get-Location).Path 'Toolchain.ps1'
			Set-Content -LiteralPath $cfg -Value 'x' -Encoding utf8
			Mock Write-ToolchainInfo { }
			Invoke-ToolchainInit -Force
			(Get-Content -LiteralPath $cfg -Raw) | Should -Match 'ToolchainPackages'
		} finally { Set-Location $cwd }
	}
}

Describe 'Invoke-ToolchainDoctor' {
	BeforeEach {
		Mock Write-ToolchainInfo { }
		Mock Write-Error { }
		Mock GetToolchainPath { return (Join-Path $TestDrive 'tlc') }
		Mock MakeDirIfNotExist { param($Path) New-Item -ItemType Directory -Path $Path -Force | Out-Null; return $Path }
		Mock GetRegistryBaseUrl { 'https://registry.example' }
		Mock GetRegistryRepoName { 'acme/toolchains' }
	}

	It 'Reports ok for offline repo that exists' {
		$repo = Join-Path $TestDrive 'repo'
		New-Item -ItemType Directory -Path $repo -Force | Out-Null
		Mock GetToolchainRepo { return $repo }
		{ Invoke-ToolchainDoctor -Strict } | Should -Not -Throw
	}

	It 'Throws in strict mode for missing offline repo' {
		Mock GetToolchainRepo { return (Join-Path $TestDrive 'missing') }
		{ Invoke-ToolchainDoctor -Strict } | Should -Throw
	}

	It 'Checks registry when not in offline mode' {
		Mock GetToolchainRepo { return $null }
		Mock GetTagsList { return @{ tags = @('a','b') } }
		{ Invoke-ToolchainDoctor } | Should -Not -Throw
	}

	It 'Reports registry failure and throws in strict mode' {
		Mock GetToolchainRepo { return $null }
		Mock GetTagsList { throw 'offline' }
		{ Invoke-ToolchainDoctor -Strict } | Should -Throw
	}

	It 'Captures ToolchainPath write failures' {
		Mock MakeDirIfNotExist { throw 'no perms' }
		Mock GetToolchainRepo { return (Join-Path $TestDrive 'repo') }
		New-Item -ItemType Directory -Path (Join-Path $TestDrive 'repo') -Force | Out-Null
		{ Invoke-ToolchainDoctor -Strict } | Should -Throw
	}
}

Describe 'Invoke-ToolchainRemote' {
	It 'Lists tags from registry' {
		Mock GetDockerTags { return 123 }
		(Invoke-ToolchainRemote -Command list) | Should -Be 123
	}
}

Describe 'Invoke-ToolchainHelp' {
	It 'Returns usage text' {
		(Invoke-ToolchainHelp) | Should -Match 'Usage:'
	}
}

Describe 'CheckForUpdates' {
	It 'Swallows network errors' {
		Mock HttpSend { throw 'offline' }
		{ CheckForUpdates } | Should -Not -Throw
	}

	It 'No-ops when no redirect location is present' {
		Mock HttpRequest { return [Net.Http.HttpRequestMessage]::new() }
		Mock HttpSend { return [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::OK) }
		Mock Import-PowerShellDataFile { return @{ ModuleVersion='1.0.0' } }
		{ CheckForUpdates } | Should -Not -Throw
	}

	It 'Writes message when a newer version is available' {
		Mock Import-PowerShellDataFile { return @{ ModuleVersion='1.2.3' } }
		Mock HttpRequest { return [Net.Http.HttpRequestMessage]::new() }
		Mock HttpSend {
			$resp = [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::OK)
			$resp.Headers.Add('Location', '/packages/toolchain/1.2.4')
			return $resp
		}
		Mock Write-ToolchainInfo { }
		CheckForUpdates
		Should -Invoke -CommandName Write-ToolchainInfo -Times 2 -Exactly
	}

	It 'No-ops when local version is newer/equal' {
		Mock Import-PowerShellDataFile { return @{ ModuleVersion='9.9.9' } }
		Mock HttpRequest { return [Net.Http.HttpRequestMessage]::new() }
		Mock HttpSend {
			$resp = [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::OK)
			$resp.Headers.Add('Location', '/packages/toolchain/1.2.4')
			return $resp
		}
		Mock Write-ToolchainInfo { }
		CheckForUpdates
		Should -Invoke -CommandName Write-ToolchainInfo -Times 0 -Exactly
	}
}

Describe 'Invoke-ToolchainModuleEntry' {
	BeforeEach {
		Remove-Item Env:TOOLCHAIN_RUN_MODULE_ENTRY -ErrorAction Ignore
	}

	It 'Returns false when not module entry and not forced' {
		Mock CheckForUpdates { throw 'no' }
		Mock PrunePackages { throw 'no' }
		(Invoke-ToolchainModuleEntry) | Should -Be $false
	}

	It 'Runs CheckForUpdates/PrunePackages when forced' {
		Mock CheckForUpdates { }
		Mock PrunePackages { }
		(Invoke-ToolchainModuleEntry -Force) | Should -Be $true
		Should -Invoke -CommandName CheckForUpdates -Times 1 -Exactly
		Should -Invoke -CommandName PrunePackages -Times 1 -Exactly
	}

	It 'Runs when env var is set' {
		$env:TOOLCHAIN_RUN_MODULE_ENTRY = 'true'
		Mock CheckForUpdates { }
		Mock PrunePackages { }
		(Invoke-ToolchainModuleEntry) | Should -Be $true
	}
}
