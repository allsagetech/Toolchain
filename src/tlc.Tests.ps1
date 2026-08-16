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

	It 'Parses explicit switch values' {
		$params, $remaining = ResolveParameters 'Invoke-ToolchainSave' @('-Output:out','-Sign:false','-Index:$true','pkg1')
		$params.Output | Should -Be 'out'
		$params.Sign | Should -Be $false
		$params.Index | Should -Be $true
		@($remaining) | Should -Be @('pkg1')
	}

	It 'Rejects invalid switch values' {
		{ ResolveParameters 'Invoke-ToolchainSave' @('-Output:out','-Sign:maybe') } | Should -Throw '*invalid switch value for -Sign*'
	}

	It 'Rejects missing parameter values' {
		{ ResolveParameters 'Invoke-ToolchainSave' @('-Output') } | Should -Throw '*missing value for -Output*'
		{ ResolveParameters 'Invoke-ToolchainSave' @('-Output','-Sign') } | Should -Throw '*missing value for -Output*'
	}
}

Describe 'Invoke-Toolchain dispatcher' {
	BeforeEach {
		Mock Invoke-ToolchainVersion { '1.0.0' }
		Mock Invoke-ToolchainList { 'list' }
		Mock Invoke-ToolchainRemote { param($Command,$Package) if ($Package) { "remote:$Command`:$Package" } else { "remote:$Command" } }
		Mock Invoke-ToolchainLoad { param([string[]]$Packages) $Packages }
		Mock Invoke-ToolchainPull { param([string[]]$Packages) $Packages }
		Mock Invoke-ToolchainPrune { 'prune' }
		Mock Invoke-ToolchainUpdate { 'update' }
		Mock Invoke-ToolchainRemove { param([string[]]$Packages) $Packages }
		Mock Invoke-ToolchainSave { 'save' }
		Mock Invoke-ToolchainExec { param([string[]]$Packages,[scriptblock]$ScriptBlock) @($Packages).Count }
		Mock Invoke-ToolchainRun { param([string]$FnName,[object[]]$ArgumentList) @($FnName) + @($ArgumentList) }
		Mock Invoke-ToolchainInit { 'init' }
		Mock Invoke-ToolchainLock { param([string[]]$Packages,[string[]]$Update) if ($Update) { @($Update) } elseif ($Packages) { @($Packages) } else { 'lock' } }
		Mock Invoke-ToolchainRestore { 'restore' }
		Mock Invoke-ToolchainVerify { param([string[]]$Packages) @($Packages) }
		Mock Invoke-ToolchainProfile { param($Command,[string[]]$Packages) @($Command) + @($Packages) }
		Mock Invoke-ToolchainCluster { param($Command,$Name,$Provider) @($Command,$Name,$Provider) }
		Mock Invoke-ToolchainK9s { param($Cluster,$Kubeconfig,[object[]]$ArgumentList) [pscustomobject]@{ Cluster = $Cluster; Kubeconfig = $Kubeconfig; Arguments = @($ArgumentList) } }
		Mock Invoke-ToolchainDoctor { 'doctor' }
		Mock Invoke-ToolchainHelp { param([string[]]$CommandPath) if ($CommandPath) { "help:$($CommandPath -join ' ')" } else { 'help' } }
	}

	It 'Routes version commands' {
		(Invoke-Toolchain -Command version) | Should -Be '1.0.0'
		(Invoke-Toolchain -Command v) | Should -Be '1.0.0'
	}

	It 'Routes remote catalog commands' {
		(Invoke-Toolchain -Command remote -ArgumentList @('list')) | Should -Be 'remote:list'
		(Invoke-Toolchain -Command remote -ArgumentList @('list','node')) | Should -Be 'remote:list:node'
		(Invoke-Toolchain -Command remote -ArgumentList @('models')) | Should -Be 'remote:models'
		(Invoke-Toolchain -Command remote -ArgumentList @('all')) | Should -Be 'remote:all'
		(Invoke-Toolchain -Command remote -ArgumentList @('tags')) | Should -Be 'remote:tags'
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

	It 'Writes an error when run is missing a function name' {
		Mock Write-Error { }
		$r = Invoke-Toolchain -Command run -ArgumentList @()
		$r | Should -Be $null
		Should -Invoke -CommandName Invoke-ToolchainRun -Times 0 -Exactly
		Should -Invoke -CommandName Write-Error -Times 1 -Exactly -ParameterFilter { $Message -match 'run requires a function name' }
	}

	It 'Routes other commands' {
		(Invoke-Toolchain -Command prune) | Should -Be 'prune'
		(Invoke-Toolchain -Command update) | Should -Be 'update'
		(Invoke-Toolchain -Command save -ArgumentList @('-Output','out')) | Should -Be 'save'
		(Invoke-Toolchain -Command init) | Should -Be 'init'
		(Invoke-Toolchain -Command lock) | Should -Be 'lock'
		@(Invoke-Toolchain -Command lock -ArgumentList @('node','git')) | Should -Be @('node','git')
		@(Invoke-Toolchain -Command lock -ArgumentList @('-Update','node','git')) | Should -Be @('node','git')
		(Invoke-Toolchain -Command restore) | Should -Be 'restore'
		@(Invoke-Toolchain -Command verify -ArgumentList @('node','git')) | Should -Be @('node','git')
		@(Invoke-Toolchain -Command profile -ArgumentList @('add','node','git')) | Should -Be @('add','node','git')
		@(Invoke-Toolchain -Command cluster -ArgumentList @('create','dev','-Provider','kind')) | Should -Be @('create','dev','kind')
		$k9s = Invoke-Toolchain -Command k9s -ArgumentList @('-Cluster','dev','-n','default')
		$k9s.Cluster | Should -Be 'dev'
		$k9s.Kubeconfig | Should -BeNullOrEmpty
		$k9s.Arguments | Should -Be @('-n','default')
		$k9s = Invoke-Toolchain -Command k9s -ArgumentList @('--readonly','-A')
		$k9s.Arguments | Should -Be @('--readonly','-A')
		(Invoke-Toolchain -Command doctor) | Should -Be 'doctor'
		(Invoke-Toolchain -Command help) | Should -Be 'help'
		(Invoke-Toolchain -Command h) | Should -Be 'help'
	}

	It 'Writes an error when a command throws' {
		Mock Invoke-ToolchainList { throw 'boom' }
		{ Invoke-Toolchain -Command list -ErrorAction SilentlyContinue } | Should -Not -Throw
	}

	It 'routes suffix help for every top-level command without executing it' {
		$commands = @('version','v','remote','list','load','pull','exec','run','remove','rm','save','prune','update','init','lock','restore','verify','profile','cluster','k9s','doctor')
		foreach ($command in $commands) {
			$expected = switch ($command) { 'v' { 'version' }; 'rm' { 'remove' }; default { $command } }
			(Invoke-Toolchain -Command $command -ArgumentList @('help')) | Should -Be "help:$expected"
		}
		Should -Invoke -CommandName Invoke-ToolchainVersion -Times 0 -Exactly
		Should -Invoke -CommandName Invoke-ToolchainList -Times 0 -Exactly
		Should -Invoke -CommandName Invoke-ToolchainRemote -Times 0 -Exactly
		Should -Invoke -CommandName Invoke-ToolchainCluster -Times 0 -Exactly
	}

	It 'routes nested and prefix help without executing command handlers' {
		(Invoke-Toolchain -Command remote -ArgumentList @('list','help')) | Should -Be 'help:remote list'
		(Invoke-Toolchain -Command profile -ArgumentList @('add','--help')) | Should -Be 'help:profile add'
		(Invoke-Toolchain -Command cluster -ArgumentList @('create','-h')) | Should -Be 'help:cluster create'
		(Invoke-Toolchain -Command help -ArgumentList @('cluster','kubeconfig')) | Should -Be 'help:cluster kubeconfig'
		Should -Invoke -CommandName Invoke-ToolchainRemote -Times 0 -Exactly
		Should -Invoke -CommandName Invoke-ToolchainProfile -Times 0 -Exactly
		Should -Invoke -CommandName Invoke-ToolchainCluster -Times 0 -Exactly
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
		Mock ResolvePackage { param([Parameter(ValueFromPipeline)][string]$Ref) return @{ Package = [string]$Ref } }
		Mock LoadPackage { param([Parameter(ValueFromPipeline)][Collections.Hashtable]$Pkg) return $Pkg }
		Mock AsPackage { param([Parameter(ValueFromPipeline)][string]$Pkg) return @{ Package = [string]$Pkg } }
		Mock PullPackage { param([Parameter(ValueFromPipeline)][Collections.Hashtable]$Pkg) return @{ Package=$Pkg.Package; Digest='sha256:x' } }
		Mock RemovePackage { param([Parameter(ValueFromPipeline)][Collections.Hashtable]$Pkg) return $Pkg }
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
		Should -Invoke -CommandName UpdatePackages -Times 0 -Exactly
		Should -Invoke -CommandName TryEachPackage -Times 0 -Exactly
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
		Should -Invoke -CommandName UpdatePackages -Times 0 -Exactly
		Should -Invoke -CommandName TryEachPackage -Times 0 -Exactly
		Should -Invoke -CommandName ExecuteScript -Times 0 -Exactly
	}

	It 'Invoke-ToolchainPull errors when no packages are available' {
		Mock GetConfigPackages { return $null }
		{ Invoke-ToolchainPull -ErrorAction Stop } | Should -Throw
		Should -Invoke -CommandName TryEachPackage -Times 0 -Exactly
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

	It 'Writes an error when the requested Toolchain function does not exist' {
		$cfg = Join-Path $TestDrive 'Toolchain3.ps1'
		Set-Content -LiteralPath $cfg -Value "# empty" -Encoding utf8
		Mock FindConfig { return $cfg }
		Mock Write-Error { }
		(Invoke-ToolchainRun -FnName 'Missing') | Should -Be $null
		Should -Invoke -CommandName Write-Error -Times 1 -Exactly -ParameterFilter { $Message -match "ToolchainMissing" }
	}

	It 'Writes an error when Toolchain.ps1 cannot be found' {
		Mock FindConfig { return $null }
		Mock Write-Error { }
		(Invoke-ToolchainRun -FnName 'Build') | Should -Be $null
		Should -Invoke -CommandName Write-Error -Times 1 -Exactly -ParameterFilter { $Message -match 'Toolchain\.ps1 not found' }
	}

	It 'Writes an error when FnName is empty' {
		Mock Write-Error { }
		(Invoke-ToolchainRun -FnName '') | Should -Be $null
		Should -Invoke -CommandName Write-Error -Times 1 -Exactly -ParameterFilter { $Message -match 'function name is required' }
	}
}

Describe 'Invoke-ToolchainSave' {
	BeforeEach {
		Mock MakeDirIfNotExist { param($Path) New-Item -ItemType Directory -Path $Path -Force | Out-Null; return $Path }
		Mock AsPackage { param([Parameter(ValueFromPipeline)][string]$Pkg) return @{ Package = [string]$Pkg } }
		Mock PullPackage { param([Parameter(ValueFromPipeline)][Collections.Hashtable]$Pkg,[string]$Output,[switch]$Sign) return @{ package=$Pkg.Package; digest='sha256:x' } }
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
		Should -Invoke -CommandName MakeDirIfNotExist -Times 0 -Exactly
		Should -Invoke -CommandName TryEachPackage -Times 0 -Exactly
	}

	It 'Errors when no packages are available and does not continue' {
		Mock GetConfigPackages { return $null }
		$out = Join-Path $TestDrive 'no-pkgs'
		{ Invoke-ToolchainSave -Output $out -ErrorAction Stop } | Should -Throw
		Should -Invoke -CommandName MakeDirIfNotExist -Times 0 -Exactly
		Should -Invoke -CommandName TryEachPackage -Times 0 -Exactly
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
			((Get-Content -LiteralPath $cfg -Raw).TrimEnd("`r","`n")) | Should -Be 'x'
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

	It 'Returns structured diagnostics for automation' {
		Mock GetToolchainRepo { return $null }
		Mock GetTagsList { return @{ tags = @('a','b') } }
		$result = Invoke-ToolchainDoctor -PassThru
		$result.PSTypeNames | Should -Contain 'Toolchain.DoctorResult'
		$result.Healthy | Should -BeTrue
		$result.TagCount | Should -Be 2
		(Invoke-ToolchainDoctor -Json | ConvertFrom-Json).Healthy | Should -BeTrue
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
	It 'Routes package views to their catalog kinds' {
		Mock GetDockerTags { param($Kind, [switch]$ToolingDefaultDisplay, [switch]$Refresh) return "$Kind`:$([bool]$ToolingDefaultDisplay):$([bool]$Refresh)" }
		(Invoke-ToolchainRemote -Command list) | Should -Be 'All:True:False'
		(Invoke-ToolchainRemote -Command models) | Should -Be 'Model:False:False'
		(Invoke-ToolchainRemote -Command all -Refresh) | Should -Be 'All:False:True'
	}

	It 'Returns normalized versions for one package' {
		Mock GetDockerTags {
			return [pscustomobject]@{
				node = @([Tag]::new('22.3.1'), [Tag]::new('20.1.0'))
			}
		}
		@(Invoke-ToolchainRemote -Command list -Package Node) | Should -Be @('22.3.1','20.1.0')
		Should -Invoke GetDockerTags -Times 1 -Exactly -ParameterFilter { $Kind -eq 'Tooling' -and -not $ToolingDefaultDisplay }
	}

	It 'Returns package versions as a JSON array' {
		Mock GetDockerTags { return [pscustomobject]@{ node = @([Tag]::new('22.3.1')) } }
		$json = Invoke-ToolchainRemote -Command all -Package node -Json | ConvertFrom-Json
		@($json) | Should -Be @('22.3.1')
	}

	It 'Rejects unknown packages and package filters on raw tags' {
		Mock GetDockerTags { return [pscustomobject]@{ node = @([Tag]::new('22.3.1')) } }
		{ Invoke-ToolchainRemote -Command list -Package missing } | Should -Throw "*remote package not found in 'list' catalog*"
		{ Invoke-ToolchainRemote -Command tags -Package node } | Should -Throw '*remote tags does not accept a package name*'
	}

	It 'Supports JSON output' {
		Mock GetDockerTags { return [pscustomobject]@{ package = @('1.0.0') } }
		$result = Invoke-ToolchainRemote -Command all -Json | ConvertFrom-Json
		$result.package | Should -Contain '1.0.0'
	}

	It 'Exposes raw registry tags only through the diagnostic command' {
		Mock GetRemoteRegistryTags { return @('package-1.0.0', 'sha256-digest.sig') }
		@(Invoke-ToolchainRemote -Command tags) | Should -Be @('package-1.0.0', 'sha256-digest.sig')
	}

	It 'routes health and package info views' {
		Mock Get-ToolchainPackageHealth { param($Package, [switch]$OnlyProblems, [switch]$Refresh) "$Package`:$([bool]$OnlyProblems):$([bool]$Refresh)" }
		(Invoke-ToolchainRemote -Command health -OnlyProblems -Refresh) | Should -Be ':True:True'
		(Invoke-ToolchainRemote -Command info -Package node) | Should -Be 'node:False:False'
		{ Invoke-ToolchainRemote -Command info } | Should -Throw '*requires a package name*'
	}
}

Describe 'Invoke-ToolchainHelp' {
	It 'Returns usage text' {
		(Invoke-ToolchainHelp) | Should -Match 'Usage:'
		(Invoke-ToolchainHelp) | Should -Match 'cluster'
		(Invoke-ToolchainHelp -CommandPath @('remote')) | Should -Match 'remote models'
		(Invoke-ToolchainHelp -CommandPath @('remote')) | Should -Match 'remote tags'
	}
}

Describe 'CheckForUpdates' {
	BeforeEach {
		Mock Set-ToolchainUpdateCheckTime { }
	}

	It 'Swallows network errors' {
		Mock HttpSend { throw 'offline' }
		{ CheckForUpdates -Force } | Should -Not -Throw
	}

	It 'No-ops when no redirect location is present' {
		Mock HttpRequest { return [Net.Http.HttpRequestMessage]::new() }
		Mock HttpSend { return [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::OK) }
		Mock Import-PowerShellDataFile { return @{ ModuleVersion='1.0.0' } }
		{ CheckForUpdates -Force } | Should -Not -Throw
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
		CheckForUpdates -Force
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
		CheckForUpdates -Force
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

	It 'Defers CheckForUpdates and runs pruning when forced' {
		Mock Request-ToolchainDeferredUpdateCheck { }
		Mock PrunePackages { }
		(Invoke-ToolchainModuleEntry -Force) | Should -Be $true
		Should -Invoke -CommandName Request-ToolchainDeferredUpdateCheck -Times 1 -Exactly
		Should -Invoke -CommandName PrunePackages -Times 1 -Exactly
	}

	It 'Runs when env var is set' {
		$env:TOOLCHAIN_RUN_MODULE_ENTRY = 'true'
		Mock Request-ToolchainDeferredUpdateCheck { }
		Mock PrunePackages { }
		(Invoke-ToolchainModuleEntry) | Should -Be $true
	}
}
