<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

BeforeAll {
	. (Join-Path $PSScriptRoot 'tlc.ps1')
}

Describe 'Toolchain-managed PowerShell shell launcher' {
	It 'locates the active Toolchain module manifest' {
		$moduleRoot = Join-Path $TestDrive 'module'
		[void][IO.Directory]::CreateDirectory($moduleRoot)
		$modulePath = Join-Path $moduleRoot 'Toolchain.psm1'
		$manifestPath = Join-Path $moduleRoot 'Toolchain.psd1'
		[IO.File]::WriteAllText($modulePath, '')
		[IO.File]::WriteAllText($manifestPath, '@{}')
		Mock Get-Module { [pscustomobject]@{ Path = $modulePath } }

		Get-ToolchainShellModuleManifestPath | Should -Be ([IO.Path]::GetFullPath($manifestPath))
	}

	It 'locates the manifest through the active Toolchain command when module enumeration is unavailable' {
		$moduleRoot = Join-Path $TestDrive 'command-module'
		[void][IO.Directory]::CreateDirectory($moduleRoot)
		$modulePath = Join-Path $moduleRoot 'Toolchain.psm1'
		$manifestPath = Join-Path $moduleRoot 'Toolchain.psd1'
		[IO.File]::WriteAllText($modulePath, '')
		[IO.File]::WriteAllText($manifestPath, '@{}')
		Mock Get-Module { @() }
		Mock Get-Command { [pscustomobject]@{ Module = [pscustomobject]@{ Path = $modulePath } } }

		Get-ToolchainShellModuleManifestPath | Should -Be ([IO.Path]::GetFullPath($manifestPath))
	}

	It 'fails clearly when the active Toolchain module manifest cannot be found' {
		Mock Get-Module { @() }
		Mock Get-Command { $null }

		{ Get-ToolchainShellModuleManifestPath } | Should -Throw '*could not locate the active Toolchain module manifest*'
	}

	It 'resolves exactly one pwsh executable from the managed package content' {
		$packageRoot = Join-Path $TestDrive 'powershell'
		[void][IO.Directory]::CreateDirectory($packageRoot)
		$executable = Join-Path $packageRoot 'pwsh.exe'
		[IO.File]::WriteAllText($executable, '')
		Mock ResolvePackageDigest { 'sha256:' + ('a' * 64) }
		Mock ResolvePackagePath { $packageRoot }

		Get-ToolchainManagedPowerShellExecutable -Package @{ Package = 'powershell' } |
			Should -Be ([IO.Path]::GetFullPath($executable))
	}

	It 'rejects unavailable and ambiguous managed PowerShell executables' {
		$emptyRoot = Join-Path $TestDrive 'empty'
		[void][IO.Directory]::CreateDirectory($emptyRoot)
		Mock ResolvePackageDigest { $null }
		{ Get-ToolchainManagedPowerShellExecutable -Package @{ Package = 'powershell' } } |
			Should -Throw '*not available locally*'

		$firstRoot = Join-Path $TestDrive 'first'
		$secondRoot = Join-Path $TestDrive 'second'
		[void][IO.Directory]::CreateDirectory($firstRoot)
		[void][IO.Directory]::CreateDirectory($secondRoot)
		[IO.File]::WriteAllText((Join-Path $firstRoot 'pwsh.exe'), '')
		[IO.File]::WriteAllText((Join-Path $secondRoot 'pwsh.exe'), '')
		Mock ResolvePackageDigest { 'sha256:' + ('c' * 64) }
		Mock ResolvePackagePath { $TestDrive }
		{ Get-ToolchainManagedPowerShellExecutable -Package @{ Package = 'powershell' } } |
			Should -Throw '*exactly one pwsh.exe*'
	}

	It 'propagates managed PowerShell exit failures' -Skip:(-not (Test-Path -LiteralPath (Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'))) {
		$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
		$successSource = Join-Path $TestDrive 'success.cs'
		$failureSource = Join-Path $TestDrive 'failure.cs'
		$successExecutable = Join-Path $TestDrive 'success.exe'
		$failureExecutable = Join-Path $TestDrive 'failure.exe'
		[IO.File]::WriteAllText($successSource, 'public static class Program { public static int Main(string[] args) { return 0; } }')
		[IO.File]::WriteAllText($failureSource, 'public static class Program { public static int Main(string[] args) { return 23; } }')
		& $compiler /nologo "/out:$successExecutable" $successSource | Out-Null
		if ($LASTEXITCODE -ne 0) { throw 'could not compile the successful PowerShell launcher test executable' }
		& $compiler /nologo "/out:$failureExecutable" $failureSource | Out-Null
		if ($LASTEXITCODE -ne 0) { throw 'could not compile the failing PowerShell launcher test executable' }

		Start-ToolchainManagedPowerShell -Executable $successExecutable -ModuleManifestPath 'C:\toolchain\Toolchain.psd1'
		{ Start-ToolchainManagedPowerShell -Executable $failureExecutable -ModuleManifestPath 'C:\toolchain\Toolchain.psd1' } |
			Should -Throw '*exited with code 23*'
	}

	It 'resolves the PowerShell package, launches its pwsh, and leaves persistent settings unchanged' {
		$package = @{ Package = 'powershell'; Tag = @{ Latest = $true }; Config = 'default'; Digest = 'sha256:' + ('b' * 64) }
		Mock UpdatePackages { }
		Mock TryEachPackage { @($package) }
		Mock Get-ToolchainManagedPowerShellExecutable { 'C:\toolchain\powershell\pwsh.exe' }
		Mock Get-ToolchainShellModuleManifestPath { 'C:\toolchain\module\Toolchain.psd1' }
		Mock Start-ToolchainManagedPowerShell { }
		Mock ExecuteScript {
			param([scriptblock]$ScriptBlock,[Collections.Hashtable[]]$Pkgs,[object[]]$ArgumentList)
			& $ScriptBlock @ArgumentList
		}

		Invoke-ToolchainShell -Command pwsh

		Should -Invoke UpdatePackages -Times 1 -Exactly -ParameterFilter { $Auto -and @($Packages) -eq @('powershell') }
		Should -Invoke Get-ToolchainManagedPowerShellExecutable -Times 1 -Exactly -ParameterFilter { $Package.Package -eq 'powershell' }
		Should -Invoke ExecuteScript -Times 1 -Exactly -ParameterFilter { @($Pkgs).Count -eq 1 -and $Pkgs[0].Package -eq 'powershell' }
		Should -Invoke Start-ToolchainManagedPowerShell -Times 1 -Exactly -ParameterFilter {
			$Executable -eq 'C:\toolchain\powershell\pwsh.exe' -and $ModuleManifestPath -eq 'C:\toolchain\module\Toolchain.psd1'
		}
	}

	It 'fails before launching when the PowerShell package cannot be resolved' {
		Mock UpdatePackages { }
		Mock TryEachPackage { @() }

		{ Invoke-ToolchainShell -Command pwsh } | Should -Throw '*could not resolve the Toolchain PowerShell package*'
	}
}
