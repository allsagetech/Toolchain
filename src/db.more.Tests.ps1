<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

BeforeAll {
	. "$PSScriptRoot\db.ps1"
	$script:root = (Resolve-Path "$PSScriptRoot\..\test").Path
}

Describe 'Db extra coverage' {
	BeforeAll {
		$script:ToolchainPath = "$root\toolchain"
	}
	BeforeEach { [Db]::Init() }
	AfterEach {
		[IO.Directory]::Delete("\\?\$ToolchainPath", $true)
	}

	It 'ContainsKey and Remove work' {
		$k = 'k1','k2'
		[Db]::Put($k, 123)
		[Db]::ContainsKey($k) | Should -BeTrue
		[Db]::Remove($k)
		[Db]::ContainsKey($k) | Should -BeFalse
		$got, $err = [Db]::TryGet($k)
		$got | Should -Be $null
		$err | Should -Not -Be $null
	}

	It 'Key/DecodeKey and HasPrefix cover both true and false' {
		$key = 'a','b','c'
		$b64 = [Db]::Key($key)
		([Db]::DecodeKey($b64) -join ',') | Should -Be ($key -join ',')
		[Db]::HasPrefix($b64, @('a','b')) | Should -BeTrue
		[Db]::HasPrefix($b64, @('a','x')) | Should -BeFalse
	}

	It 'FileLock Put/Get/Unlock writes, Revert does not, Remove deletes' {
		$k = 'filelock'
		[Db]::Put($k, 'old')

		$lk = [Db]::Lock($k)
		$lk.Get() | Should -Be 'old'
		$lk.Put('new')
		$lk.Revert()
		[Db]::Get($k) | Should -Be 'old'

		$lk2 = [Db]::Lock($k)
		$lk2.Put('new')
		$lk2.Unlock()
		[Db]::Get($k) | Should -Be 'new'

		$lk3 = [Db]::Lock($k)
		$lk3.Remove()
		$lk3.Unlock()
		[Db]::ContainsKey($k) | Should -BeFalse
	}

	It 'TryLockAll returns a helpful error and reverts previous locks' {
		[Db]::Put(@('x','1'), 1)
		[Db]::Put(@('x','2'), 2)

		$hold = [Db]::Lock(@('x','2'))
		try {
			$locks, $err = [Db]::TryLockAll(@('x'))
			$locks | Should -Be $null
			$err | Should -Match 'being used by another toolchain process'
			$lk, $e2 = [Db]::TryLock(@('x','1'))
			$e2 | Should -BeNullOrEmpty
			if ($lk) { $lk.Unlock() }
		} finally {
			$hold.Unlock()
		}
	}
}
