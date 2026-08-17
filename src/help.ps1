<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

function New-ToolchainHelpTopic {
	param(
		[Parameter(Mandatory)][string]$Description,
		[Parameter(Mandatory)][string[]]$Usage,
		[string[]]$Commands = @(),
		[string[]]$Options = @(),
		[string[]]$Examples = @(),
		[string[]]$Notes = @()
	)
	return [pscustomobject]@{
		Description = $Description
		Usage = @($Usage)
		Commands = @($Commands)
		Options = @($Options)
		Examples = @($Examples)
		Notes = @($Notes)
	}
}

function Get-ToolchainHelpTopics {
	$topics = [ordered]@{}

	$topics.version = New-ToolchainHelpTopic `
		-Description 'Displays the installed Toolchain module version.' `
		-Usage @('tlc version', 'tlc v') `
		-Examples @('tlc version')
	$topics.list = New-ToolchainHelpTopic `
		-Description 'Lists packages installed in the local Toolchain store.' `
		-Usage @('tlc list') `
		-Examples @('tlc list', "tlc list | Where-Object Package -eq 'git'")
	$topics.remote = New-ToolchainHelpTopic `
		-Description 'Lists installable packages or raw tags from the configured remote registry.' `
		-Usage @('tlc remote COMMAND [OPTIONS]', 'tlc remote COMMAND help') `
		-Commands @(
			'list      List ordinary tooling packages or one package''s versions.',
			'models    List AI model packages or one package''s versions.',
			'all       List all packages or one package''s versions.',
			'health    Show package availability and security health.',
			'info      Show detailed health for one package.',
			'tags      List raw registry tags for diagnostics.'
		) `
		-Examples @('tlc remote list', 'tlc remote list node', 'tlc remote models', 'tlc remote tags help')
	$topics.'remote list' = New-ToolchainHelpTopic `
		-Description 'Lists ordinary tooling packages and their available versions.' `
		-Usage @('tlc remote list [PACKAGE] [-Refresh] [-Json]') `
		-Options @('PACKAGE     Return only this tooling package''s versions.', '-Refresh    Bypass the local catalog cache.', '-Json       Emit JSON instead of PowerShell objects.') `
		-Examples @('tlc remote list', 'tlc remote list node', 'tlc remote list node -Json', 'tlc remote list -Refresh')
	$topics.'remote models' = New-ToolchainHelpTopic `
		-Description 'Lists AI model packages and their available versions.' `
		-Usage @('tlc remote models [PACKAGE] [-Refresh] [-Json]') `
		-Options @('PACKAGE     Return only this model package''s versions.', '-Refresh    Bypass the local catalog cache.', '-Json       Emit JSON instead of PowerShell objects.') `
		-Examples @('tlc remote models', 'tlc remote models qwen3-0.6b', 'tlc remote models -Json')
	$topics.'remote all' = New-ToolchainHelpTopic `
		-Description 'Lists every installable tooling and AI model package.' `
		-Usage @('tlc remote all [PACKAGE] [-Refresh] [-Json]') `
		-Options @('PACKAGE     Return only this package''s versions.', '-Refresh    Bypass the local catalog cache.', '-Json       Emit JSON instead of PowerShell objects.') `
		-Examples @('tlc remote all', 'tlc remote all node', 'tlc remote all -Refresh -Json')
	$topics.'remote tags' = New-ToolchainHelpTopic `
		-Description 'Lists raw registry tags, including signature, marker, and staging metadata.' `
		-Usage @('tlc remote tags [-Refresh] [-Json]') `
		-Options @('-Refresh    Bypass the local registry-tag cache.', '-Json       Emit JSON instead of PowerShell objects.') `
		-Examples @('tlc remote tags', 'tlc remote tags -Refresh') `
		-Notes @('Use remote list, models, or all for installable package views.')
	$topics.'remote health' = New-ToolchainHelpTopic `
		-Description 'Shows the signed package availability and security-health catalog.' `
		-Usage @('tlc remote health [PACKAGE] [-OnlyProblems] [-Refresh] [-Json]') `
		-Options @('PACKAGE          Return only one package.', '-OnlyProblems    Show only unavailable, quarantined, or scan-blocked packages.', '-Refresh         Bypass cached registry data.', '-Json            Emit JSON.') `
		-Examples @('tlc remote health', 'tlc remote health -OnlyProblems', 'tlc remote health k9s -Json')
	$topics.'remote info' = New-ToolchainHelpTopic `
		-Description 'Shows versions, platforms, provenance location, and health for one package.' `
		-Usage @('tlc remote info PACKAGE [-Refresh] [-Json]') `
		-Examples @('tlc remote info kubectl', 'tlc remote info k9s -Refresh')
	$topics.pull = New-ToolchainHelpTopic `
		-Description 'Downloads package content into the local Toolchain store.' `
		-Usage @('tlc pull [PACKAGE[:TAG] ...]') `
		-Examples @('tlc pull node', 'tlc pull git:latest node:20') `
		-Notes @('When no package is supplied, Toolchain uses the nearest toolchain.yaml or legacy Toolchain.ps1 project.')
	$topics.load = New-ToolchainHelpTopic `
		-Description 'Loads packages into the current PowerShell session.' `
		-Usage @('tlc load [PACKAGE[:TAG] ...]') `
		-Examples @('tlc load node', 'tlc load git:latest go') `
		-Notes @('When no package is supplied, Toolchain uses the nearest toolchain.yaml or legacy Toolchain.ps1 project.')
	$topics.exec = New-ToolchainHelpTopic `
		-Description 'Runs a PowerShell script block with one or more Toolchain packages loaded.' `
		-Usage @('tlc exec [PACKAGE[:TAG] ...] [SCRIPTBLOCK]') `
		-Examples @("tlc exec go { go version }", "tlc exec node { node --version }") `
		-Notes @('When no script block is supplied, Toolchain opens a nested PowerShell prompt.', 'When no package is supplied, Toolchain uses the nearest project configuration.')
	$topics.run = New-ToolchainHelpTopic `
		-Description 'Runs a Toolchain<Name> function defined in the nearest Toolchain.ps1 project file.' `
		-Usage @('tlc run FUNCTION [ARGUMENT ...]') `
		-Examples @('tlc run build', 'tlc run test -Configuration Release') `
		-Notes @('For example, tlc run build invokes a function named ToolchainBuild.')
	$topics.update = New-ToolchainHelpTopic `
		-Description 'Updates locally tagged packages to their current remote versions.' `
		-Usage @('tlc update') `
		-Examples @('tlc update')
	$topics.prune = New-ToolchainHelpTopic `
		-Description 'Deletes local package content that is no longer referenced by a tag.' `
		-Usage @('tlc prune') `
		-Examples @('tlc prune')
	$topics.remove = New-ToolchainHelpTopic `
		-Description 'Removes local package tags and deletes package content when it is no longer referenced.' `
		-Usage @('tlc remove PACKAGE[:TAG] ...', 'tlc rm PACKAGE[:TAG] ...') `
		-Examples @('tlc remove node', 'tlc rm git:latest')
	$topics.save = New-ToolchainHelpTopic `
		-Description 'Downloads packages into an offline repository directory.' `
		-Usage @('tlc save -Output PATH [-Sign] [-Index] [PACKAGE[:TAG] ...]') `
		-Options @(
			'-Output PATH    Destination directory for the offline package files.',
			'-Sign           Create package signatures.',
			'-Index          Write toolchain.index.json for the saved repository.'
		) `
		-Examples @('tlc save -Output .\toolchain-cache node git', 'tlc save -Output .\toolchain-cache -Sign -Index node') `
		-Notes @('When no package is supplied, Toolchain uses the nearest toolchain.yaml or legacy Toolchain.ps1 project.')
	$topics.init = New-ToolchainHelpTopic `
		-Description 'Writes a starter declarative toolchain.yaml project manifest.' `
		-Usage @('tlc init [-Force] [-Legacy]') `
		-Options @('-Force     Replace an existing destination file.', '-Legacy    Write the legacy executable Toolchain.ps1 format instead.') `
		-Examples @('tlc init', 'tlc init -Force', 'tlc init -Legacy')
	$topics.lock = New-ToolchainHelpTopic `
		-Description 'Resolves project packages to exact platform manifest digests and writes Toolchain.lock.json.' `
		-Usage @('tlc lock [PACKAGE...] [-Path PATH]', 'tlc lock -Update PACKAGE [PACKAGE...] [-Path PATH]') `
		-Examples @('tlc lock', 'tlc lock -Update node', 'tlc lock -Path .\ci\Toolchain.lock.json')
	$topics.restore = New-ToolchainHelpTopic `
		-Description 'Restores every package from the exact digests in Toolchain.lock.json.' `
		-Usage @('tlc restore [-Path PATH]') `
		-Examples @('tlc restore', 'tlc restore -Path .\ci\Toolchain.lock.json')
	$topics.sync = New-ToolchainHelpTopic `
		-Description 'Converges the project manifest, lock file, and installed packages in one operation.' `
		-Usage @('tlc sync [-Update] [-Frozen] [-NoRestore] [-Activate] [-Path PATH]') `
		-Options @('-Update       Resolve the newest versions allowed by the manifest.', '-Frozen       Fail instead of creating or refreshing a stale lock.', '-NoRestore    Resolve and lock without pulling package content.', '-Activate     Activate the synchronized environment.', '-Path PATH    Select another lock-file path.', '-PassThru     Return a structured Toolchain.SyncResult.') `
		-Examples @('tlc sync', 'tlc sync -Frozen', 'tlc sync -Update -Activate')
	$topics.activate = New-ToolchainHelpTopic `
		-Description 'Synchronizes and loads the project packages into the current PowerShell session.' `
		-Usage @('tlc activate [-NoSync] [-Path PATH] [-PassThru]') `
		-Options @('-NoSync      Load the resolved project without synchronizing first.', '-Path PATH    Select another lock-file path for synchronization.', '-PassThru     Return activation metadata.') `
		-Examples @('tlc activate', 'tlc activate -NoSync') `
		-Notes @('Only one project environment can be active in a session. Activation is idempotent for the same project.')
	$topics.deactivate = New-ToolchainHelpTopic `
		-Description 'Restores every environment value changed by the active Toolchain project.' `
		-Usage @('tlc deactivate [-PassThru]') `
		-Examples @('tlc deactivate')
	$topics.verify = New-ToolchainHelpTopic `
		-Description 'Verifies package index and platform-manifest signatures with Cosign.' `
		-Usage @('tlc verify [PACKAGE[:TAG] ...] [-Json]') `
		-Examples @('tlc verify kubectl', 'tlc verify kind:0.32.0 -Json') `
		-Notes @('Cosign must be available on PATH and the configured identity or key policy is enforced.')
	$topics.audit = New-ToolchainHelpTopic `
		-Description 'Audits project lock drift, updates, package health, signatures, and policy compliance.' `
		-Usage @('tlc audit [-Path PATH] [-Refresh] [-VerifySignatures] [-Fix] [-WhatIf] [-Strict] [-Json]') `
		-Options @(
			'-Path PATH          Select another Toolchain.lock.json file.',
			'-Refresh            Bypass cached registry and health metadata.',
			'-VerifySignatures   Verify every resolved digest with Cosign.',
			'-Fix                 Atomically refresh the lock and restore packages when all safety gates pass.',
			'-WhatIf              Preview fix actions without changing project state.',
			'-Strict             Write the report and fail when findings exist.',
			'-Json               Emit a structured JSON report.'
		) `
		-Examples @('tlc audit', 'tlc audit -Fix -WhatIf', 'tlc audit -Fix -Refresh -VerifySignatures -Strict', 'tlc audit -Path .\ci\Toolchain.lock.json -Json') `
		-Notes @('Signature verification also runs automatically when required by Toolchain.policy.json or environment policy.', '-Fix refuses to run while health, policy, signature, remote, or project-definition errors remain.')

	$topics.profile = New-ToolchainHelpTopic `
		-Description 'Creates and manages Toolchain package loads in the current PowerShell profile.' `
		-Usage @('tlc profile COMMAND [ARGUMENTS]', 'tlc profile COMMAND help') `
		-Commands @(
			'init      Create the current-host profile when it is missing.',
			'add       Add managed package loads.',
			'remove    Remove managed package loads.',
			'list      List managed package loads.',
			'path      Display the selected profile path.'
		) `
		-Examples @('tlc profile init', 'tlc profile add help')
	$topics.'profile init' = New-ToolchainHelpTopic `
		-Description 'Creates the current-user current-host PowerShell profile when it is missing.' `
		-Usage @('tlc profile init') `
		-Examples @('tlc profile init') `
		-Notes @('An existing profile is never overwritten.')
	$topics.'profile add' = New-ToolchainHelpTopic `
		-Description 'Adds package loads to Toolchain-managed markers in the PowerShell profile.' `
		-Usage @('tlc profile add PACKAGE[:TAG] [PACKAGE[:TAG] ...]') `
		-Examples @('tlc profile add node', 'tlc profile add git:latest go') `
		-Notes @('Managed startup loads suppress output with *> $null.')
	$topics.'profile remove' = New-ToolchainHelpTopic `
		-Description 'Removes package loads from Toolchain-managed profile markers.' `
		-Usage @('tlc profile remove PACKAGE[:TAG] [PACKAGE[:TAG] ...]') `
		-Examples @('tlc profile remove node') `
		-Notes @('Commands outside Toolchain-managed markers are preserved.')
	$topics.'profile list' = New-ToolchainHelpTopic `
		-Description 'Lists packages managed by Toolchain in the PowerShell profile.' `
		-Usage @('tlc profile list') `
		-Examples @('tlc profile list')
	$topics.'profile path' = New-ToolchainHelpTopic `
		-Description 'Displays the current-user current-host PowerShell profile path.' `
		-Usage @('tlc profile path') `
		-Examples @('tlc profile path')

	$topics.cluster = New-ToolchainHelpTopic `
		-Description 'Creates and manages local container-engine-backed Kubernetes development clusters.' `
		-Usage @('tlc cluster COMMAND [ARGUMENTS] [OPTIONS]', 'tlc cluster COMMAND help') `
		-Commands @(
			'create        Create a kind, k0s, or K3s-on-k3d cluster.',
			'init          Bootstrap Toolchain-owned registry and admission infrastructure.',
			'list          List managed clusters.',
			'status        Show one managed cluster and its runtime status.',
			'kubeconfig    Return a managed kubeconfig path or contents.',
			'use           Select a managed cluster for the current PowerShell process.',
			'current       Print the selected Toolchain-managed cluster.',
			'delete        Delete a managed cluster and its local state.'
		) `
		-Examples @('tlc cluster create help', 'tlc cluster init -Confirm', 'tlc cluster list') `
		-Notes @('Kind supports Docker, Podman, and nerdctl. K3d supports Docker and experimental Podman operation.')
	$topics.'cluster create' = New-ToolchainHelpTopic `
		-Description 'Creates an isolated local Kubernetes development cluster.' `
		-Usage @('tlc cluster create NAME [-Provider kind|k0s|k3s] [-Engine auto|docker|podman|nerdctl] [-Servers COUNT] [-Workers COUNT] [-ApiPort PORT] [-WaitSeconds SECONDS] [-Image REF] [-Config PATH]') `
		-Options @(
			'-Provider VALUE       Cluster provider: kind, k0s, or k3s. Default: kind.',
			'-Engine VALUE         Container engine: auto, docker, podman, or nerdctl. Default: auto.',
			'-Servers COUNT        Server/control-plane count from 1 through 9. Default: 1.',
			'-Workers COUNT        Worker count from 0 through 20. Default: 0.',
			'-ApiPort PORT         Host API port from 0 through 65535. Zero selects automatically.',
			'-WaitSeconds SECONDS  Readiness timeout from 10 through 1800. Default: 120.',
			'-Image REF            Explicit provider node image.',
			'-Config PATH          kind or k3d configuration file.'
		) `
		-Examples @('tlc cluster create dev -Provider kind', 'tlc cluster create dev -Provider k3s -Workers 2', 'tlc cluster create dev -Provider k0s -Image docker.io/k0sproject/k0s:v1.32.4-k0s.0') `
		-Notes @('k0s requires an explicitly versioned image and supports one combined controller/worker container.', '-Config cannot be combined with -Servers, -Workers, or -ApiPort.')
	$topics.'cluster init' = New-ToolchainHelpTopic `
		-Description 'Natively prepares a Kubernetes cluster with Toolchain registry, state, and image-mutation infrastructure.' `
		-Usage @('tlc cluster init [NAME] -Confirm [-Kubeconfig PATH] [-Components git-server|none] [-AgentMutationPolicy all|labeled] [-StorageClass NAME] [-RegistryStorage SIZE] [-GitStorage SIZE] [-RegistryNodePort PORT] [-WaitSeconds SECONDS] [-PassThru]') `
		-Options @(
			'NAME                         Initialize a Toolchain-managed cluster.',
			'-Kubeconfig PATH             Initialize an external cluster through an explicit kubeconfig.',
			'-Confirm                     Required acknowledgement of cluster changes.',
			'-Components VALUE           Skip the prompt: git-server installs Git; none installs no optional components.',
			'-AgentMutationPolicy VALUE  Mutate known images globally (all) or only labeled Pods (labeled).',
			'-StorageClass NAME          Storage class for persistent registry and Git volumes.',
			'-RegistryStorage SIZE       Registry PVC size. Default: 20Gi.',
			'-GitStorage SIZE            Git PVC size. Default: 10Gi.',
			'-RegistryNodePort PORT      Node-local registry port from 30000 through 32767. Default: 31999.',
			'-AgentImage REF             Skip the managed-cluster local build and use this admission-agent image.',
			'-RegistryImage REF          Override the digest-pinned registry image.',
			'-GitImage REF               Override the digest-pinned Git image.',
			'-WaitSeconds SECONDS        Rollout timeout from 30 through 1800. Default: 120.',
			'-PassThru                   Return structured initialization details.'
		) `
		-Examples @('tlc cluster init -Confirm', 'tlc cluster init dev -Confirm', 'tlc cluster init dev -Confirm -Components none', 'tlc cluster init -Kubeconfig .\kubeconfig.yaml -Confirm -Components git-server') `
		-Notes @("When -Components is omitted, Toolchain asks whether to install the optional Git server; the default answer is no.", 'Managed clusters build the admission agent locally and import it into their node runtime; -AgentImage overrides that behavior.', 'This is a Toolchain-native implementation and does not install or invoke third-party bootstrap tooling.', 'Only exact image references present in the Toolchain mapping ConfigMap are mutated.', 'Registry pulls are anonymous through the node-local gateway; writes require the generated Kubernetes Secret.', 'Repeated runs preserve credentials and mappings, then use server-side apply as an upgrade.')
	$topics.'cluster list' = New-ToolchainHelpTopic `
		-Description 'Lists clusters managed by Toolchain.' `
		-Usage @('tlc cluster list [-Provider kind|k0s|k3s]') `
		-Options @('-Provider VALUE    Return only clusters using the selected provider.') `
		-Examples @('tlc cluster list', 'tlc cluster list -Provider kind')
	$topics.'cluster status' = New-ToolchainHelpTopic `
		-Description 'Shows saved configuration and current runtime status for one managed cluster.' `
		-Usage @('tlc cluster status NAME') `
		-Examples @('tlc cluster status dev')
	$topics.'cluster kubeconfig' = New-ToolchainHelpTopic `
		-Description 'Returns the managed kubeconfig path or its raw contents.' `
		-Usage @('tlc cluster kubeconfig NAME [-Raw]') `
		-Options @('-Raw    Return kubeconfig file contents instead of its path.') `
		-Examples @('tlc cluster kubeconfig dev', 'tlc cluster kubeconfig dev -Raw') `
		-Notes @("Use 'tlc cluster use NAME' to select this file for the current PowerShell process.")
	$topics.'cluster use' = New-ToolchainHelpTopic `
		-Description 'Selects a Toolchain-managed cluster for commands in the current PowerShell process.' `
		-Usage @('tlc cluster use NAME [-PassThru]') `
		-Options @('-PassThru    Return the selected cluster context object.') `
		-Examples @('tlc cluster use dev', 'kubectl get nodes') `
		-Notes @('Sets KUBECONFIG to the isolated managed kubeconfig. It does not merge or modify the default Kubernetes configuration file.', 'The selection lasts only for the current PowerShell process and its child processes.')
	$topics.'cluster current' = New-ToolchainHelpTopic `
		-Description 'Prints the selected Toolchain-managed cluster, automatically selecting the only managed cluster when unambiguous.' `
		-Usage @('tlc cluster current [-PassThru]') `
		-Options @('-PassThru    Return the cluster name, provider, and kubeconfig path as an object.') `
		-Examples @('tlc cluster current', 'tlc cluster current -PassThru') `
		-Notes @('When KUBECONFIG is unset and exactly one managed cluster exists, selects that cluster for the current PowerShell process.', 'Returns an error for an external or multi-file KUBECONFIG, or when multiple managed clusters exist without a selection.')
	$topics.'cluster delete' = New-ToolchainHelpTopic `
		-Description 'Deletes a managed provider cluster and then removes its Toolchain state.' `
		-Usage @('tlc cluster delete NAME') `
		-Examples @('tlc cluster delete dev')
	$topics.k9s = New-ToolchainHelpTopic `
		-Description 'Launches the K9s terminal UI against the current context or a selected kubeconfig.' `
		-Usage @('tlc k9s [-Cluster NAME | -Kubeconfig PATH] [K9S_ARGUMENT ...]') `
		-Options @(
			'-Cluster NAME       Use the isolated kubeconfig for a Toolchain-managed cluster.',
			'-Kubeconfig PATH     Use an explicit kubeconfig file.',
			'K9S_ARGUMENT         Pass any other argument directly to K9s.'
		) `
		-Examples @('tlc k9s', 'tlc k9s -Cluster dev', 'tlc k9s -Kubeconfig .\kubeconfig.yaml -n default', 'tlc k9s --readonly -A') `
		-Notes @('If k9s is absent from PATH, Toolchain resolves and loads its platform package from the configured catalog.', 'The command does not merge kubeconfigs or change the current context.')

	$topics.doctor = New-ToolchainHelpTopic `
		-Description 'Checks Toolchain storage and registry configuration and reports diagnostics.' `
		-Usage @('tlc doctor [-Strict] [-PassThru] [-Json] [-Refresh]') `
		-Options @(
			'-Strict      Throw when any diagnostic fails.',
			'-PassThru    Return a Toolchain.DoctorResult object.',
			'-Json        Emit a JSON diagnostic result.',
			'-Refresh     Bypass cached remote registry data.'
		) `
		-Examples @('tlc doctor', 'tlc doctor -Strict', 'tlc doctor -Json')
	$topics.help = New-ToolchainHelpTopic `
		-Description 'Displays the command overview or detailed help for a command path.' `
		-Usage @('tlc help', 'tlc COMMAND help', 'tlc COMMAND SUBCOMMAND help', 'tlc help COMMAND [SUBCOMMAND]') `
		-Examples @('tlc help', 'tlc pull help', 'tlc cluster create help', 'tlc help remote tags') `
		-Notes @('The tokens h, -h, --help, and ? are also accepted as help requests.')

	return $topics
}

function Test-ToolchainHelpToken {
	param([AllowNull()][object]$Value)
	if ($null -eq $Value) { return $false }
	return ([string]$Value).ToLowerInvariant() -in @('help', 'h', '-h', '--help', '?', '/?')
}

function ConvertTo-ToolchainHelpPath {
	param([object[]]$Elements)
	$path = @($Elements | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Where-Object { $_ })
	if ($path.Count -gt 0) {
		switch ($path[0]) {
			'v' { $path[0] = 'version' }
			'rm' { $path[0] = 'remove' }
			'h' { $path[0] = 'help' }
		}
	}
	return [string[]]$path
}

function Get-ToolchainHelpRequest {
	param(
		[Parameter(Mandatory)][string]$Command,
		[object[]]$ArgumentList
	)
	$arguments = @($ArgumentList)
	if (Test-ToolchainHelpToken $Command) {
		$path = ConvertTo-ToolchainHelpPath $arguments
		if ($arguments.Count -eq 1 -and ([string]$arguments[0]).ToLowerInvariant() -in @('h', '-h', '--help', '?', '/?')) { $path = @() }
		return [pscustomobject]@{ Requested = $true; CommandPath = [string[]]$path }
	}
	if ($arguments.Count -gt 0 -and (Test-ToolchainHelpToken $arguments[-1])) {
		$prefix = @()
		if ($arguments.Count -gt 1) { $prefix = @($arguments[0..($arguments.Count - 2)]) }
		$canonicalCommand = @(ConvertTo-ToolchainHelpPath @($Command))[0]
		$path = @($canonicalCommand)
		if ($prefix.Count -gt 0) {
			$candidate = ([string]$prefix[0]).ToLowerInvariant()
			if ((Get-ToolchainHelpTopics).Contains("$canonicalCommand $candidate")) {
				$path = @($canonicalCommand, $candidate)
			}
		}
		return [pscustomobject]@{ Requested = $true; CommandPath = [string[]]$path }
	}
	return [pscustomobject]@{ Requested = $false; CommandPath = @() }
}

function Add-ToolchainHelpSection {
	param(
		[Parameter(Mandatory)][AllowEmptyString()][Collections.Generic.List[string]]$Lines,
		[Parameter(Mandatory)][string]$Heading,
		[string[]]$Values
	)
	if (-not $Values -or $Values.Count -eq 0) { return }
	[void]$Lines.Add('')
	[void]$Lines.Add("${Heading}:")
	foreach ($value in $Values) { [void]$Lines.Add("  $value") }
}

function Invoke-ToolchainHelp {
	[CmdletBinding()]
	param([string[]]$CommandPath)

	$lines = [Collections.Generic.List[string]]::new()
	$path = @(ConvertTo-ToolchainHelpPath $CommandPath)
	if ($path.Count -eq 0) {
		[void]$lines.Add('')
		[void]$lines.Add('Toolchain command line help')
		Add-ToolchainHelpSection -Lines $lines -Heading 'Usage' -Values @(
			'tlc COMMAND [ARGUMENTS]',
			'tlc COMMAND help',
			'tlc help [COMMAND [SUBCOMMAND]]'
		)
		Add-ToolchainHelpSection -Lines $lines -Heading 'Commands' -Values @(
			'version        Display the installed module version.',
			'list           List locally installed packages.',
			'remote         List remote packages or raw registry tags.',
			'pull           Download packages.',
			'load           Load packages into the current session.',
			'exec           Run a script block with packages loaded.',
			'run            Run a Toolchain.ps1 project function.',
			'update         Update locally tagged packages.',
			'prune          Delete unreferenced package content.',
			'remove         Remove local package tags and content.',
			'save           Create an offline package repository.',
			'init           Create a starter toolchain.yaml file.',
			'lock           Pin project packages to immutable platform digests.',
			'restore        Restore packages from Toolchain.lock.json.',
			'sync           Converge the project, lock, and installed packages.',
			'activate       Activate the project environment in this session.',
			'deactivate     Restore the pre-activation environment.',
			'verify         Verify package signatures.',
			'audit          Audit project reproducibility and supply-chain status.',
			'profile        Manage PowerShell profile package loads.',
			'cluster        Manage local Docker-backed Kubernetes clusters.',
			'k9s            Launch a terminal UI for a Kubernetes cluster.',
			'doctor         Check Toolchain storage and registry configuration.',
			'help           Display overview or command-specific help.'
		)
		[void]$lines.Add('')
		[void]$lines.Add("Run 'tlc COMMAND help' for details and examples.")
		[void]$lines.Add('Documentation: https://github.com/allsagetech/toolchain')
		[void]$lines.Add('')
		return ($lines -join [Environment]::NewLine)
	}

	$key = $path -join ' '
	$topics = Get-ToolchainHelpTopics
	if (-not $topics.Contains($key)) {
		throw "unknown Toolchain help topic '$key'. Run 'tlc help' to list commands."
	}
	$topic = $topics[$key]
	[void]$lines.Add('')
	[void]$lines.Add("Toolchain command: $key")
	Add-ToolchainHelpSection -Lines $lines -Heading 'Description' -Values @($topic.Description)
	Add-ToolchainHelpSection -Lines $lines -Heading 'Usage' -Values $topic.Usage
	Add-ToolchainHelpSection -Lines $lines -Heading 'Commands' -Values $topic.Commands
	Add-ToolchainHelpSection -Lines $lines -Heading 'Options' -Values $topic.Options
	Add-ToolchainHelpSection -Lines $lines -Heading 'Examples' -Values $topic.Examples
	Add-ToolchainHelpSection -Lines $lines -Heading 'Notes' -Values $topic.Notes
	[void]$lines.Add('')
	[void]$lines.Add("Run 'tlc help' for the full command list.")
	[void]$lines.Add('Documentation: https://github.com/allsagetech/toolchain')
	[void]$lines.Add('')
	return ($lines -join [Environment]::NewLine)
}
