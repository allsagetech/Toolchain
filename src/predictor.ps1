<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

$script:ToolchainPredictorId = [guid]'501eb087-2163-4fcd-976a-05f0e68e7052'
$script:ToolchainPredictorInstance = $null
$script:ToolchainPredictorPreviousPredictionSource = $null
$script:ToolchainPredictorChangedPredictionSource = $false

function Get-ToolchainPredictiveIntelliSenseSupport {
	$predictionContextType = 'System.Management.Automation.Subsystem.Prediction.PredictionContext' -as [type]
	$subsystemManagerType = 'System.Management.Automation.Subsystem.SubsystemManager' -as [type]
	$psReadLineCommand = Get-Command -Name 'Get-PSReadLineOption' -ErrorAction SilentlyContinue
	$setPsReadLineCommand = Get-Command -Name 'Set-PSReadLineOption' -ErrorAction SilentlyContinue
	$psReadLineModule = if ($psReadLineCommand) { Get-Module -Name PSReadLine } else { $null }
	$consoleOutputRedirected = [Console]::IsOutputRedirected
	$supportsVirtualTerminal = $Host.UI -and $Host.UI.PSObject.Properties['SupportsVirtualTerminal'] -and [bool]$Host.UI.SupportsVirtualTerminal
	$minimumPowerShell = [Version]'7.2'
	$minimumPsReadLine = [Version]'2.2.2'
	$reason = $null

	if ($PSVersionTable.PSVersion -lt $minimumPowerShell) {
		$reason = "requires PowerShell $minimumPowerShell or later"
	} elseif (-not $predictionContextType -or -not $subsystemManagerType) {
		$reason = 'requires the PowerShell command-predictor subsystem'
	} elseif (-not $psReadLineCommand -or -not $setPsReadLineCommand -or -not $psReadLineModule) {
		$reason = "requires PSReadLine $minimumPsReadLine or later"
	} elseif ($psReadLineModule.Version -lt $minimumPsReadLine) {
		$reason = "requires PSReadLine $minimumPsReadLine or later (found $($psReadLineModule.Version))"
	} elseif ($consoleOutputRedirected) {
		$reason = 'requires an interactive terminal with non-redirected console output'
	} elseif (-not $supportsVirtualTerminal) {
		$reason = 'requires an interactive terminal with virtual-terminal support'
	}

	return [pscustomobject]@{
		Supported = [string]::IsNullOrWhiteSpace($reason)
		Reason = $reason
		PowerShellVersion = $PSVersionTable.PSVersion.ToString()
		PSReadLineVersion = if ($psReadLineModule) { $psReadLineModule.Version.ToString() } else { $null }
	}
}

function Initialize-ToolchainPredictiveIntelliSenseType {
	if ('AllSageTech.Toolchain.ToolchainCommandPredictor' -as [type]) { return }

	$source = @'
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Management.Automation.Subsystem;
using System.Management.Automation.Subsystem.Prediction;

namespace AllSageTech.Toolchain
{
    public sealed class ToolchainCommandPredictor : ICommandPredictor
    {
        private static readonly Guid PredictorGuid = new Guid("501eb087-2163-4fcd-976a-05f0e68e7052");
        private static readonly string[] TopLevelCommands = new[]
        {
            "version", "list", "remote", "pull", "load", "exec", "run", "shell", "remove", "save",
            "prune", "update", "init", "lock", "restore", "sync", "activate", "deactivate",
            "verify", "audit", "profile", "package", "cluster", "k9s", "doctor", "completion", "help"
        };
        private static readonly Dictionary<string, string[]> NestedCommands = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            { "remote", new[] { "list", "models", "all", "tags", "health", "info" } },
            { "profile", new[] { "init", "add", "remove", "list", "path" } },
            { "package", new[] { "create", "deploy", "remove" } },
            { "cluster", new[] { "create", "init", "deinit", "reset", "restore", "doctor", "list", "status", "kubeconfig", "use", "current", "delete" } },
            { "completion", new[] { "enable", "disable", "status" } },
            { "shell", new[] { "pwsh" } }
        };

        public Guid Id { get { return PredictorGuid; } }
        public string Name { get { return "Toolchain"; } }
        public string Description { get { return "Suggests Toolchain commands while you type."; } }
        public Dictionary<string, string> FunctionsToDefine { get { return null; } }

        public string[] GetSuggestionTexts(string input)
        {
            if (String.IsNullOrWhiteSpace(input)) { return new string[0]; }

            string trimmedStart = input.TrimStart();
            string[] parts = trimmedStart.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0 || !new[] { "tlc", "toolchain", "tool" }.Contains(parts[0], StringComparer.OrdinalIgnoreCase)) {
                return new string[0];
            }

            string prefix = parts[0];
            bool hasTrailingWhitespace = Char.IsWhiteSpace(input[input.Length - 1]);
            IEnumerable<string> candidates;
            if (parts.Length == 1)
            {
                candidates = TopLevelCommands.Select(command => prefix + " " + command);
            }
            else
            {
                string command = parts[1];
                if (parts.Length == 2 && !hasTrailingWhitespace)
                {
                    candidates = TopLevelCommands
                        .Where(candidate => candidate.StartsWith(command, StringComparison.OrdinalIgnoreCase))
                        .Select(candidate => prefix + " " + candidate);
                }
                else if (NestedCommands.TryGetValue(command, out string[] nestedCommands))
                {
                    string nestedPrefix = prefix + " " + command + " ";
                    string nestedInput = parts.Length > 2 && !hasTrailingWhitespace ? parts[2] : String.Empty;
                    candidates = nestedCommands
                        .Where(candidate => candidate.StartsWith(nestedInput, StringComparison.OrdinalIgnoreCase))
                        .Select(candidate => nestedPrefix + candidate);
                }
                else
                {
                    candidates = new string[0];
                }
            }

            return candidates
                .Where(candidate => candidate.StartsWith(input, StringComparison.OrdinalIgnoreCase))
                .Take(8)
                .ToArray();
        }

        public SuggestionPackage GetSuggestion(PredictionClient client, PredictionContext context, CancellationToken cancellationToken)
        {
            if (cancellationToken.IsCancellationRequested) { return default(SuggestionPackage); }

            string input = context == null || context.InputAst == null ? String.Empty : context.InputAst.Extent.Text;
            List<PredictiveSuggestion> suggestions = GetSuggestionTexts(input)
                .Select(text => new PredictiveSuggestion(text, "Toolchain command"))
                .ToList();
            return suggestions.Count == 0 ? default(SuggestionPackage) : new SuggestionPackage(suggestions);
        }

        public bool CanAcceptFeedback(PredictionClient client, PredictorFeedbackKind feedback) { return false; }
        public void OnSuggestionDisplayed(PredictionClient client, uint session, int countOrIndex) { }
        public void OnSuggestionAccepted(PredictionClient client, uint session, string acceptedSuggestion) { }
        public void OnCommandLineAccepted(PredictionClient client, IReadOnlyList<string> history) { }
        public void OnCommandLineExecuted(PredictionClient client, string commandLine, bool success) { }
    }
}
'@
	Add-Type -TypeDefinition $source -Language CSharp -ErrorAction Stop
}

function Get-ToolchainPredictiveIntelliSenseImplementation {
	$support = Get-ToolchainPredictiveIntelliSenseSupport
	if (-not $support.Supported) { return $null }

	$subsystemManagerType = 'System.Management.Automation.Subsystem.SubsystemManager' -as [type]
	$subsystemKindType = 'System.Management.Automation.Subsystem.SubsystemKind' -as [type]
	$kind = [Enum]::Parse($subsystemKindType, 'CommandPredictor')
	$info = $subsystemManagerType::GetSubsystemInfo($kind)
	return @($info.Implementations | Where-Object { $_.Id -eq $script:ToolchainPredictorId } | Select-Object -First 1)[0]
}

function Get-ToolchainPredictiveIntelliSenseStatus {
	$support = Get-ToolchainPredictiveIntelliSenseSupport
	$options = if ($support.Supported) { Get-PSReadLineOption } else { $null }
	$implementation = if ($support.Supported) { Get-ToolchainPredictiveIntelliSenseImplementation } else { $null }
	return [pscustomobject]@{
		PSTypeName = 'Toolchain.PredictiveIntelliSenseStatus'
		Supported = $support.Supported
		Enabled = $null -ne $implementation
		Reason = $support.Reason
		PowerShellVersion = $support.PowerShellVersion
		PSReadLineVersion = $support.PSReadLineVersion
		PredictionSource = if ($options) { [string]$options.PredictionSource } else { $null }
		PredictionViewStyle = if ($options) { [string]$options.PredictionViewStyle } else { $null }
	}
}

function Enable-ToolchainPredictiveIntelliSense {
	$support = Get-ToolchainPredictiveIntelliSenseSupport
	if (-not $support.Supported) { throw "Toolchain predictive IntelliSense $($support.Reason)." }

	Initialize-ToolchainPredictiveIntelliSenseType
	$implementation = Get-ToolchainPredictiveIntelliSenseImplementation
	if (-not $implementation) {
		$type = 'AllSageTech.Toolchain.ToolchainCommandPredictor' -as [type]
		$script:ToolchainPredictorInstance = [Activator]::CreateInstance($type)
		[System.Management.Automation.Subsystem.SubsystemManager]::RegisterSubsystem(
			[System.Management.Automation.Subsystem.SubsystemKind]::CommandPredictor,
			$script:ToolchainPredictorInstance
		)
	}

	$options = Get-PSReadLineOption
	$desiredPredictionSource = switch ([string]$options.PredictionSource) {
		'None' { 'Plugin' }
		'History' { 'HistoryAndPlugin' }
		default { [string]$options.PredictionSource }
	}
	if ($desiredPredictionSource -ne [string]$options.PredictionSource) {
		$script:ToolchainPredictorPreviousPredictionSource = [string]$options.PredictionSource
		$script:ToolchainPredictorChangedPredictionSource = $true
		Set-PSReadLineOption -PredictionSource $desiredPredictionSource
	}

	return Get-ToolchainPredictiveIntelliSenseStatus
}

function Disable-ToolchainPredictiveIntelliSense {
	$support = Get-ToolchainPredictiveIntelliSenseSupport
	if (-not $support.Supported) { return Get-ToolchainPredictiveIntelliSenseStatus }

	$implementation = Get-ToolchainPredictiveIntelliSenseImplementation
	if ($implementation) {
		[System.Management.Automation.Subsystem.SubsystemManager]::UnregisterSubsystem(
			[System.Management.Automation.Subsystem.SubsystemKind]::CommandPredictor,
			$script:ToolchainPredictorId
		)
	}
	if ($script:ToolchainPredictorChangedPredictionSource -and $script:ToolchainPredictorPreviousPredictionSource) {
		Set-PSReadLineOption -PredictionSource $script:ToolchainPredictorPreviousPredictionSource
	}
	$script:ToolchainPredictorInstance = $null
	$script:ToolchainPredictorPreviousPredictionSource = $null
	$script:ToolchainPredictorChangedPredictionSource = $false
	return Get-ToolchainPredictiveIntelliSenseStatus
}

function Invoke-ToolchainPredictiveIntelliSense {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory, Position = 0)]
		[ValidateSet('enable', 'disable', 'status')]
		[string]$Command
	)

	switch ($Command) {
		'enable' { return Enable-ToolchainPredictiveIntelliSense }
		'disable' { return Disable-ToolchainPredictiveIntelliSense }
		'status' { return Get-ToolchainPredictiveIntelliSenseStatus }
	}
}
