# Benchmark: CIS Microsoft 365 v7.0.0
# Author: Daniel Bastos

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Save-M365SATEvidence
{
	param ([string]$Name, $InputObject)
	try
	{
		if (-not [string]::IsNullOrEmpty("$OutPath"))
		{
			$InputObject | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path -Path "$OutPath" -ChildPath "$Name.json") -Encoding utf8
		}
	}
	catch
	{
		Write-WarningLog 'Could not write evidence file {name}' -PropertyValues $Name
	}
}

function Build-CISM7Ex323
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISM7Ex323"
        ID               = "3.2.3"
        Title            = '(L1) Ensure DLP policies are enabled for Microsoft 365 Copilot'
        ProductFamily    = "Microsoft Exchange"
        DefaultValue     = 'No Copilot DLP policy (some tenants have a Microsoft-provisioned default policy)'
        ExpectedValue    = 'At least one DLP policy with the Copilot location, Mode = Enable, scoped to all accounts'
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = 'Copilot answers from everything a user can access. Without DLP scoped to Copilot interactions, sensitive data (PII, financial, labeled content) can be summarized and surfaced in prompts and responses.'
        Impact           = 'Copilot stops processing or returning content that matches the policy conditions; tune rules to avoid blocking legitimate work.'
        Remediation      = 'Microsoft Purview > Data loss prevention > Policies > create or enable a policy with location ''Microsoft 365 Copilot and Copilot Chat'' for all accounts and rules for the organization''s sensitive information types, Mode = On.'
        References       = @(
            @{ 'Name' = 'Learn about the Microsoft 365 Copilot DLP location'; 'URL' = 'https://learn.microsoft.com/en-us/purview/dlp-microsoft365-copilot-location-learn-about' },
            @{ 'Name' = 'Get-DlpCompliancePolicy'; 'URL' = 'https://learn.microsoft.com/en-us/powershell/module/exchange/get-dlpcompliancepolicy' }
        )
    }
    return $inspectorobject
}

function Audit-CISM7Ex323
{
	try
	{
		$Violation = @()
		$PassValue = $null
		if (-not (Get-Command -Name Get-DlpCompliancePolicy -ErrorAction SilentlyContinue))
		{
			throw "Get-DlpCompliancePolicy is not available. Connect to Security & Compliance PowerShell (run with -Modules All)."
		}
		$CopilotPolicies = @(Get-DlpCompliancePolicy -ErrorAction Stop | Where-Object { "$($_.EnforcementPlanes)" -match 'CopilotExperiences' })
		Save-M365SATEvidence -Name 'CISM7Ex323-CopilotDlpPolicies' -InputObject ($CopilotPolicies | Select-Object Name, Mode, EnforcementPlanes, LocationInclusions, LocationExclusions)
		$Compliant = @($CopilotPolicies | Where-Object { $_.Mode -eq 'Enable' })
		if ($CopilotPolicies.Count -eq 0)
		{
			$Violation += "No DLP policy includes the Microsoft 365 Copilot location"
		}
		elseif ($Compliant.Count -eq 0)
		{
			foreach ($Policy in $CopilotPolicies) { $Violation += "Copilot DLP policy not enforced: $($Policy.Name) (Mode: $($Policy.Mode))" }
		}
		$PassValue = "Enforced Copilot DLP policy: $(($Compliant.Name) -join ', '). Review LocationExclusions in the evidence file."

		# Validation
		if ($Violation.Count -ne 0)
		{
			$endobject = Build-CISM7Ex323 -ReturnedValue ($Violation) -Status "FAIL" -RiskScore "6" -RiskRating "Medium"
			return $endobject
		}
		else
		{
			$endobject = Build-CISM7Ex323 -ReturnedValue ($PassValue) -Status "PASS" -RiskScore "0" -RiskRating "None"
			return $endobject
		}
	}
	catch
	{
		$endobject = Build-CISM7Ex323 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISM7Ex323
