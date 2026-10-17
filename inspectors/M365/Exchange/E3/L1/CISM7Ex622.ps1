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

function Build-CISM7Ex622
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISM7Ex622"
        ID               = "6.2.2"
        Title            = '(L1) Ensure mail flow rules do not bypass spam filtering for sender domains'
        ProductFamily    = "Microsoft Exchange"
        DefaultValue     = 'No such rules'
        ExpectedValue    = 'No transport rule sets SCL -1 based on SenderDomainIs'
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = 'A transport rule that sets the spam confidence level to -1 for a sender domain skips spam and phishing filtering for that domain. Sender domains are trivially spoofed, so the rule becomes a delivery path for phishing.'
        Impact           = 'Mail from the listed domains is filtered normally again; use tenant allow/block list or advanced delivery for legitimate exceptions.'
        Remediation      = 'Exchange admin center > Mail flow > Rules > remove the ''Set the spam confidence level (SCL) to -1'' action from rules conditioned on sender domain. PowerShell: Get-TransportRule | Where-Object { $_.SetSCL -eq -1 -and $_.SenderDomainIs } | Remove-TransportRule'
        References       = @(
            @{ 'Name' = 'Mail flow rules in Exchange Online'; 'URL' = 'https://learn.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/mail-flow-rules' },
            @{ 'Name' = 'Create safe sender lists in EOP'; 'URL' = 'https://learn.microsoft.com/en-us/defender-office-365/create-safe-sender-lists-in-office-365' }
        )
    }
    return $inspectorobject
}

function Audit-CISM7Ex622
{
	try
	{
		$Violation = @()
		$PassValue = $null
		$Rules = @(Get-TransportRule -ErrorAction Stop | Where-Object { $_.SetSCL -eq -1 -and $null -ne $_.SenderDomainIs -and @($_.SenderDomainIs).Count -gt 0 })
		Save-M365SATEvidence -Name 'CISM7Ex622-SpamBypassTransportRules' -InputObject ($Rules | Select-Object Name, State, SenderDomainIs, SetSCL)
		foreach ($Rule in $Rules)
		{
			$Violation += "Transport rule '$($Rule.Name)' sets SCL -1 for: $(@($Rule.SenderDomainIs) -join ', ')"
		}
		$PassValue = "No transport rule bypasses spam filtering based on sender domain"

		# Validation
		if ($Violation.Count -ne 0)
		{
			$endobject = Build-CISM7Ex622 -ReturnedValue ($Violation) -Status "FAIL" -RiskScore "7" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISM7Ex622 -ReturnedValue ($PassValue) -Status "PASS" -RiskScore "0" -RiskRating "None"
			return $endobject
		}
	}
	catch
	{
		$endobject = Build-CISM7Ex622 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISM7Ex622
