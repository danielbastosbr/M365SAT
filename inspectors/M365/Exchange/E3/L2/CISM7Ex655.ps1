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

function Build-CISM7Ex655
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISM7Ex655"
        ID               = "6.5.5"
        Title            = '(L2) Ensure Direct Send is rejected'
        ProductFamily    = "Microsoft Exchange"
        DefaultValue     = 'RejectDirectSend: False'
        ExpectedValue    = 'RejectDirectSend: True'
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = 'Direct Send lets anyone deliver mail to the tenant''s MX using the organization''s own accepted domain as sender, without authentication. Attackers abuse it to send internal-looking phishing.'
        Impact           = 'Devices and applications that send through Direct Send (printers, scanners, line-of-business apps) stop working until they move to authenticated SMTP or a partner connector.'
        Remediation      = 'Inventory Direct Send usage (message trace), move senders to SMTP AUTH or an inbound partner connector, then run: Set-OrganizationConfig -RejectDirectSend $true'
        References       = @(
            @{ 'Name' = 'Introducing more control over Direct Send'; 'URL' = 'https://techcommunity.microsoft.com/blog/exchange/introducing-more-control-over-direct-send-in-exchange-online/4408790' },
            @{ 'Name' = 'How to set up a device or application to send email'; 'URL' = 'https://learn.microsoft.com/en-us/exchange/mail-flow-best-practices/how-to-set-up-a-multifunction-device-or-application-to-send-email-using-microsoft-365-or-office-365' }
        )
    }
    return $inspectorobject
}

function Audit-CISM7Ex655
{
	try
	{
		$Violation = @()
		$PassValue = $null
		$OrgConfig = Get-OrganizationConfig -ErrorAction Stop
		Save-M365SATEvidence -Name 'CISM7Ex655-OrganizationConfig' -InputObject ($OrgConfig | Select-Object Name, RejectDirectSend)
		if ($OrgConfig.RejectDirectSend -ne $true)
		{
			$Violation += "RejectDirectSend: $($OrgConfig.RejectDirectSend)"
		}
		$PassValue = "RejectDirectSend: True"

		# Validation
		if ($Violation.Count -ne 0)
		{
			$endobject = Build-CISM7Ex655 -ReturnedValue ($Violation) -Status "FAIL" -RiskScore "6" -RiskRating "Medium"
			return $endobject
		}
		else
		{
			$endobject = Build-CISM7Ex655 -ReturnedValue ($PassValue) -Status "PASS" -RiskScore "0" -RiskRating "None"
			return $endobject
		}
	}
	catch
	{
		$endobject = Build-CISM7Ex655 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISM7Ex655
