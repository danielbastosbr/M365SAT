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

function Build-CISM7Az5145
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISM7Az5145"
        ID               = "5.1.4.5"
        Title            = '(L1) Ensure Microsoft Entra LAPS is enabled'
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = 'No'
        ExpectedValue    = 'Yes'
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = 'Without Windows LAPS the built-in local administrator password is usually identical across devices or never rotated, which enables pass-the-hash and lateral movement after a single device is compromised.'
        Impact           = 'Enabling the tenant setting only allows LAPS; an Intune or GPO LAPS policy is still required to back up and rotate the passwords.'
        Remediation      = 'Entra admin center > Entra ID > Devices > Device settings > set ''Enable Microsoft Entra Local Administrator Password Solution (LAPS)'' to Yes, then deploy an Intune account protection (LAPS) policy.'
        References       = @(
            @{ 'Name' = 'Windows LAPS with Microsoft Entra ID'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/devices/howto-manage-local-admin-passwords' },
            @{ 'Name' = 'deviceRegistrationPolicy resource'; 'URL' = 'https://learn.microsoft.com/en-us/graph/api/resources/deviceregistrationpolicy' }
        )
    }
    return $inspectorobject
}

function Audit-CISM7Az5145
{
	try
	{
		$Violation = @()
		$PassValue = $null
		$Policy = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/deviceRegistrationPolicy' -OutputType PSObject -ErrorAction Stop
		Save-M365SATEvidence -Name 'CISM7Az5145-DeviceRegistrationPolicy' -InputObject $Policy
		if ($Policy.localAdminPassword.isEnabled -ne $true)
		{
			$Violation += "localAdminPassword.isEnabled: $($Policy.localAdminPassword.isEnabled)"
		}
		$PassValue = "localAdminPassword.isEnabled: True"

		# Validation
		if ($Violation.Count -ne 0)
		{
			$endobject = Build-CISM7Az5145 -ReturnedValue ($Violation) -Status "FAIL" -RiskScore "7" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISM7Az5145 -ReturnedValue ($PassValue) -Status "PASS" -RiskScore "0" -RiskRating "None"
			return $endobject
		}
	}
	catch
	{
		$endobject = Build-CISM7Az5145 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISM7Az5145
