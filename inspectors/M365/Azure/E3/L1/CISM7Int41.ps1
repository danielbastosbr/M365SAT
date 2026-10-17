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

function Build-CISM7Int41
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISM7Int41"
        ID               = "4.1"
        Title            = '(L1) Ensure devices without a compliance policy are marked ''not compliant'''
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = 'Compliant (secureByDefault = False)'
        ExpectedValue    = 'Not compliant (secureByDefault = True)'
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = 'Intune treats devices that have no compliance policy assigned as compliant by default. Conditional Access policies that require a compliant device are then satisfied by unmanaged, unevaluated devices.'
        Impact           = 'Devices without an assigned compliance policy lose access to resources protected by ''require compliant device'' Conditional Access policies until a policy is assigned.'
        Remediation      = 'Intune admin center > Devices > Compliance > Compliance settings > set ''Mark devices with no compliance policy assigned as'' to ''Not compliant''. Graph: PATCH https://graph.microsoft.com/v1.0/deviceManagement/settings with body {"secureByDefault": true}'
        References       = @(
            @{ 'Name' = 'Compliance policy settings'; 'URL' = 'https://learn.microsoft.com/en-us/mem/intune/protect/device-compliance-get-started#compliance-policy-settings' },
            @{ 'Name' = 'deviceManagementSettings resource'; 'URL' = 'https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-devicemanagementsettings' }
        )
    }
    return $inspectorobject
}

function Audit-CISM7Int41
{
	try
	{
		$Violation = @()
		$PassValue = $null
		$Settings = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/settings' -OutputType PSObject -ErrorAction Stop
		Save-M365SATEvidence -Name 'CISM7Int41-DeviceManagementSettings' -InputObject $Settings
		if ($Settings.secureByDefault -ne $true)
		{
			$Violation += "secureByDefault: $($Settings.secureByDefault) (devices without compliance policy are marked compliant)"
		}
		$PassValue = "secureByDefault: True"

		# Validation
		if ($Violation.Count -ne 0)
		{
			$endobject = Build-CISM7Int41 -ReturnedValue ($Violation) -Status "FAIL" -RiskScore "6" -RiskRating "Medium"
			return $endobject
		}
		else
		{
			$endobject = Build-CISM7Int41 -ReturnedValue ($PassValue) -Status "PASS" -RiskScore "0" -RiskRating "None"
			return $endobject
		}
	}
	catch
	{
		$endobject = Build-CISM7Int41 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISM7Int41
