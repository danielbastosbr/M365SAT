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

function Build-CISM7Az5144
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISM7Az5144"
        ID               = "5.1.4.4"
        Title            = '(L1) Ensure the registering user is not added as local administrator during Entra join'
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = 'All'
        ExpectedValue    = 'Selected or None'
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = 'By default the user who joins a device to Entra ID becomes its local administrator. Standard users with local admin rights can disable security controls and install unapproved software.'
        Impact           = 'Users who join devices no longer receive local administrator rights. Elevation must be handled through LAPS, Endpoint Privilege Management or a selected group.'
        Remediation      = 'Entra admin center > Entra ID > Devices > Device settings > set ''Registering user is added as local administrator on the device during Microsoft Entra join'' to Selected or None.'
        References       = @(
            @{ 'Name' = 'Manage the local administrators group on Entra joined devices'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/devices/assign-local-admin' },
            @{ 'Name' = 'deviceRegistrationPolicy resource'; 'URL' = 'https://learn.microsoft.com/en-us/graph/api/resources/deviceregistrationpolicy' }
        )
    }
    return $inspectorobject
}

function Audit-CISM7Az5144
{
	try
	{
		$Violation = @()
		$PassValue = $null
		$Policy = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/beta/policies/deviceRegistrationPolicy' -OutputType PSObject -ErrorAction Stop
		Save-M365SATEvidence -Name 'CISM7Az5144-DeviceRegistrationPolicy' -InputObject $Policy
		$Membership = $Policy.azureADJoin.localAdmins.registeringUsers.'@odata.type'
		if ($Membership -notin @('#microsoft.graph.enumeratedDeviceRegistrationMembership', '#microsoft.graph.noDeviceRegistrationMembership'))
		{
			$Violation += "azureADJoin.localAdmins.registeringUsers: $Membership"
		}
		$PassValue = "azureADJoin.localAdmins.registeringUsers: $Membership"

		# Validation
		if ($Violation.Count -ne 0)
		{
			$endobject = Build-CISM7Az5144 -ReturnedValue ($Violation) -Status "FAIL" -RiskScore "6" -RiskRating "Medium"
			return $endobject
		}
		else
		{
			$endobject = Build-CISM7Az5144 -ReturnedValue ($PassValue) -Status "PASS" -RiskScore "0" -RiskRating "None"
			return $endobject
		}
	}
	catch
	{
		$endobject = Build-CISM7Az5144 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISM7Az5144
