# Benchmark: CIS Microsoft 365 v7.0.0
# Author: Daniel Bastos

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Get-M365SATGraphCollection
{
	param ([Parameter(Mandatory = $true)][string]$Uri)
	$items = @()
	$next = $Uri
	while ($next)
	{
		$response = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType PSObject -ErrorAction Stop
		if ($null -ne $response.value) { $items += $response.value }
		$next = $response.'@odata.nextLink'
	}
	return ,$items
}

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

function Build-CISM7Int42
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISM7Int42"
        ID               = "4.2"
        Title            = '(L1) Ensure enrollment of personally owned devices is blocked'
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = 'Allow'
        ExpectedValue    = 'Personally owned enrollment blocked (or platform blocked) for every platform'
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = 'The default Intune device platform restriction allows personally owned devices to enroll. Blocking personal enrollment keeps corporate management and data on devices the organization owns.'
        Impact           = 'Users can no longer enroll personal devices. BYOD scenarios must move to app protection policies or to a corporate enrollment method (Autopilot, ABM, Android Enterprise).'
        Remediation      = 'Intune admin center > Devices > Enrollment > Device platform restriction > Default (All users) > Properties > set ''Personally owned'' to Block for every platform, or block unused platforms.'
        References       = @(
            @{ 'Name' = 'Create device platform restrictions'; 'URL' = 'https://learn.microsoft.com/en-us/mem/intune/enrollment/create-device-platform-restrictions' },
            @{ 'Name' = 'Enrollment restrictions'; 'URL' = 'https://learn.microsoft.com/en-us/mem/intune/enrollment/enrollment-restrictions-set' }
        )
    }
    return $inspectorobject
}

function Audit-CISM7Int42
{
	try
	{
		$Violation = @()
		$PassValue = $null
		$Configs = Get-M365SATGraphCollection -Uri 'https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations'
		$Default = @($Configs | Where-Object { $_.priority -eq 0 -and $_.'@odata.type' -match 'deviceEnrollmentPlatformRestriction' })
		Save-M365SATEvidence -Name 'CISM7Int42-PlatformRestrictions' -InputObject $Default
		$Results = @{}
		# Legacy tenants: a single object holding one restriction per platform
		foreach ($Legacy in ($Default | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration' }))
		{
			foreach ($Platform in @('windows', 'ios', 'androidForWork', 'macOS', 'android'))
			{
				$Restriction = $Legacy."$($Platform)Restriction"
				if ($null -ne $Restriction)
				{
					$Results[$Platform] = ($Restriction.platformBlocked -eq $true) -or ($Restriction.personalDeviceEnrollmentBlocked -eq $true)
				}
			}
		}
		# Current tenants: one default object per platform
		foreach ($PerPlatform in ($Default | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.deviceEnrollmentPlatformRestrictionConfiguration' }))
		{
			$Restriction = $PerPlatform.platformRestriction
			$Results["$($PerPlatform.platformType)"] = ($Restriction.platformBlocked -eq $true) -or ($Restriction.personalDeviceEnrollmentBlocked -eq $true)
		}
		if ($Results.Count -eq 0)
		{
			throw "No default device platform restriction returned by Graph"
		}
		foreach ($Platform in $Results.Keys)
		{
			if (-not $Results[$Platform])
			{
				$Violation += "Personally owned enrollment allowed: $Platform"
			}
		}
		$PassValue = "Personally owned enrollment blocked for: $(($Results.Keys | Sort-Object) -join ', ')"

		# Validation
		if ($Violation.Count -ne 0)
		{
			$endobject = Build-CISM7Int42 -ReturnedValue ($Violation) -Status "FAIL" -RiskScore "5" -RiskRating "Medium"
			return $endobject
		}
		else
		{
			$endobject = Build-CISM7Int42 -ReturnedValue ($PassValue) -Status "PASS" -RiskScore "0" -RiskRating "None"
			return $endobject
		}
	}
	catch
	{
		$endobject = Build-CISM7Int42 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISM7Int42
