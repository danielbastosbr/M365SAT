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

function Build-CISM7Az5154
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISM7Az5154"
        ID               = "5.1.5.4"
        Title            = '(L1) Ensure application client secrets have a maximum lifetime of 180 days or less'
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = 'Off'
        ExpectedValue    = 'Enabled for applications and service principals, maxLifetime <= P180D'
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = 'Client secrets without an expiry limit stay valid for years. A leaked secret then gives an attacker long-lived, MFA-free access with the permissions of the application.'
        Impact           = 'New client secrets cannot exceed the configured lifetime; application owners must rotate them more often. Existing secrets are not changed.'
        Remediation      = 'Entra admin center > Entra ID > Enterprise apps > Application policies > ''Restrict max password lifetime'' > On, 180 days or less, applies to all applications. Graph: PATCH https://graph.microsoft.com/v1.0/policies/defaultAppManagementPolicy'
        References       = @(
            @{ 'Name' = 'Configure app management policies'; 'URL' = 'https://learn.microsoft.com/en-us/graph/api/resources/tenantappmanagementpolicy' },
            @{ 'Name' = 'Manage app authentication method policies'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-app-management-policies' }
        )
    }
    return $inspectorobject
}

function Audit-CISM7Az5154
{
	try
	{
		$Violation = @()
		$PassValue = $null
		$Policy = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/defaultAppManagementPolicy' -OutputType PSObject -ErrorAction Stop
		Save-M365SATEvidence -Name 'CISM7Az5154-DefaultAppManagementPolicy' -InputObject $Policy
		$MaxLifetime = New-TimeSpan -Days 180
		if ($Policy.isEnabled -ne $true)
		{
			$Violation += "defaultAppManagementPolicy.isEnabled: $($Policy.isEnabled)"
		}
		foreach ($Scope in @('applicationRestrictions', 'servicePrincipalRestrictions'))
		{
			$Restriction = @($Policy.$Scope.passwordCredentials) | Where-Object { $_.restrictionType -eq 'passwordLifetime' } | Select-Object -First 1
			if ($null -eq $Restriction)
			{
				$Violation += "$($Scope): no passwordLifetime restriction"
				continue
			}
			if ($Restriction.state -ne 'enabled')
			{
				$Violation += "$($Scope): passwordLifetime state is $($Restriction.state)"
			}
			if ([string]::IsNullOrEmpty($Restriction.maxLifetime) -or [System.Xml.XmlConvert]::ToTimeSpan("$($Restriction.maxLifetime)") -gt $MaxLifetime)
			{
				$Violation += "$($Scope): maxLifetime is $($Restriction.maxLifetime) (expected P180D or less)"
			}
			if (-not [string]::IsNullOrEmpty("$($Restriction.restrictForAppsCreatedAfterDateTime)") -and [datetime]$Restriction.restrictForAppsCreatedAfterDateTime -gt (Get-Date))
			{
				$Violation += "$($Scope): restriction only applies to apps created after $($Restriction.restrictForAppsCreatedAfterDateTime)"
			}
		}
		$PassValue = "Client secret lifetime restricted to 180 days or less for applications and service principals"

		# Validation
		if ($Violation.Count -ne 0)
		{
			$endobject = Build-CISM7Az5154 -ReturnedValue ($Violation) -Status "FAIL" -RiskScore "6" -RiskRating "Medium"
			return $endobject
		}
		else
		{
			$endobject = Build-CISM7Az5154 -ReturnedValue ($PassValue) -Status "PASS" -RiskScore "0" -RiskRating "None"
			return $endobject
		}
	}
	catch
	{
		$endobject = Build-CISM7Az5154 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISM7Az5154
