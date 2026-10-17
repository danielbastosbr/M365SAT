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

function Build-CISM7Az531
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISM7Az531"
        ID               = "5.3.1"
        Title            = '(L2) Ensure privileged roles are activated just-in-time through Privileged Identity Management'
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = 'All privileged role assignments are permanent and active'
        ExpectedValue    = 'Users/groups: Activated (max. 2 permanent Global Administrators for break-glass); service principals: time-bound'
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = 'Standing privileged access means every compromised admin account is immediately a tenant-level compromise. PIM turns privileged roles into time-bound activations with justification, approval and audit.'
        Impact           = 'Administrators must activate roles before use. Requires Entra ID P2 (or Entra ID Governance). Permanent Global Administrator assignments must be limited to the documented break-glass accounts.'
        Remediation      = 'Entra admin center > Identity Governance > Privileged Identity Management > Microsoft Entra roles > convert permanent active assignments of privileged roles to eligible assignments. Keep at most two permanent Global Administrator break-glass accounts and set end dates on service principal assignments.'
        References       = @(
            @{ 'Name' = 'What is Privileged Identity Management?'; 'URL' = 'https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure' },
            @{ 'Name' = 'Assign Microsoft Entra roles in PIM'; 'URL' = 'https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-add-role-to-user' },
            @{ 'Name' = 'Privileged roles and permissions'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/privileged-roles-permissions' }
        )
    }
    return $inspectorobject
}

function Audit-CISM7Az531
{
	try
	{
		$Violation = @()
		$PassValue = $null
		$GlobalAdminRoleId = '62e90394-69f5-4237-9190-012177145e10'
		$PrivilegedRoles = Get-M365SATGraphCollection -Uri 'https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions?$filter=isPrivileged eq true&$select=id,displayName,isPrivileged'
		$RoleNames = @{}
		foreach ($Role in $PrivilegedRoles) { $RoleNames[$Role.id] = $Role.displayName }
		$Instances = Get-M365SATGraphCollection -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?$expand=principal'
		$Privileged = @($Instances | Where-Object { $RoleNames.ContainsKey($_.roleDefinitionId) })
		Save-M365SATEvidence -Name 'CISM7Az531-PrivilegedRoleAssignments' -InputObject $Privileged
		$PermanentGlobalAdmins = @()
		foreach ($Assignment in $Privileged)
		{
			$PrincipalType = "$($Assignment.principal.'@odata.type')"
			$PrincipalName = if ($Assignment.principal.userPrincipalName) { $Assignment.principal.userPrincipalName } else { $Assignment.principal.displayName }
			$RoleName = $RoleNames[$Assignment.roleDefinitionId]
			if ($PrincipalType -eq '#microsoft.graph.servicePrincipal')
			{
				if ($Assignment.assignmentType -ne 'Assigned' -or [string]::IsNullOrEmpty("$($Assignment.endDateTime)"))
				{
					$Violation += "$RoleName -> service principal $PrincipalName has no end date"
				}
			}
			elseif ($Assignment.assignmentType -ne 'Activated')
			{
				if ($Assignment.roleDefinitionId -eq $GlobalAdminRoleId -and $PrincipalType -eq '#microsoft.graph.user')
				{
					$PermanentGlobalAdmins += $PrincipalName
				}
				else
				{
					$Violation += "$RoleName -> $PrincipalName is permanently assigned (not activated through PIM)"
				}
			}
		}
		if ($PermanentGlobalAdmins.Count -gt 2)
		{
			$Violation += "More than 2 permanent Global Administrators (break-glass maximum): $($PermanentGlobalAdmins -join ', ')"
		}
		$PassValue = "All privileged roles use PIM activation. Permanent Global Administrators (verify they are break-glass accounts): $($PermanentGlobalAdmins -join ', ')"

		# Validation
		if ($Violation.Count -ne 0)
		{
			$endobject = Build-CISM7Az531 -ReturnedValue ($Violation) -Status "FAIL" -RiskScore "8" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISM7Az531 -ReturnedValue ($PassValue) -Status "PASS" -RiskScore "0" -RiskRating "None"
			return $endobject
		}
	}
	catch
	{
		$endobject = Build-CISM7Az531 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISM7Az531
