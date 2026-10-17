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

function Test-M365SATBlockAllPolicy
{
	param ($Policy)
	return ($Policy.state -eq 'enabled') -and
	(@($Policy.conditions.users.includeUsers) -contains 'All') -and
	(@($Policy.conditions.applications.includeApplications) -contains 'All') -and
	(@($Policy.grantControls.builtInControls) -contains 'block')
}

function Build-CISM7Az52217
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISM7Az52217"
        ID               = "5.2.2.17"
        Title            = '(L1) Ensure a Conditional Access policy blocks authentication transfer'
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = 'No policy'
        ExpectedValue    = 'Enabled policy: all users, all resources, authentication flow ''Authentication transfer'', Block'
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = 'Authentication transfer moves a signed-in state from one device to another, for example by scanning a QR code in Outlook desktop. It can let a session reach an unmanaged device without a fresh, policy-evaluated sign-in.'
        Impact           = 'Users can no longer move a session to mobile by QR code and must sign in on the second device directly.'
        Remediation      = 'Entra admin center > Conditional Access > New policy: Users = All users (exclude break-glass), Target resources = All resources, Conditions > Authentication flows = Authentication transfer, Grant = Block access, Enable policy = On.'
        References       = @(
            @{ 'Name' = 'Block authentication flows with Conditional Access'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-authentication-flows' },
            @{ 'Name' = 'Authentication flows condition'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-authentication-flows' }
        )
    }
    return $inspectorobject
}

function Audit-CISM7Az52217
{
	try
	{
		$Violation = @()
		$PassValue = $null
		$Policies = Get-M365SATGraphCollection -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'
		$FlowPolicies = @($Policies | Where-Object { "$($_.conditions.authenticationFlows.transferMethods)" -match 'authenticationTransfer' })
		Save-M365SATEvidence -Name 'CISM7Az52217-AuthenticationTransferPolicies' -InputObject $FlowPolicies
		$Compliant = @($FlowPolicies | Where-Object { Test-M365SATBlockAllPolicy -Policy $_ })
		if ($Compliant.Count -eq 0)
		{
			$Violation += "No enabled Conditional Access policy blocks authentication transfer for all users and all resources"
			foreach ($Policy in $FlowPolicies) { $Violation += "Non-compliant authentication transfer policy: $($Policy.displayName) (state: $($Policy.state))" }
		}
		$PassValue = "Compliant policy: $(($Compliant.displayName) -join ', ')"

		# Validation
		if ($Violation.Count -ne 0)
		{
			$endobject = Build-CISM7Az52217 -ReturnedValue ($Violation) -Status "FAIL" -RiskScore "5" -RiskRating "Medium"
			return $endobject
		}
		else
		{
			$endobject = Build-CISM7Az52217 -ReturnedValue ($PassValue) -Status "PASS" -RiskScore "0" -RiskRating "None"
			return $endobject
		}
	}
	catch
	{
		$endobject = Build-CISM7Az52217 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISM7Az52217
