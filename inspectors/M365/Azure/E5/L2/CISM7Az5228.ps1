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

function Build-CISM7Az5228
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISM7Az5228"
        ID               = "5.2.2.8"
        Title            = '(L2) Ensure a Conditional Access policy blocks medium and high sign-in risk'
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = 'No policy'
        ExpectedValue    = 'Enabled policy: all users, all resources, sign-in risk High+Medium, Block'
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = 'Entra ID Protection scores each sign-in for risk (anomalous token, unfamiliar location, password spray). Blocking medium and high risk sign-ins stops most credential-based account takeovers before a session is issued.'
        Impact           = 'Users whose sign-ins are flagged medium or high risk are blocked and need an administrator or a self-remediation flow to regain access. Requires Entra ID P2.'
        Remediation      = 'Entra admin center > Conditional Access > New policy: Users = All users (exclude break-glass), Target resources = All resources, Conditions > Sign-in risk = High, Medium, Grant = Block access, Enable policy = On.'
        References       = @(
            @{ 'Name' = 'Risk-based access policies'; 'URL' = 'https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-policies' },
            @{ 'Name' = 'Require MFA for elevated sign-in risk'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-risk-based-sign-in' }
        )
    }
    return $inspectorobject
}

function Audit-CISM7Az5228
{
	try
	{
		$Violation = @()
		$PassValue = $null
		$Policies = Get-M365SATGraphCollection -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'
		$RiskPolicies = @($Policies | Where-Object { @($_.conditions.signInRiskLevels).Count -gt 0 })
		Save-M365SATEvidence -Name 'CISM7Az5228-SignInRiskPolicies' -InputObject $RiskPolicies
		$Compliant = @($RiskPolicies | Where-Object {
				($_.state -eq 'enabled') -and
				(@($_.conditions.users.includeUsers) -contains 'All') -and
				(@($_.conditions.applications.includeApplications) -contains 'All') -and
				(@($_.conditions.applications.excludeApplications).Count -eq 0) -and
				(@($_.conditions.signInRiskLevels) -contains 'high') -and
				(@($_.conditions.signInRiskLevels) -contains 'medium') -and
				(@($_.grantControls.builtInControls) -contains 'block')
			})
		if ($Compliant.Count -eq 0)
		{
			$Violation += "No enabled Conditional Access policy blocks medium and high sign-in risk for all users and all resources"
			foreach ($Policy in $RiskPolicies) { $Violation += "Non-compliant sign-in risk policy: $($Policy.displayName) (state: $($Policy.state))" }
		}
		$PassValue = "Compliant policy: $(($Compliant.displayName) -join ', ')"

		# Validation
		if ($Violation.Count -ne 0)
		{
			$endobject = Build-CISM7Az5228 -ReturnedValue ($Violation) -Status "FAIL" -RiskScore "8" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISM7Az5228 -ReturnedValue ($PassValue) -Status "PASS" -RiskScore "0" -RiskRating "None"
			return $endobject
		}
	}
	catch
	{
		$endobject = Build-CISM7Az5228 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISM7Az5228
