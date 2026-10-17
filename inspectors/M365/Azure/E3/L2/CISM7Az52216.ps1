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

function Build-CISM7Az52216
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISM7Az52216"
        ID               = "5.2.2.16"
        Title            = '(L2) Ensure a Conditional Access policy requires token protection for sign-in sessions'
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = 'No policy'
        ExpectedValue    = 'Enabled policy: Exchange, SharePoint and Teams, Windows, mobile apps and desktop clients, token protection required'
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = 'Token theft (infostealers, adversary-in-the-middle kits) lets attackers replay session tokens from another device and bypass MFA. Token protection binds sign-in session tokens to the device that requested them.'
        Impact           = 'Unsupported clients and devices that are not Entra registered or joined are denied for the targeted apps. Pilot with report-only mode first; licensing is Entra ID P1.'
        Remediation      = 'Entra admin center > Conditional Access > New policy: Users = target users, Target resources = Office 365 Exchange Online, Office 365 SharePoint Online, Microsoft Teams Services, Conditions > Device platforms = Windows, Client apps = Mobile apps and desktop clients, Session = Require token protection for sign-in sessions, Enable policy = On.'
        References       = @(
            @{ 'Name' = 'Token protection in Conditional Access'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-token-protection' },
            @{ 'Name' = 'Require token protection policy'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-token-protection' }
        )
    }
    return $inspectorobject
}

function Audit-CISM7Az52216
{
	try
	{
		$Violation = @()
		$PassValue = $null
		$RequiredApps = @(
			'00000002-0000-0ff1-ce00-000000000000', # Office 365 Exchange Online
			'00000003-0000-0ff1-ce00-000000000000', # Office 365 SharePoint Online
			'cc15fd57-2c6c-4117-a88c-83b1d56b4bbe'  # Microsoft Teams Services
		)
		$Policies = Get-M365SATGraphCollection -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'
		$TokenPolicies = @($Policies | Where-Object { $_.sessionControls.secureSignInSession.isEnabled -eq $true })
		Save-M365SATEvidence -Name 'CISM7Az52216-TokenProtectionPolicies' -InputObject $TokenPolicies
		$Compliant = @($TokenPolicies | Where-Object {
				$Policy = $_
				$Users = $Policy.conditions.users
				$HasUsers = (@($Users.includeUsers | Where-Object { $_ -ne 'None' }).Count + @($Users.includeGroups).Count + @($Users.includeRoles).Count) -gt 0
				$Apps = @($Policy.conditions.applications.includeApplications)
				$HasApps = @($RequiredApps | Where-Object { $Apps -notcontains $_ }).Count -eq 0
				($Policy.state -eq 'enabled') -and $HasUsers -and $HasApps -and
				(@($Policy.conditions.platforms.includePlatforms) -contains 'windows') -and
				(@($Policy.conditions.clientAppTypes).Count -eq 1) -and
				(@($Policy.conditions.clientAppTypes) -contains 'mobileAppsAndDesktopClients')
			})
		if ($Compliant.Count -eq 0)
		{
			$Violation += "No enabled Conditional Access policy requires token protection for Exchange Online, SharePoint Online and Teams on Windows desktop clients"
			foreach ($Policy in $TokenPolicies) { $Violation += "Non-compliant token protection policy: $($Policy.displayName) (state: $($Policy.state))" }
		}
		$PassValue = "Compliant policy: $(($Compliant.displayName) -join ', ')"

		# Validation
		if ($Violation.Count -ne 0)
		{
			$endobject = Build-CISM7Az52216 -ReturnedValue ($Violation) -Status "FAIL" -RiskScore "6" -RiskRating "Medium"
			return $endobject
		}
		else
		{
			$endobject = Build-CISM7Az52216 -ReturnedValue ($PassValue) -Status "PASS" -RiskScore "0" -RiskRating "None"
			return $endobject
		}
	}
	catch
	{
		$endobject = Build-CISM7Az52216 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISM7Az52216
