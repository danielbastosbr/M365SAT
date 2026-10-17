<#
	.SYNOPSIS
		Offline behaviour tests for inspectors: mocks Microsoft Graph / Exchange cmdlets and asserts the returned Status.

	.EXAMPLE
		pwsh -NoProfile -File ./tests/Invoke-InspectorMockTests.ps1
		pwsh -NoProfile -File ./tests/Invoke-InspectorMockTests.ps1 -Filter CISM7Az52*
#>
param (
	[string]$Filter = '*'
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$OutPath = Join-Path ([System.IO.Path]::GetTempPath()) "m365sat-mocktests-$PID"
New-Item -ItemType Directory -Force -Path $OutPath | Out-Null

# ---- Mocks ------------------------------------------------------------------------------------
$global:GraphFixtures = @{}
$global:CmdletFixtures = @{}
$global:LoggedErrors = @()

function global:Write-WarningLog { param($MessageTemplate, $PropertyValues) }
function global:Write-ErrorLog { param($MessageTemplate, $ErrorRecord, $PropertyValues) $global:LoggedErrors += "$($ErrorRecord.Exception.Message)" }
function global:Import-Module { param([Parameter(ValueFromRemainingArguments = $true)]$Args) }

function global:Invoke-MgGraphRequest
{
	param ($Method, $Uri, $OutputType, $ErrorAction)
	$key = ($global:GraphFixtures.Keys | Where-Object { $Uri -like "$_*" } | Sort-Object Length -Descending | Select-Object -First 1)
	if (-not $key) { throw "No Graph fixture for $Uri" }
	return ($global:GraphFixtures[$key] | ConvertTo-Json -Depth 20 | ConvertFrom-Json)
}
foreach ($cmd in @('Get-TransportRule', 'Get-OrganizationConfig', 'Get-DlpCompliancePolicy'))
{
	Set-Item -Path "function:global:$cmd" -Value ([scriptblock]::Create("param([Parameter(ValueFromRemainingArguments = `$true)]`$a) `$global:CmdletFixtures['$cmd'] | ForEach-Object { [pscustomobject]`$_ }"))
}

# ---- Fixture helpers --------------------------------------------------------------------------
function CA
{
	param ([hashtable]$Conditions = @{}, [hashtable]$Grant = @{}, [hashtable]$Session = @{}, [string]$State = 'enabled', [string]$Name = 'policy')
	$base = @{ users = @{ includeUsers = @('All'); excludeUsers = @('breakglass') }; applications = @{ includeApplications = @('All'); excludeApplications = @() } }
	foreach ($k in $Conditions.Keys) { $base[$k] = $Conditions[$k] }
	return @{ displayName = $Name; state = $State; conditions = $base; grantControls = $Grant; sessionControls = $Session }
}
$CAUri = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'
$DRP = 'https://graph.microsoft.com/beta/policies/deviceRegistrationPolicy'
$DRP1 = 'https://graph.microsoft.com/v1.0/policies/deviceRegistrationPolicy'
$Block = @{ builtInControls = @('block'); operator = 'OR' }
$Lifetime = { param($d, $state = 'enabled') @{ passwordCredentials = @(@{ restrictionType = 'passwordLifetime'; state = $state; maxLifetime = $d; restrictForAppsCreatedAfterDateTime = '0001-01-01T00:00:00Z' }) } }
$Tp = @{ users = @{ includeUsers = @('All') }; applications = @{ includeApplications = @('00000002-0000-0ff1-ce00-000000000000', '00000003-0000-0ff1-ce00-000000000000', 'cc15fd57-2c6c-4117-a88c-83b1d56b4bbe') }; platforms = @{ includePlatforms = @('windows') }; clientAppTypes = @('mobileAppsAndDesktopClients') }
$Roles = 'https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions'
$Inst = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances'
$PrivRoles = @{ value = @(@{ id = '62e90394-69f5-4237-9190-012177145e10'; displayName = 'Global Administrator' }, @{ id = 'e8611ab8-c189-46e8-94e1-60213ab1f814'; displayName = 'Privileged Role Administrator' }) }
$User = { param($n) @{ '@odata.type' = '#microsoft.graph.user'; userPrincipalName = $n } }

# ---- Cases: inspector, name, expected status, graph fixtures, cmdlet fixtures -------------------
$Cases = @(
	@{ I = 'CISM7Int41'; N = 'secureByDefault true'; E = 'PASS'; G = @{ 'https://graph.microsoft.com/v1.0/deviceManagement/settings' = @{ secureByDefault = $true } } }
	@{ I = 'CISM7Int41'; N = 'secureByDefault false'; E = 'FAIL'; G = @{ 'https://graph.microsoft.com/v1.0/deviceManagement/settings' = @{ secureByDefault = $false } } }
	@{ I = 'CISM7Int42'; N = 'per-platform all blocked'; E = 'PASS'; G = @{ 'https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations' = @{ value = @(
					@{ '@odata.type' = '#microsoft.graph.deviceEnrollmentPlatformRestrictionConfiguration'; priority = 0; platformType = 'windows'; platformRestriction = @{ platformBlocked = $false; personalDeviceEnrollmentBlocked = $true } },
					@{ '@odata.type' = '#microsoft.graph.deviceEnrollmentPlatformRestrictionConfiguration'; priority = 0; platformType = 'ios'; platformRestriction = @{ platformBlocked = $true; personalDeviceEnrollmentBlocked = $false } },
					@{ '@odata.type' = '#microsoft.graph.deviceEnrollmentPlatformRestrictionConfiguration'; priority = 1; platformType = 'android'; platformRestriction = @{ platformBlocked = $false; personalDeviceEnrollmentBlocked = $false } }) } } }
	@{ I = 'CISM7Int42'; N = 'legacy windows allowed'; E = 'FAIL'; G = @{ 'https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations' = @{ value = @(
					@{ '@odata.type' = '#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration'; id = 'x_DefaultPlatformRestrictions'; priority = 0
						windowsRestriction = @{ platformBlocked = $false; personalDeviceEnrollmentBlocked = $false }; iosRestriction = @{ personalDeviceEnrollmentBlocked = $true } }) } } }
	@{ I = 'CISM7Int42'; N = 'no default policy'; E = 'UNKNOWN'; G = @{ 'https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations' = @{ value = @() } } }
	@{ I = 'CISM7Az5143'; N = 'global admins off'; E = 'PASS'; G = @{ $DRP = @{ azureADJoin = @{ localAdmins = @{ enableGlobalAdmins = $false } } } } }
	@{ I = 'CISM7Az5143'; N = 'global admins on'; E = 'FAIL'; G = @{ $DRP = @{ azureADJoin = @{ localAdmins = @{ enableGlobalAdmins = $true } } } } }
	@{ I = 'CISM7Az5144'; N = 'registering users none'; E = 'PASS'; G = @{ $DRP = @{ azureADJoin = @{ localAdmins = @{ registeringUsers = @{ '@odata.type' = '#microsoft.graph.noDeviceRegistrationMembership' } } } } } }
	@{ I = 'CISM7Az5144'; N = 'registering users all'; E = 'FAIL'; G = @{ $DRP = @{ azureADJoin = @{ localAdmins = @{ registeringUsers = @{ '@odata.type' = '#microsoft.graph.allDeviceRegistrationMembership' } } } } } }
	@{ I = 'CISM7Az5145'; N = 'laps on'; E = 'PASS'; G = @{ $DRP1 = @{ localAdminPassword = @{ isEnabled = $true } } } }
	@{ I = 'CISM7Az5145'; N = 'laps off'; E = 'FAIL'; G = @{ $DRP1 = @{ localAdminPassword = @{ isEnabled = $false } } } }
	@{ I = 'CISM7Az5154'; N = '90 days both scopes'; E = 'PASS'; G = @{ 'https://graph.microsoft.com/v1.0/policies/defaultAppManagementPolicy' = @{ isEnabled = $true; applicationRestrictions = (& $Lifetime 'P90D'); servicePrincipalRestrictions = (& $Lifetime 'P180D') } } }
	@{ I = 'CISM7Az5154'; N = '365 days on SPs'; E = 'FAIL'; G = @{ 'https://graph.microsoft.com/v1.0/policies/defaultAppManagementPolicy' = @{ isEnabled = $true; applicationRestrictions = (& $Lifetime 'P90D'); servicePrincipalRestrictions = (& $Lifetime 'P365D') } } }
	@{ I = 'CISM7Az5154'; N = 'policy disabled'; E = 'FAIL'; G = @{ 'https://graph.microsoft.com/v1.0/policies/defaultAppManagementPolicy' = @{ isEnabled = $false; applicationRestrictions = @{}; servicePrincipalRestrictions = @{} } } }
	@{ I = 'CISM7Az5228'; N = 'risk block policy'; E = 'PASS'; G = @{ $CAUri = @{ value = @((CA -Conditions @{ signInRiskLevels = @('high', 'medium') } -Grant $Block)) } } }
	@{ I = 'CISM7Az5228'; N = 'only high risk'; E = 'FAIL'; G = @{ $CAUri = @{ value = @((CA -Conditions @{ signInRiskLevels = @('high') } -Grant $Block)) } } }
	@{ I = 'CISM7Az5228'; N = 'report-only'; E = 'FAIL'; G = @{ $CAUri = @{ value = @((CA -State 'enabledForReportingButNotEnforced' -Conditions @{ signInRiskLevels = @('high', 'medium') } -Grant $Block)) } } }
	@{ I = 'CISM7Az52212'; N = 'device code blocked'; E = 'PASS'; G = @{ $CAUri = @{ value = @((CA -Conditions @{ authenticationFlows = @{ transferMethods = 'deviceCodeFlow,authenticationTransfer' } } -Grant $Block)) } } }
	@{ I = 'CISM7Az52212'; N = 'no policy'; E = 'FAIL'; G = @{ $CAUri = @{ value = @() } } }
	@{ I = 'CISM7Az52212'; N = 'scoped to one app'; E = 'FAIL'; G = @{ $CAUri = @{ value = @((CA -Conditions @{ applications = @{ includeApplications = @('00000002-0000-0ff1-ce00-000000000000') }; authenticationFlows = @{ transferMethods = 'deviceCodeFlow' } } -Grant $Block)) } } }
	@{ I = 'CISM7Az52216'; N = 'token protection'; E = 'PASS'; G = @{ $CAUri = @{ value = @((CA -Conditions $Tp -Session @{ secureSignInSession = @{ isEnabled = $true } })) } } }
	@{ I = 'CISM7Az52216'; N = 'missing Teams'; E = 'FAIL'; G = @{ $CAUri = @{ value = @((CA -Conditions @{ users = $Tp.users; platforms = $Tp.platforms; clientAppTypes = $Tp.clientAppTypes; applications = @{ includeApplications = @('00000002-0000-0ff1-ce00-000000000000') } } -Session @{ secureSignInSession = @{ isEnabled = $true } })) } } }
	@{ I = 'CISM7Az52217'; N = 'auth transfer blocked'; E = 'PASS'; G = @{ $CAUri = @{ value = @((CA -Conditions @{ authenticationFlows = @{ transferMethods = 'authenticationTransfer' } } -Grant $Block)) } } }
	@{ I = 'CISM7Az52217'; N = 'device code only'; E = 'FAIL'; G = @{ $CAUri = @{ value = @((CA -Conditions @{ authenticationFlows = @{ transferMethods = 'deviceCodeFlow' } } -Grant $Block)) } } }
	@{ I = 'CISM7Az531'; N = 'pim activated + 2 breakglass'; E = 'PASS'; G = @{ $Roles = $PrivRoles; $Inst = @{ value = @(
					@{ roleDefinitionId = '62e90394-69f5-4237-9190-012177145e10'; assignmentType = 'Assigned'; principal = (& $User 'bg1@x') },
					@{ roleDefinitionId = '62e90394-69f5-4237-9190-012177145e10'; assignmentType = 'Assigned'; principal = (& $User 'bg2@x') },
					@{ roleDefinitionId = 'e8611ab8-c189-46e8-94e1-60213ab1f814'; assignmentType = 'Activated'; principal = (& $User 'admin@x') },
					@{ roleDefinitionId = 'other-role'; assignmentType = 'Assigned'; principal = (& $User 'helpdesk@x') }) } } }
	@{ I = 'CISM7Az531'; N = 'permanent PRA'; E = 'FAIL'; G = @{ $Roles = $PrivRoles; $Inst = @{ value = @(
					@{ roleDefinitionId = 'e8611ab8-c189-46e8-94e1-60213ab1f814'; assignmentType = 'Assigned'; principal = (& $User 'admin@x') }) } } }
	@{ I = 'CISM7Az531'; N = '3 permanent GAs'; E = 'FAIL'; G = @{ $Roles = $PrivRoles; $Inst = @{ value = @(1..3 | ForEach-Object { @{ roleDefinitionId = '62e90394-69f5-4237-9190-012177145e10'; assignmentType = 'Assigned'; principal = (& $User "ga$_@x") } }) } } }
	@{ I = 'CISM7Az531'; N = 'SP without end date'; E = 'FAIL'; G = @{ $Roles = $PrivRoles; $Inst = @{ value = @(
					@{ roleDefinitionId = 'e8611ab8-c189-46e8-94e1-60213ab1f814'; assignmentType = 'Assigned'; endDateTime = $null; principal = @{ '@odata.type' = '#microsoft.graph.servicePrincipal'; displayName = 'app' } }) } } }
	@{ I = 'CISM7Ex323'; N = 'copilot policy enabled'; E = 'PASS'; C = @{ 'Get-DlpCompliancePolicy' = @(@{ Name = 'Copilot'; Mode = 'Enable'; EnforcementPlanes = @('CopilotExperiences') }, @{ Name = 'Mail'; Mode = 'Enable'; EnforcementPlanes = @('Exchange') }) } }
	@{ I = 'CISM7Ex323'; N = 'copilot policy in test mode'; E = 'FAIL'; C = @{ 'Get-DlpCompliancePolicy' = @(@{ Name = 'Copilot'; Mode = 'TestWithNotifications'; EnforcementPlanes = @('CopilotExperiences') }) } }
	@{ I = 'CISM7Ex323'; N = 'no copilot policy'; E = 'FAIL'; C = @{ 'Get-DlpCompliancePolicy' = @(@{ Name = 'Mail'; Mode = 'Enable'; EnforcementPlanes = @('Exchange') }) } }
	@{ I = 'CISM7Ex622'; N = 'no bypass rules'; E = 'PASS'; C = @{ 'Get-TransportRule' = @(@{ Name = 'disclaimer'; SetSCL = $null; SenderDomainIs = $null }, @{ Name = 'ip allow'; SetSCL = -1; SenderDomainIs = $null }) } }
	@{ I = 'CISM7Ex622'; N = 'domain bypass rule'; E = 'FAIL'; C = @{ 'Get-TransportRule' = @(@{ Name = 'partner'; SetSCL = -1; SenderDomainIs = @('partner.com') }) } }
	@{ I = 'CISM7Ex655'; N = 'direct send rejected'; E = 'PASS'; C = @{ 'Get-OrganizationConfig' = @(@{ Name = 'org'; RejectDirectSend = $true }) } }
	@{ I = 'CISM7Ex655'; N = 'direct send allowed'; E = 'FAIL'; C = @{ 'Get-OrganizationConfig' = @(@{ Name = 'org'; RejectDirectSend = $false }) } }
)

# ---- Runner -----------------------------------------------------------------------------------
$Files = @{}
Get-ChildItem -Path (Join-Path $Root 'inspectors') -Recurse -Filter '*.ps1' | ForEach-Object { $Files[$_.BaseName] = $_.FullName }
$Failed = 0
$Run = 0
foreach ($Case in ($Cases | Where-Object { $_.I -like $Filter }))
{
	$Run++
	$global:GraphFixtures = if ($Case.G) { $Case.G } else { @{} }
	$global:CmdletFixtures = if ($Case.C) { $Case.C } else { @{} }
	$global:LoggedErrors = @()
	$Result = & $Files[$Case.I]
	$Ok = ($Result.Status -eq $Case.E) -and ($Result.UUID -eq $Case.I)
	if (-not $Ok) { $Failed++ }
	$Detail = if ($global:LoggedErrors) { " error: $($global:LoggedErrors -join '; ')" } else { '' }
	Write-Host ("[{0}] {1,-14} {2,-30} expected {3,-7} got {4,-7} :: {5}{6}" -f ($(if ($Ok) { 'PASS' } else { 'FAIL' })), $Case.I, $Case.N, $Case.E, $Result.Status, (@($Result.ReturnedValue) -join ' | '), $Detail) -ForegroundColor ($(if ($Ok) { 'Green' } else { 'Red' }))
}
Remove-Item -Recurse -Force $OutPath -ErrorAction SilentlyContinue
Write-Host "$($Run - $Failed)/$Run cases passed"
exit $Failed
