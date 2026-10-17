# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

M365SAT — PowerShell (5.1 and 7) security assessment tool for Microsoft 365 and Azure tenants. Runs ~270 "inspector" scripts mapped to CIS Benchmarks (M365 and Azure) and produces an HTML or CSV report. There is no build step and no linter config. Offline behaviour tests for inspectors live in `tests/` (see below).

## Running

Requires the external modules: `Az`, `ExchangeOnlineManagement` (3.6.0 recommended on Windows due to WAM issues), `Microsoft.Online.SharePoint.PowerShell` (Windows) or `PnP.PowerShell` (Linux), `Microsoft.Graph`, `Microsoft.Graph.Beta`, `MicrosoftTeams`, `PoShLog`. Module is `#Requires -RunAsAdministrator`.

```powershell
# Option A: edit $ScriptConfig at the top of the script, then run it (self-elevates on Windows)
./M365SATTester.ps1

# Option B: import and call directly
Import-Module ./M365SAT.psd1
Get-M365SATReport -OutPath ./out -Username admin@tenant.onmicrosoft.com `
  -EnvironmentType M365 -Modules Exchange -LicenseMode E3 -LicenseLevel L1 `
  -reportType HTML -LocalMode -SkipChecks
```

To exercise a single inspector, narrow `-EnvironmentType`/`-Modules`/`-LicenseMode`/`-LicenseLevel` to its folder, or, after connecting (`-SkipLogin` assumes existing sessions), invoke the inspector file directly: it ends with `return Audit-<UUID>` and returns the finding object.

Offline tests (no tenant needed; mock `Invoke-MgGraphRequest` and Exchange cmdlets, assert PASS/FAIL/UNKNOWN per fixture):

```bash
pwsh -NoProfile -File ./tests/Invoke-InspectorMockTests.ps1               # all cases
pwsh -NoProfile -File ./tests/Invoke-InspectorMockTests.ps1 -Filter CISM7Az52*   # one inspector family
```

Add a PASS and a FAIL case to `$Cases` for every new inspector. Syntax-only check for any file: `[System.Management.Automation.Language.Parser]::ParseFile(...)`.

`M365SATConnectionTester.ps1` tests connectivity to each service without running inspectors.

## Architecture

**Entry point**: `M365SAT.psm1` → `Get-M365SATReport`. It dot-sources everything in `core/` and `modules/welcome/` at call time (functions are not loaded at import), then runs this pipeline:

1. Unless `-SkipChecks`: `Check-M365SATUpdates`, `Check-M365SATModules` (installs missing), `Update-M365SATModules`, `Check-M365SATModuleDuplicates` (removes older versions). These modify the user's installed modules — use `-SkipChecks` during development.
2. Unless `-SkipLogin`: `Connect-M365SAT` (`core/Connect-M365SAT.ps1`) authenticates per module via `core/m365connectors/*`, honouring `-Environment` (Default/USGovGCCHigh/USGovDoD/Germany/China), and returns the tenant org name. Graph is authenticated first because Teams depends on it. On PS7, the SharePoint module is loaded with `-UseWindowsPowerShell`; on Linux, PnP is used instead.
3. Inspector discovery (`core/Get-M365SATChecks.ps1`):
   - `-LocalMode` → `Get-M365SATLocalChecks` reads the repo's `inspectors/` folder.
   - Without `-LocalMode` → `Get-M365SATChecks` **deletes `inspectors/` and replaces it** with a download of `Karmakstylez/M365SAT-Inspectors` (production branch). Always pass `-LocalMode` when testing local inspector changes, or your edits are wiped.
4. Execution (`core/Invoke-M365SATChecks.ps1`): each inspector path is run with `Invoke-Expression` in the caller's scope (so inspectors see variables such as `$OutPath`). Findings are collected into an object `{Findings, StartDate, EndDate, Inspectors, InspectorsCount}`.
5. Report: `core/Get-M365SATHTMLReport.ps1` (Bootstrap/FontAwesome HTML, the only fully working format) or `core/Get-M365SATCSVReport.ps1`. XML/CSMS fall back to HTML.
6. `Disconnect-M365SAT`, cleanup, `Close-Logger`.

Logging uses PoShLog (`core/Invoke-M365SATLogger.ps1`); inspectors call `Write-WarningLog` / `Write-ErrorLog`. Logs go to `log/`.

## Inspectors

Folder layout drives selection — the path segments must match the parameter values exactly:

- M365: `inspectors/M365/<Module>/<E3|E5>/<L1|L2>/*.ps1` where `<Module>` ∈ `Azure, Exchange, Office365, Sharepoint, Teams`
- Azure: `inspectors/AZURE/<L1|L2>/*.ps1` (no license mode)
- Custom: `inspectors/CUSTOM/<Module>/<E3|E5>/<L1|L2>/*.ps1` (`-EnvironmentType CUSTOM`), naming `CSTM-<Az|Ex|O365|Sp|Tms><NNN>.ps1`

File name = UUID (e.g. `CISMEx122.ps1`, `CISAz2010.ps1`). Each inspector is self-contained and follows a fixed shape:

- `Build-<UUID>` creates a PSObject with required fields: `UUID, ID, Title, ProductFamily, DefaultValue, ExpectedValue, ReturnedValue, Status, RiskScore, RiskRating, Description, Impact, Remediation, References` (array of `@{Name; URL}`). The report depends on all of them.
- `Audit-<UUID>` performs the check inside `try/catch`; returns `Status` `FAIL` (with RiskScore/RiskRating), `PASS` (`RiskScore "0"`, `RiskRating "None"`), or `UNKNOWN` from the `catch` with PoShLog error logging.
- The file's last line is `return Audit-<UUID>` — the function name must match exactly, or the inspector returns nothing.
- Helpers are duplicated per file rather than shared (e.g. `Invoke-MultiMicrosoftAPI`, which calls internal Azure portal APIs such as `main.iam.ad.ext.azure.com`).

Use an existing inspector in the same folder as the template; the README section 5.1.1 shows the canonical skeleton.

CIS M365 v7.0.0 inspectors use the `CISM7<Area><ID>` UUID/file name (e.g. `CISM7Az52212`, `CISM7Ex655`, `CISM7Int41` for Intune) because v7 renumbered controls and the v4 names (`CISMAz5228`, …) already exist with different meanings. They call Graph through `Invoke-MgGraphRequest -OutputType PSObject` (with a local paging helper) instead of the `Get-Mg*` cmdlets, and write raw evidence as JSON to `$OutPath`. `ProductFamily` must be one of the values the HTML report groups by (`Microsoft Azure`, `Microsoft Exchange`, `Microsoft Office 365`, `Microsoft SharePoint`, `Microsoft Teams`); Intune checks use `Microsoft Azure`. New Graph permissions must also be added to the scope lists in `core/m365connectors/Connect-MicrosoftGraph.ps1`.

Module/connection coupling: Graph is only connected for `-Modules` Teams/Graph/Exchange/SecurityCompliance/Sharepoint or All, and Security & Compliance (`Get-DlpCompliancePolicy`, …) only with `-Modules All`.

## CIS coverage

`docs/CIS-GAP-v7.md` maps every inspector to CIS M365 v7.0.0 / Azure v6.0.0 (new controls to build, IDs to renumber, Azure identity controls relocated into M365, obsolete inspectors). Regenerate with `tools/cis-gap/run.sh`; requirement data comes from Prowler's compliance JSON. Manual mapping corrections go in `MANUAL` in `tools/cis-gap/gap.py`, control summaries/priorities in `NEW` in `tools/cis-gap/report.py`.

## Conventions

- Code must run on Windows PowerShell 5.1 and PowerShell 7 (Windows/Linux/macOS). Branch on `$IsWindows` / `$IsLinux` / `$IsMac` when touching filesystem paths or SharePoint connectivity.
- Public exports are declared in `M365SAT.psd1` (`FunctionsToExport`); bump `ModuleVersion` there and the version header in `M365SAT.psm1` together, and record changes in `CHANGELOG.md`.
- Upstream is `Karmakstylez/M365SAT`; inspectors are also published separately in `Karmakstylez/M365SAT-Inspectors`.
