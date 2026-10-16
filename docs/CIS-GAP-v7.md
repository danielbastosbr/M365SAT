# CIS Gap Analysis — M365 v7.0.0 / Azure v6.0.0

Matriz entre os inspectors do M365SAT (CIS M365 v4.0.0 / Azure v3.0.0) e as versões atuais do CIS.
Fonte dos requisitos: definições de compliance do [Prowler](https://github.com/prowler-cloud/prowler/tree/master/prowler/compliance) (`cis_7.0_m365.json`, `cis_6.0_azure.json`). Este documento não reproduz texto do CIS; confirmar contra o PDF oficial.

Regenerar: `tools/cis-gap/run.sh`. Método de cruzamento: check do Prowler em comum → nome de configuração citado no título → similaridade da descrição → tokens do título → mesmo ID.

## Resumo

| Indicador | Valor |
|---|---|
| Inspectors no repo | 273 |
| Mapeados para v7/v6 | 204 |
| Sem equivalente (obsoletos/removidos) | 69 |
| CIS M365 v7 — controles | 160 |
| CIS M365 v7 — cobertos | 115 (71%) |
| CIS M365 v7 — **a criar** | **45** (A=15, B=15, C=15) |
| CIS Azure v6 — controles / cobertos / a criar | 127 / 76 / 51 |
| Inspectors Azure que migram para o M365 v7 | 15 |
| Inspectors M365 com ID renumerado | 7 |
| Inspectors usando API interna (reescrever p/ Graph) | 22 |
| Mapeamentos de baixa confiança (revisar) | 8 |

Prioridade: **A** = alto impacto de segurança e automatizável via Graph/EXO; **B** = hardening relevante; **C** = baixo risco, nicho ou manual.

## 1. Controles novos — CIS M365 v7 sem inspector

| ID v7 | Controle | Perfil | Tipo | Prior. | Fonte de dados | Check Prowler |
|---|---|---|---|---|---|---|
| 2.2.1 | Monitorar sign-in de contas break-glass com alerta | E5 Level 1 | Manual | A | Graph auditLogs/signIns + alert rule (parcialmente manual) | `—` |
| 3.2.3 | DLP cobrindo Microsoft 365 Copilot (prompts e respostas) | E5 Level 1 | Automated | A | Get-DlpCompliancePolicy (Locations Copilot) | `—` |
| 4.1 | Dispositivo sem compliance policy = não conforme | E3 Level 1 | Automated | A | Graph deviceManagement/settings (secureByDefault) | `intune_device_compliance_policy_unassigned_devices_not_compliant_by_default` |
| 4.2 | Bloquear enrollment de dispositivo pessoal | E3 Level 1 | Automated | A | Graph deviceManagement/deviceEnrollmentConfigurations | `—` |
| 5.1.4.3 | Global Admin não vira admin local no join | E3 Level 1 | Automated | A | Graph policies/deviceRegistrationPolicy | `entra_device_registration_global_admins_not_local_admins` |
| 5.1.4.4 | Usuário que registra não vira admin local | E3 Level 1 | Automated | A | Graph policies/deviceRegistrationPolicy | `entra_device_registration_registering_user_not_local_admin` |
| 5.1.4.5 | Cloud LAPS habilitado | E3 Level 1 | Automated | A | Graph policies/deviceRegistrationPolicy (localAdminPassword) | `entra_device_registration_laps_enabled` |
| 5.1.5.4 | Validade máxima de client secret | E3 Level 1 | Automated | A | Graph policies/defaultAppManagementPolicy | `entra_default_app_management_policy_enabled` |
| 5.2.2.8 | CA bloqueia sign-in de risco médio/alto | E5 Level 2 | Automated | A | Graph identity/conditionalAccess/policies | `entra_conditional_access_policy_block_high_medium_sign_in_risk` |
| 5.2.2.12 | CA bloqueia device code flow | E3 Level 1 | Automated | A | Graph identity/conditionalAccess/policies | `entra_conditional_access_policy_device_code_flow_blocked` |
| 5.2.2.16 | CA com Token Protection | E3 Level 2 | Automated | A | Graph identity/conditionalAccess/policies (sessionControls) | `entra_conditional_access_policy_token_protection_enforced` |
| 5.2.2.17 | CA bloqueia authentication transfer | E3 Level 1 | Automated | A | Graph identity/conditionalAccess/policies (authenticationFlows) | `entra_conditional_access_policy_authentication_transfer_blocked` |
| 5.3.1 | PIM em uso para roles privilegiadas | E5 Level 2 | Automated | A | Graph roleManagement/directory/roleEligibilitySchedules | `—` |
| 6.2.2 | Transport rule não define SCL -1 (bypass de spam) | E3 Level 1 | Automated | A | Get-TransportRule | `exchange_transport_rules_whitelist_disabled` |
| 6.5.5 | Reject Direct Send habilitado | E3 Level 2 | Automated | A | Get-OrganizationConfig (RejectDirectSend) | `exchange_organization_reject_direct_send_enabled` |
| 2.1.15 | Política anti-spam outbound padrão configurada | E3 Level 1 | Automated | B | Get-HostedOutboundSpamFilterPolicy (Default) | `defender_antispam_outbound_policy_configured` |
| 5.1.3.1 | Usuário comum não cria security groups | E3 Level 1 | Automated | B | Graph policies/authorizationPolicy | `entra_policy_default_user_cannot_create_security_groups` |
| 5.1.4.1 | Entra join restrito a usuários selecionados | E3 Level 2 | Automated | B | Graph policies/deviceRegistrationPolicy | `entra_device_registration_join_restricted` |
| 5.1.4.2 | Limite de dispositivos por usuário | E3 Level 1 | Automated | B | Graph policies/deviceRegistrationPolicy | `entra_device_registration_max_devices_per_user_limited` |
| 5.1.4.6 | Usuário não lê chave BitLocker | E3 Level 2 | Automated | B | Graph policies/authorizationPolicy | `entra_policy_default_user_cannot_read_bitlocker_keys` |
| 5.1.5.3 | Bloquear client secrets (só certificado) em apps | E3 Level 2 | Automated | B | Graph policies/defaultAppManagementPolicy | `entra_default_app_management_policy_enabled` |
| 5.1.5.5 | Bloquear secret customizado (definido pelo usuário) | E3 Level 1 | Automated | B | Graph policies/defaultAppManagementPolicy | `entra_default_app_management_policy_enabled` |
| 5.1.5.6 | Validade máxima de certificado de app | E3 Level 1 | Automated | B | Graph policies/defaultAppManagementPolicy | `entra_default_app_management_policy_enabled` |
| 5.2.2.11 | CA: sign-in frequency 'every time' no enrollment Intune | E3 Level 1 | Automated | B | Graph identity/conditionalAccess/policies | `entra_intune_enrollment_sign_in_frequency_every_time` |
| 5.2.2.13 | CA: sign-in frequency para todos os usuários | E3 Level 1 | Automated | B | Graph identity/conditionalAccess/policies | `entra_conditional_access_policy_sign_in_frequency_all_users` |
| 5.2.2.14 | Named locations confiáveis definidas | E3 Level 2 | Automated | B | Graph identity/conditionalAccess/namedLocations | `entra_conditional_access_trusted_named_location_exists` |
| 5.2.3.6 | MFA system-preferred habilitado | E3 Level 1 | Automated | B | Graph policies/authenticationMethodsPolicy | `—` |
| 5.3.5 | PIM: aprovação para Privileged Role Administrator | E5 Level 1 | Automated | B | Graph policies/roleManagementPolicies | `entra_pim_privileged_role_administrator_approval_required` |
| 6.3.2 | OWA sem contas pessoais (Gmail/Outlook.com) | E3 Level 1 | Automated | B | Get-OwaMailboxPolicy | `exchange_owa_mailbox_policy_personal_accounts_disabled` |
| 8.2.4 | Teams bloqueia tenants trial | E3 Level 1 | Automated | B | Get-CsTenantFederationConfiguration | `teams_external_access_trial_tenants_blocked` |
| 1.3.9 | Shared Bookings desabilitado | E3 Level 1 | Automated | C | Get-OrganizationConfig (BookingsEnabled) / Get-OwaMailboxPolicy | `admincenter_shared_bookings_disabled` |
| 2.4.5 | AIR (Automated Investigation & Response) configurado | E5 Level 1 | Manual | C | Manual — Defender portal | `—` |
| 5.2.3.10 | Authenticator Lite desabilitado | E3 Level 1 | Automated | C | Graph policies/authenticationMethodsPolicy/.../microsoftAuthenticator | `—` |
| 9.1.1 | Guest B2B sem acesso ao Fabric | E3 Level 1 | Automated | C | Fabric Admin API admin/tenantsettings | `—` |
| 9.1.2 | Convite de externos via Power BI restrito | E3 Level 1 | Automated | C | Fabric Admin API admin/tenantsettings | `—` |
| 9.1.3 | Guest sem navegação completa | E3 Level 1 | Automated | C | Fabric Admin API admin/tenantsettings | `—` |
| 9.1.4 | Publish to web restrito | E3 Level 1 | Automated | C | Fabric Admin API admin/tenantsettings | `—` |
| 9.1.5 | Visuais R/Python desabilitados | E3 Level 2 | Automated | C | Fabric Admin API admin/tenantsettings | `—` |
| 9.1.6 | Sensitivity labels habilitados no Power BI | E3 Level 1 | Automated | C | Fabric Admin API admin/tenantsettings | `—` |
| 9.1.7 | Links compartilháveis restritos | E3 Level 1 | Automated | C | Fabric Admin API admin/tenantsettings | `—` |
| 9.1.8 | Compartilhamento externo de datasets restrito | E3 Level 1 | Automated | C | Fabric Admin API admin/tenantsettings | `—` |
| 9.1.9 | ResourceKey authentication bloqueada | E3 Level 1 | Automated | C | Fabric Admin API admin/tenantsettings | `—` |
| 9.1.10 | Service principals em APIs Fabric restritos | E3 Level 1 | Automated | C | Fabric Admin API admin/tenantsettings | `—` |
| 9.1.11 | Service principal profiles restritos | E3 Level 1 | Automated | C | Fabric Admin API admin/tenantsettings | `—` |
| 9.1.12 | Service principals em APIs não protegidas restritos | E3 Level 1 | Automated | C | Fabric Admin API admin/tenantsettings | `—` |

Observação: a seção 9 (Power BI / Fabric) não existe no M365SAT. Exige novo conector (Fabric Admin API) e nova pasta `inspectors/M365/PowerBI`.

## 2. Inspectors Azure que passam para o CIS M365 v7

Controles de Entra ID saíram do Azure Benchmark. Mover para `inspectors/M365/Azure/...`, trocar `UUID`/`ID` e o cabeçalho `# Benchmark`.

| Inspector atual | ID v3 | → ID M365 v7 | API interna |
|---|---|---|---|
| CISAz2014 | 2.14 | 5.1.2.2 |  |
| CISAz23 | 2.3 | 5.1.2.3 |  |
| CISAz2017 | 2.17 | 5.1.2.4 | sim |
| CISAz2018 | 2.18 | 5.1.3.2 | sim |
| CISAz2020 | 2.20 | 5.1.3.3 | sim |
| CISAz2021 | 2.21 | 5.1.3.4 |  |
| CISAz2012 | 2.12 | 5.1.5.1 |  |
| CISAz2016 | 2.16 | 5.1.6.3 |  |
| CISAz221 | 2.2.1 | 5.2.2.15 |  |
| CISAz26 | 2.6 | 5.2.3.8 | sim |
| CISAz27 | 2.7 | 5.2.3.9 | sim |
| CISAz25 | 2.5 | 5.2.4.2 | sim |
| CISAz29 | 2.9 | 5.2.4.3 | sim |
| CISAz2010 | 2.10 | 5.2.4.4 | sim |
| CISAz2011 | 2.11 | 5.2.4.5 | sim |

## 3. Inspectors M365 com ID renumerado na v7

Lógica provavelmente válida; atualizar `ID`, título e referência. Revisar audit procedure no PDF.

| Inspector | ID v4 | → ID v7 | Método | API interna |
|---|---|---|---|---|
| CISMAz5228 | 5.2.2.8 | 5.1.2.4 | check |  |
| CISMAz5229 | 5.2.2.9 | 5.2.2.7 | quoted |  |
| CISMAz52210 | 5.2.2.10 | 5.2.2.9 | check |  |
| CISMAz52211 | 5.2.2.11 | 5.2.2.10 | check |  |
| CISMAz531 | 5.3.1 | 5.3.4 | quoted |  |
| CISMEx613 | 6.1.3 | 6.1.2 | check |  |
| CISMEx614 | 6.1.4 | 6.1.3 | check |  |

## 4. Inspectors sem equivalente (candidatos a remover ou mover para benchmark de serviço)

A maioria são controles de serviços Azure (SQL, PostgreSQL single server, App Service, VM) que o CIS tirou do Foundations e passou para benchmarks de serviço específicos. Manter só se o cliente usa esses serviços.

| Inspector | ID | Título atual |
|---|---|---|
| CISAz2026 | 2.26 | (L1) Ensure fewer than 5 users have global administrator assignment |
| CISAz28 | 2.8 | (L1) Ensure that a Custom Bad Password List is set to 'Enforce' for your Organization |
| CISAz3111 | 3.1.1.1 | (L1) Ensure that Auto provisioning of 'Log Analytics agent for Azure VMs' is Set to 'On' |
| CISAz45 | 4.5 | (L1) Ensure that Shared Access Signature Tokens Expire Within an Hour |
| CISAz511 | 5.1.1 | (L1) Ensure that 'Auditing' is set to 'On' |
| CISAz512 | 5.1.2 | (L1) Ensure no Azure SQL Databases allow ingress from 0.0.0.0/0 (ANY IP) |
| CISAz514 | 5.1.4 | (L1) Ensure that Microsoft Entra authentication is Configured for SQL Servers |
| CISAz515 | 5.1.5 | (L1) Ensure that 'Data encryption' is set to 'On' on a SQL Database |
| CISAz516 | 5.1.6 | (L1) Ensure that 'Auditing' Retention is 'greater than 90 days' |
| CISAz521 | 5.2.1 | (L1) Ensure server parameter 'require_secure_transport' is set to 'ON' for PostgreSQL flexible server |
| CISAz522 | 5.2.2 | (L1) Ensure server parameter 'log_checkpoints' is set to 'ON' for PostgreSQL flexible server |
| CISAz523 | 5.2.3 | (L1) Ensure server parameter 'connection_throttle.enable' is set to 'ON' for PostgreSQL flexible server |
| CISAz524 | 5.2.4 | (L1) Ensure server parameter 'logfiles.retention_days' is greater than 3 days for PostgreSQL flexible server |
| CISAz525 | 5.2.5 | (L1) Ensure 'Allow public access from any Azure service within Azure to this server' for PostgreSQL flexible server is disabled |
| CISAz526 | 5.2.6 | (L1) Ensure server parameter 'log_connections' is set to 'ON' for PostgreSQL single server |
| CISAz527 | 5.2.7 | (L1) Ensure server parameter 'log_disconnections' is set to 'ON' for PostgreSQL single server |
| CISAz528 | 5.2.8 | (L1) Ensure 'Infrastructure double encryption' for PostgreSQL single server is 'Enabled' |
| CISAz531 | 5.3.1 | (L1) Ensure server parameter 'require_secure_transport' is set to 'ON' for MySQL flexible server |
| CISAz532 | 5.3.2 | (L1) Ensure server parameter 'tls_version' is set to 'TLSv1.2' (or higher) for MySQL flexible server |
| CISAz543 | 5.4.3 | (L1) Use Entra ID Client Authentication and Azure RBAC where possible |
| CISAz811 | 8.11 | (L1) Ensure Trusted Launch is enabled on Virtual Machines |
| CISAz82 | 8.2 | (L1) Ensure Virtual Machines are utilizing Managed Disks |
| CISAz85 | 8.5 | (L1) Ensure that 'Disk Network Access' is NOT set to 'Enable public access from all networks' |
| CISAz86 | 8.6 | (L1) Ensure that 'Enable Data Access Authentication Mode' is 'Checked' |
| CISAz87 | 8.7 | (L1) Ensure that Only Approved Extensions Are Installed |
| CISAz91 | 9.1 | (L1) Ensure 'HTTPS Only' is set to 'On' |
| CISAz910 | 9.10 | (L1) Ensure that 'HTTP20enabled' is set to 'true' (if in use) |
| CISAz912 | 9.12 | (L1) Ensure that 'Remote debugging' is set to 'Off' |
| CISAz93 | 9.3 | (L1) Ensure 'FTP State' is set to 'FTPS Only' or 'Disabled' |
| CISAz94 | 9.4 | (L1) Ensure Web App is using the latest version of TLS encryption |
| CISAz95 | 9.5 | (L1) Ensure that Register with Entra ID is enabled on App Service |
| CISAz96 | 9.6 | (L1) Ensure that 'Basic Authentication' is 'Disabled' |
| CISAz97 | 9.7 | (L1) Ensure that 'PHP version' is currently supported (if in use) |
| CISAz98 | 9.8 | (L1) Ensure that 'Python version' is currently supported (if in use) |
| CISAz99 | 9.9 | (L1) Ensure that 'Java version' is currently supported (if in use) |
| CISAz2013 | 2.13 | (L2) Ensure 'User consent for applications' is set to 'Do not allow user consent' or 'Allow for Verified Publishers' |
| CISAz2019 | 2.19 | (L2) Restrict user ability to create security groups in Azure |
| CISAz222 | 2.2.2 | (L2) Ensure that an exclusionary Geographic Access Policy is considered |
| CISAz223 | 2.2.3 | (L2) Ensure that an exclusionary Device code flow policy is considered |
| CISAz224 | 2.2.4 | (L1) Ensure Multi-Factor Authentication (MFA) is enabled for Administrative Groups |
| CISAz225 | 2.2.5 | (L2) Ensure that A Multi-factor Authentication Policy Exists for All Users |
| CISAz226 | 2.2.6 | (L2) Ensure Multi-factor Authentication is Required for Risky Sign-ins |
| CISAz227 | 2.2.7 | (L2) Ensure Multi-Factor Authentication (MFA) is enabled for Azure Service Management API |
| CISAz228 | 2.2.8 | (L1) Ensure Multi-Factor Authentication (MFA) is enabled for Microsoft Admin Portals |
| CISAz31016 | 3.1.16 | (L2) Ensure That Microsoft Defender for DNS Is Set To 'On' |
| CISAz3112 | 3.1.1.2 | (L2) Ensure that Microsoft Defender for Cloud Apps integration with Microsoft Defender for Cloud is Selected |
| CISAz3135 | 3.1.3.5 | (L2) Ensure File Integrity Monitoring (FIM) is Enabled |
| CISAz3142 | 3.1.4.2 | (L2) Ensure that 'Agentless discovery for Kubernetes' component status 'On' |
| CISAz3143 | 3.1.4.3 | (L2) Ensure that 'Agentless container vulnerability assessment' component status is 'On' |
| CISAz42 | 4.2 | (L2) Ensure that ‘Enable Infrastructure Encryption’ for Each Storage Account in Azure Storage is Set to ‘enabled’ |
| CISAz513 | 5.1.3 | (L2) Ensure SQL server's Transparent Data Encryption (TDE) protector is encrypted with Customer-managed key |
| CISAz533 | 5.3.3 | (L1) Ensure server parameter 'audit_log_enabled' is set to 'ON' for MySQL flexible server |
| CISAz534 | 5.3.4 | (L1) Ensure server parameter 'audit_log_events' has 'CONNECTION' set for MySQL flexible server |
| CISAz541 | 5.4.1 | (L2) Ensure That 'Firewalls & Networks' Is Limited to Use Selected Networks Instead of All Networks |
| CISAz542 | 5.4.2 | (L2) Ensure That Private Endpoints Are Used Where Possible |
| CISAz616 | 6.1.6 | (L1) Ensure that logging for Azure AppService 'HTTP logs' is enabled |
| CISAz650 | 6.5 | (L2) Ensure that SKU Basic/Consumption is not used on artifacts that need to be monitored (Particularly for Production Workloads) |
| CISAz83 | 8.3 | (L2) Ensure that 'OS and Data' disks are encrypted with Customer Managed Key (CMK) |
| CISAz84 | 8.4 | (L2) Ensure that 'Unattached disks' are encrypted with 'Customer Managed Key' (CMK) |
| CISAz89 | 8.9 | (L2) Ensure that VHDs are Encrypted |
| CISAz911 | 9.11 | (L2) Ensure Azure Key Vaults are Used to Store Secrets |
| CISAz92 | 9.2 | (L2) Ensure App Service Authentication is set up for apps in Azure App Service |
| CISMAz5111 | 5.1.1.1 | (L1) Ensure Security Defaults is disabled |
| CISMAz5124 | 5.1.2.4 | (L1) Ensure access to the Entra admin center is restricted |
| CISMAz5131 | 5.1.3.1 | (L1) Ensure a dynamic group for guest users is created |
| CISMSp733 | 7.3.3 | (L1) Ensure custom script execution is restricted on personal sites |
| CISMSp734 | 7.3.4 | (L1) Ensure custom script execution is restricted on site collections |
| CISMSp732 | 7.3.2 | (L2) Ensure OneDrive sync is restricted for unmanaged devices |
| CISMTm824 | 8.2.4 | (L1) Ensure communication with Skype users is disabled |

## 5. CIS Azure v6 sem inspector

Baixa prioridade para o foco MSP/M365. Listado por seção.

| ID v6 | Seção | Perfil | Tipo | Check Prowler |
|---|---|---|---|---|
| 2.1.1 | 2.1 Azure Databricks | Level 1 | Automated | `databricks_workspace_vnet_injection_enabled` |
| 2.1.2 | 2.1 Azure Databricks | Level 1 | Automated | `—` |
| 2.1.3 | 2.1 Azure Databricks | Level 2 | Manual | `—` |
| 2.1.4 | 2.1 Azure Databricks | Level 1 | Manual | `—` |
| 2.1.5 | 2.1 Azure Databricks | Level 1 | Manual | `—` |
| 2.1.6 | 2.1 Azure Databricks | Level 1 | Manual | `—` |
| 2.1.7 | 2.1 Azure Databricks | Level 1 | Automated | `—` |
| 2.1.9 | 2.1 Azure Databricks | Level 1 | Automated | `databricks_workspace_no_public_ip_enabled` |
| 2.1.11 | 2.1 Azure Databricks | Level 2 | Automated | `—` |
| 2.1.12 | 2.1 Azure Databricks | Level 1 | Manual | `—` |
| 5.3.1 | 5.3 Periodic Identity Reviews | Level 1 | Manual | `—` |
| 5.3.3 | 5.3 Periodic Identity Reviews | Level 1 | Automated | `iam_role_user_access_admin_restricted` |
| 5.3.4 | 5.3 Periodic Identity Reviews | Level 1 | Manual | `—` |
| 5.3.5 | 5.3 Periodic Identity Reviews | Level 1 | Manual | `—` |
| 5.3.6 | 5.3 Periodic Identity Reviews | Level 1 | Manual | `—` |
| 5.3.7 | 5.3 Periodic Identity Reviews | Level 1 | Manual | `—` |
| 5.7 | 5 Identity Services | Level 1 | Automated | `—` |
| 6.1.1.6 | 6.1 Logging and Monitoring | Level 2 | Manual | `network_flow_log_captured_sent` |
| 6.1.1.7 | 6.1 Logging and Monitoring | Level 2 | Manual | `monitor_diagnostic_settings_exists` |
| 6.1.1.8 | 6.1 Logging and Monitoring | Level 2 | Manual | `monitor_diagnostic_settings_exists` |
| 6.1.1.9 | 6.1 Logging and Monitoring | Level 2 | Manual | `—` |
| 6.1.2.11 | 6.1 Logging and Monitoring | Level 1 | Automated | `monitor_alert_service_health_exists` |
| 6.1.5 | 6.1 Logging and Monitoring | Level 2 | Manual | `—` |
| 7.8 | 7 Networking Services | Level 2 | Automated | `network_flow_log_more_than_90_days` |
| 7.9 | 7 Networking Services | Level 2 | Automated | `—` |
| 7.10 | 7 Networking Services | Level 2 | Automated | `—` |
| 7.11 | 7 Networking Services | Level 1 | Automated | `network_subnet_nsg_associated` |
| 7.12 | 7 Networking Services | Level 1 | Automated | `—` |
| 7.13 | 7 Networking Services | Level 1 | Automated | `—` |
| 7.14 | 7 Networking Services | Level 2 | Automated | `—` |
| 7.15 | 7 Networking Services | Level 2 | Automated | `—` |
| 7.16 | 7 Networking Services | Level 2 | Manual | `—` |
| 8.1.1.1 | 8.1 Microsoft Defender for Cloud | Level 2 | Automated | `defender_ensure_defender_cspm_is_on` |
| 8.1.2.1 | 8.1 Microsoft Defender for Cloud | Level 2 | Automated | `defender_ensure_defender_for_app_services_is_on` |
| 8.1.3.5 | 8.1 Microsoft Defender for Cloud | Level 2 | Manual | `—` |
| 8.1.5.2 | 8.1 Microsoft Defender for Cloud | Level 2 | Manual | `—` |
| 8.1.15 | 8.1 Microsoft Defender for Cloud | Level 1 | Automated | `defender_attack_path_notifications_properly_configured` |
| 8.3.7 | 8.3 Key Vault | Level 1 | Automated | `keyvault_private_endpoints` |
| 8.3.10 | 8.3 Key Vault | Level 2 | Manual | `—` |
| 8.3.11 | 8.3 Key Vault | Level 1 | Automated | `—` |
| 8.5 | 8 Security Services | Level 2 | Automated | `network_vnet_ddos_protection_enabled` |
| 9.1.1 | 9.1 Azure Files | Level 1 | Automated | `storage_ensure_file_shares_soft_delete_is_enabled` |
| 9.1.2 | 9.1 Azure Files | Level 1 | Automated | `storage_smb_protocol_version_is_latest` |
| 9.1.3 | 9.1 Azure Files | Level 1 | Automated | `storage_smb_channel_encryption_with_secure_algorithm` |
| 9.2.2 | 9.2 Azure Blob Storage | Level 1 | Automated | `storage_ensure_soft_delete_is_enabled` |
| 9.2.3 | 9.2 Azure Blob Storage | Level 2 | Automated | `storage_blob_versioning_is_enabled` |
| 9.3.1.3 | 9.3 Storage Accounts | Level 1 | Automated | `storage_account_key_access_disabled` |
| 9.3.3.1 | 9.3 Storage Accounts | Level 1 | Automated | `storage_default_to_entra_authorization_enabled` |
| 9.3.9 | 9.3 Storage Accounts | Level 1 | Manual | `—` |
| 9.3.10 | 9.3 Storage Accounts | Level 2 | Manual | `—` |
| 9.3.11 | 9.3 Storage Accounts | Level 2 | Automated | `storage_geo_redundant_enabled` |

## 6. Mapeamentos a revisar manualmente

| Inspector | ID atual | → Alvo | Método | Score |
|---|---|---|---|---|
| CISAz24 | 2.4 | Azure v6 5.3.2 | tokens | 1.0 |
| CISAz517 | 5.1.7 | Azure v6 2.1.10 | tokens | 1.0 |
| CISAz640 | 6.4 | Azure v6 6.1.4 | tokens | 1.0 |
| CISAz77 | 7.7 | Azure v6 7.7 | tokens | 1.0 |
| CISAz1001 | 10.1 | Azure v6 6.2 | tokens | 1.0 |
| CISAz31015 | 3.1.15 | Azure v6 8.1.16 | tokens | 0.89 |
| CISAz411 | 4.11 | Azure v6 2.1.8 | tokens | 0.88 |
| CISMSp728 | 7.2.8 | M365 v7 7.2.8 | same-id | 0.67 |

