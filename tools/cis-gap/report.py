"""Render docs/CIS-GAP-v7.md from gap.json. Uses only IDs, Prowler check names and own summaries (no CIS text)."""
import json
import sys
from collections import Counter
from pathlib import Path

SCRATCH, OUT = Path(sys.argv[1]), Path(sys.argv[2])
g = json.loads((SCRATCH / "gap.json").read_text())

# id: (resumo PT, prioridade, fonte de dados sugerida)
NEW = {
    "1.3.9": ("Shared Bookings desabilitado", "C", "Get-OrganizationConfig (BookingsEnabled) / Get-OwaMailboxPolicy"),
    "2.1.6": ("Política anti-spam outbound com notificação e limites", "B", "Get-HostedOutboundSpamFilterPolicy"),
    "2.1.15": ("Política anti-spam outbound padrão configurada", "B", "Get-HostedOutboundSpamFilterPolicy (Default)"),
    "2.2.1": ("Monitorar sign-in de contas break-glass com alerta", "A", "Graph auditLogs/signIns + alert rule (parcialmente manual)"),
    "2.4.5": ("AIR (Automated Investigation & Response) configurado", "C", "Manual — Defender portal"),
    "3.2.3": ("DLP cobrindo Microsoft 365 Copilot (prompts e respostas)", "A", "Get-DlpCompliancePolicy (Locations Copilot)"),
    "4.1": ("Dispositivo sem compliance policy = não conforme", "A", "Graph deviceManagement/settings (secureByDefault)"),
    "4.2": ("Bloquear enrollment de dispositivo pessoal", "A", "Graph deviceManagement/deviceEnrollmentConfigurations"),
    "5.1.3.1": ("Usuário comum não cria security groups", "B", "Graph policies/authorizationPolicy"),
    "5.1.4.1": ("Entra join restrito a usuários selecionados", "B", "Graph policies/deviceRegistrationPolicy"),
    "5.1.4.2": ("Limite de dispositivos por usuário", "B", "Graph policies/deviceRegistrationPolicy"),
    "5.1.4.3": ("Global Admin não vira admin local no join", "A", "Graph policies/deviceRegistrationPolicy"),
    "5.1.4.4": ("Usuário que registra não vira admin local", "A", "Graph policies/deviceRegistrationPolicy"),
    "5.1.4.5": ("Cloud LAPS habilitado", "A", "Graph policies/deviceRegistrationPolicy (localAdminPassword)"),
    "5.1.4.6": ("Usuário não lê chave BitLocker", "B", "Graph policies/authorizationPolicy"),
    "5.1.5.3": ("Bloquear client secrets (só certificado) em apps", "B", "Graph policies/defaultAppManagementPolicy"),
    "5.1.5.4": ("Validade máxima de client secret", "A", "Graph policies/defaultAppManagementPolicy"),
    "5.1.5.5": ("Bloquear secret customizado (definido pelo usuário)", "B", "Graph policies/defaultAppManagementPolicy"),
    "5.1.5.6": ("Validade máxima de certificado de app", "B", "Graph policies/defaultAppManagementPolicy"),
    "5.2.2.8": ("CA bloqueia sign-in de risco médio/alto", "A", "Graph identity/conditionalAccess/policies"),
    "5.2.2.11": ("CA: sign-in frequency 'every time' no enrollment Intune", "B", "Graph identity/conditionalAccess/policies"),
    "5.2.2.12": ("CA bloqueia device code flow", "A", "Graph identity/conditionalAccess/policies"),
    "5.2.2.13": ("CA: sign-in frequency para todos os usuários", "B", "Graph identity/conditionalAccess/policies"),
    "5.2.2.14": ("Named locations confiáveis definidas", "B", "Graph identity/conditionalAccess/namedLocations"),
    "5.2.2.16": ("CA com Token Protection", "A", "Graph identity/conditionalAccess/policies (sessionControls)"),
    "5.2.2.17": ("CA bloqueia authentication transfer", "A", "Graph identity/conditionalAccess/policies (authenticationFlows)"),
    "5.2.3.5": ("SMS e voz desabilitados como método MFA", "A", "Graph policies/authenticationMethodsPolicy"),
    "5.2.3.6": ("MFA system-preferred habilitado", "B", "Graph policies/authenticationMethodsPolicy"),
    "5.2.3.10": ("Authenticator Lite desabilitado", "C", "Graph policies/authenticationMethodsPolicy/.../microsoftAuthenticator"),
    "5.3.1": ("PIM em uso para roles privilegiadas", "A", "Graph roleManagement/directory/roleEligibilitySchedules"),
    "5.3.5": ("PIM: aprovação para Privileged Role Administrator", "B", "Graph policies/roleManagementPolicies"),
    "6.2.2": ("Transport rule não define SCL -1 (bypass de spam)", "A", "Get-TransportRule"),
    "6.3.2": ("OWA sem contas pessoais (Gmail/Outlook.com)", "B", "Get-OwaMailboxPolicy"),
    "6.5.3": ("OWA sem armazenamento de terceiros", "C", "Get-OwaMailboxPolicy"),
    "6.5.5": ("Reject Direct Send habilitado", "A", "Get-OrganizationConfig (RejectDirectSend)"),
    "8.2.4": ("Teams bloqueia tenants trial", "B", "Get-CsTenantFederationConfiguration"),
    "8.4.1": ("Políticas de permissão de apps no Teams", "C", "Manual — Teams admin center"),
}
for i in range(1, 13):
    NEW[f"9.1.{i}"] = None
FABRIC = {
    "9.1.1": "Guest B2B sem acesso ao Fabric",
    "9.1.2": "Convite de externos via Power BI restrito",
    "9.1.3": "Guest sem navegação completa",
    "9.1.4": "Publish to web restrito",
    "9.1.5": "Visuais R/Python desabilitados",
    "9.1.6": "Sensitivity labels habilitados no Power BI",
    "9.1.7": "Links compartilháveis restritos",
    "9.1.8": "Compartilhamento externo de datasets restrito",
    "9.1.9": "ResourceKey authentication bloqueada",
    "9.1.10": "Service principals em APIs Fabric restritos",
    "9.1.11": "Service principal profiles restritos",
    "9.1.12": "Service principals em APIs não protegidas restritos",
}
for k, v in FABRIC.items():
    NEW[k] = (v, "C", "Fabric Admin API admin/tenantsettings")

repo = g["repo"]
internal = {r["uuid"] for r in repo if r["internal"]}
m7, a6 = g["m365_v7"], g["azure_v6"]
missing7 = [x for x in m7 if not x["covered_by"]]
missing6 = [x for x in a6 if not x["covered_by"]]
mapped = [r for r in repo if r["target"]]
relocated = [r for r in mapped if r["family"] == "AZURE" and r["target"]["family"] == "M365 v7"]
renum = [r for r in mapped if r["family"] == "M365" and r["target"]["family"] == "M365 v7" and r["target"]["id"] != r["id"]]
obsolete = [r for r in repo if not r["target"]]
review = [r for r in mapped if r["target"]["method"] == "tokens" or r["target"]["score"] < 0.7]
prio = Counter(NEW[x["id"]][1] for x in missing7 if NEW.get(x["id"]))

L = []
w = L.append
w("# CIS Gap Analysis — M365 v7.0.0 / Azure v6.0.0\n")
w("Matriz entre os inspectors do M365SAT (CIS M365 v4.0.0 / Azure v3.0.0) e as versões atuais do CIS.")
w("Fonte dos requisitos: definições de compliance do [Prowler](https://github.com/prowler-cloud/prowler/tree/master/prowler/compliance) "
  "(`cis_7.0_m365.json`, `cis_6.0_azure.json`). Este documento não reproduz texto do CIS; confirmar contra o PDF oficial.\n")
w("Regenerar: `tools/cis-gap/run.sh`. Método de cruzamento: check do Prowler em comum → "
  "nome de configuração citado no título → similaridade da descrição → tokens do título → mesmo ID.\n")
w("## Resumo\n")
w("| Indicador | Valor |\n|---|---|")
w(f"| Inspectors no repo | {len(repo)} |")
w(f"| Mapeados para v7/v6 | {len(mapped)} |")
w(f"| Sem equivalente (obsoletos/removidos) | {len(obsolete)} |")
w(f"| CIS M365 v7 — controles | {len(m7)} |")
w(f"| CIS M365 v7 — cobertos | {len(m7) - len(missing7)} ({100 * (len(m7) - len(missing7)) // len(m7)}%) |")
w(f"| CIS M365 v7 — **a criar** | **{len(missing7)}** (A={prio['A']}, B={prio['B']}, C={prio['C']}) |")
w(f"| CIS Azure v6 — controles / cobertos / a criar | {len(a6)} / {len(a6) - len(missing6)} / {len(missing6)} |")
w(f"| Inspectors Azure que migram para o M365 v7 | {len(relocated)} |")
w(f"| Inspectors M365 com ID renumerado | {len(renum)} |")
w(f"| Inspectors usando API interna (reescrever p/ Graph) | {len(internal)} |")
w(f"| Mapeamentos de baixa confiança (revisar) | {len(review)} |\n")
w("Prioridade: **A** = alto impacto de segurança e automatizável via Graph/EXO; **B** = hardening relevante; **C** = baixo risco, nicho ou manual.\n")

w("## 1. Controles novos — CIS M365 v7 sem inspector\n")
w("| ID v7 | Controle | Perfil | Tipo | Prior. | Fonte de dados | Check Prowler |\n|---|---|---|---|---|---|---|")
order = {"A": 0, "B": 1, "C": 2}
for x in sorted(missing7, key=lambda x: (order[NEW[x["id"]][1]] if NEW.get(x["id"]) else 3, [int(p) for p in x["id"].split(".")])):
    t, p, src = NEW.get(x["id"]) or ("(sem resumo)", "?", "")
    w(f"| {x['id']} | {t} | {x['profile']} | {x['status']} | {p} | {src} | `{', '.join(x['checks']) or '—'}` |")
w("")
w("Observação: a seção 9 (Power BI / Fabric) não existe no M365SAT. Exige novo conector (Fabric Admin API) e nova pasta `inspectors/M365/PowerBI`.\n")

w("## 2. Inspectors Azure que passam para o CIS M365 v7\n")
w("Controles de Entra ID saíram do Azure Benchmark. Mover para `inspectors/M365/Azure/...`, trocar `UUID`/`ID` e o cabeçalho `# Benchmark`.\n")
w("| Inspector atual | ID v3 | → ID M365 v7 | API interna |\n|---|---|---|---|")
for r in sorted(relocated, key=lambda r: [int(p) for p in r["target"]["id"].split(".")]):
    w(f"| {r['uuid']} | {r['id']} | {r['target']['id']} | {'sim' if r['uuid'] in internal else ''} |")
w("")

w("## 3. Inspectors M365 com ID renumerado na v7\n")
w("Lógica provavelmente válida; atualizar `ID`, título e referência. Revisar audit procedure no PDF.\n")
w("| Inspector | ID v4 | → ID v7 | Método | API interna |\n|---|---|---|---|---|")
for r in sorted(renum, key=lambda r: [int(p) for p in r["id"].split(".")]):
    w(f"| {r['uuid']} | {r['id']} | {r['target']['id']} | {r['target']['method']} | {'sim' if r['uuid'] in internal else ''} |")
w("")

w("## 4. Inspectors sem equivalente (candidatos a remover ou mover para benchmark de serviço)\n")
w("A maioria são controles de serviços Azure (SQL, PostgreSQL single server, App Service, VM) que o CIS tirou do Foundations "
  "e passou para benchmarks de serviço específicos. Manter só se o cliente usa esses serviços.\n")
w("| Inspector | ID | Título atual |\n|---|---|---|")
for r in obsolete:
    w(f"| {r['uuid']} | {r['id']} | {(r['title'] or '').replace('|', '/')} |")
w("")

w("## 5. CIS Azure v6 sem inspector\n")
w("Baixa prioridade para o foco MSP/M365. Listado por seção.\n")
w("| ID v6 | Seção | Perfil | Tipo | Check Prowler |\n|---|---|---|---|---|")
for x in missing6:
    w(f"| {x['id']} | {x['section']} | {x['profile']} | {x['status']} | `{', '.join(x['checks']) or '—'}` |")
w("")

w("## 6. Mapeamentos a revisar manualmente\n")
w("| Inspector | ID atual | → Alvo | Método | Score |\n|---|---|---|---|---|")
for r in review:
    t = r["target"]
    w(f"| {r['uuid']} | {r['id']} | {t['family']} {t['id']} | {t['method']} | {t['score']} |")
w("")

OUT.write_text("\n".join(L) + "\n")
print(f"wrote {OUT}: missing7={len(missing7)} prio={dict(prio)} relocated={len(relocated)} renum={len(renum)} obsolete={len(obsolete)} review={len(review)}")
