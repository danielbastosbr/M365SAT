"""Gap matrix: M365SAT inspectors vs CIS M365 v7.0 / Azure v6.0 (Prowler compliance JSON).

Matching order per inspector (first hit wins):
  1. shared Prowler check name between the source requirement (M365 v4 / Azure v3) and the target
  2. quoted setting name from the title found verbatim in the target text
  3. description similarity (body text vs body text)
  4. title-token containment in the target text
"""
import json
import re
import sys
from difflib import SequenceMatcher
from pathlib import Path

SCRATCH = Path(sys.argv[1])
COMP = SCRATCH / "ext/prowler/prowler/compliance"
STOP = set("ensure that the is are set to for a an of and or in on be with not all by from is any use using if".split())


def load(rel):
    return json.loads((COMP / rel).read_text())["Requirements"]


def toks(t):
    return re.sub(r"[^a-z0-9 ]", " ", (t or "").lower()).split()


def full(r):
    a = r["Attributes"][0]
    return " ".join([r["Description"], a.get("AuditProcedure", ""), a.get("RemediationProcedure", "")])


def sim(a, b):
    return SequenceMatcher(None, toks(a), toks(b), autojunk=False).ratio()


def containment(title, text):
    t = [w for w in toks(re.sub(r"^\(L\d\)\s*", "", title or "")) if w not in STOP]
    body = set(toks(text))
    return sum(w in body for w in t) / len(t) if t else 0


GENERIC = {"enabled", "disabled", "checked", "auditing", "everyone", "selected"}


def quoted(title):
    qs = [q.lower() for q in re.findall(r"['`‘’\"]([^'`‘’\"]{6,})['`‘’\"]", title or "")]
    return [q for q in qs if q not in GENERIC and (len(q) >= 12 or " " in q)]


def desc_containment(title, t):
    words = [w for w in toks(re.sub(r"^\(L\d\)\s*", "", title or "")) if w not in STOP]
    return containment(title, t["Description"]) if len(words) >= 4 else 0


def match(title, src, targets, src_id=None):
    """Return (target_req, method, score) or None. src_id is only passed when IDs are comparable (M365 v4 -> v7)."""
    checks = set(src["Checks"]) if src else set()
    if checks:
        hits = [t for t in targets if checks & set(t["Checks"])]
        if hits:
            same = [t for t in hits if t["Id"] == src_id]
            t = same[0] if same else max(hits, key=lambda t: containment(title, full(t)))
            return t, "check", 1.0
    if src and src_id:
        same = [t for t in targets if t["Id"] == src_id]
        if same and sim(src["Description"], same[0]["Description"]) >= 0.5:
            return same[0], "same-id", round(sim(src["Description"], same[0]["Description"]), 2)
    qs = quoted(title)
    if qs:
        hits = [t for t in targets if all(q in full(t).lower() for q in qs)]
        if hits:
            t = max(hits, key=lambda t: containment(title, full(t)))
            return t, "quoted", 0.95
    if src and len(src["Description"]) > 150:
        s, t = max(((sim(src["Description"], t["Description"]), t) for t in targets), key=lambda x: x[0])
        if s >= 0.65:
            return t, "desc", round(s, 2)
    s, t = max(((desc_containment(title, t), t) for t in targets), key=lambda x: x[0])
    if s >= 0.85:
        return t, "tokens", round(s, 2)
    return None


repo = json.loads((SCRATCH / "repo.json").read_text())
m4, m7 = load("m365/cis_4.0_m365.json"), load("m365/cis_7.0_m365.json")
a3, a6 = load("azure/cis_3.0_azure.json"), load("azure/cis_6.0_azure.json")
m4_by_id = {r["Id"]: r for r in m4}
a3_by_id = {r["Id"]: r for r in a3}

rows = []
for ins in repo:
    if not ins["uuid"]:
        continue
    is_az = ins["path"].startswith("inspectors/AZURE/")
    src = (a3_by_id if is_az else m4_by_id).get(ins["id"] or "")
    title = ins["title"] or ""
    cands = []
    # only Azure identity controls (section 2) can have been relocated into the M365 benchmark
    if not is_az or (ins["id"] or "").startswith("2."):
        m = match(title, src, m7, None if is_az else ins["id"])
        if m:
            cands.append(("M365 v7",) + m)
    if is_az or not cands:
        m = match(title, src, a6)
        if m:
            cands.append(("Azure v6",) + m)
    target = None
    if cands:
        fam, req, how, score = max(cands, key=lambda c: (c[3], c[0] == "Azure v6"))
        target = dict(family=fam, id=req["Id"], method=how, score=score)
    rows.append(dict(ins, family="AZURE" if is_az else "M365", target=target))

# Manual review results: (target id, method). A list means the v4 control was split in v7.
MANUAL = {
    "CISMEx331": ["3.3.1"],   # SharePoint information protection -> sensitivity labels published
    "CISAz2018": ["5.1.3.2"], # Access Panel groups features -> My Groups restricted
    "CISMAz5235": ["5.2.3.5", "5.2.3.7"],  # weak methods split into SMS/voice + email OTP
}
extra = []
for r in rows:
    ids = MANUAL.get(r["uuid"])
    if ids:
        r["target"] = dict(family="M365 v7", id=ids[0], method="manual", score=1.0)
        extra += [(i, r["uuid"]) for i in ids[1:]]

cov = {"M365 v7": {}, "Azure v6": {}}
for i, u in extra:
    cov["M365 v7"].setdefault(i, []).append(u)
for r in rows:
    if r["target"]:
        cov[r["target"]["family"]].setdefault(r["target"]["id"], []).append(r["uuid"])


def summarize(reqs, fam):
    out = []
    for r in reqs:
        a = r["Attributes"][0]
        out.append(dict(id=r["Id"], section=a.get("SubSection") or a["Section"], profile=a["Profile"],
                        status=a["AssessmentStatus"], desc=r["Description"], checks=r["Checks"],
                        audit=a.get("AuditProcedure", ""), covered_by=cov[fam].get(r["Id"], [])))
    return out


result = {"repo": rows, "m365_v7": summarize(m7, "M365 v7"), "azure_v6": summarize(a6, "Azure v6")}
(SCRATCH / "gap.json").write_text(json.dumps(result, indent=1))

orph = [r for r in rows if not r["target"]]
print(f"repo inspectors: {len(rows)}  mapped: {len(rows) - len(orph)}  unmapped: {len(orph)}")
for fam, key in (("M365 v7", "m365_v7"), ("Azure v6", "azure_v6")):
    tot = result[key]
    c = [x for x in tot if x["covered_by"]]
    print(f"{fam}: {len(tot)} controls, covered {len(c)}, missing {len(tot) - len(c)}")
from collections import Counter
print("methods:", Counter(r["target"]["method"] for r in rows if r["target"]))
print("azure->m365:", len([r for r in rows if r["family"] == "AZURE" and r["target"] and r["target"]["family"] == "M365 v7"]))
print("unmapped:")
for r in orph:
    print(f"  {r['uuid']:12} {r['id']:8} {(r['title'] or '')[:80]}")
