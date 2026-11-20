#!/usr/bin/env python3
"""Regression smoke test against a running Rampart (docs/28).

Every check here is a bug that was found by hand on the dev cluster on 2026-11-17 and fixed. Run it after a rollout:

    RAMPART_URL=https://rampart.example.com RAMPART_USER=admin RAMPART_PASSWORD=... python3 hack/qa/live_smoke.py

It works in its own application (qa-smoke) and its own repository, so it touches no other data. It does write: a few
findings, runs and one risk-free triage decision in that application. There is no delete for an application; the data
stays and is overwritten by the next run. It needs the `requests` package. Exit code 1 if any check fails.
"""
import json
import os
import sys
import uuid

import requests

BASE = os.environ.get("RAMPART_URL", "").rstrip("/")
USER = os.environ.get("RAMPART_USER", "admin")
PASSWORD = os.environ.get("RAMPART_PASSWORD", "")
if not BASE or not PASSWORD:
    sys.exit("set RAMPART_URL and RAMPART_PASSWORD (and RAMPART_USER if it is not admin)")

s = requests.Session()
s.headers["User-Agent"] = "rampart-live-smoke"
failures = []
APP = "qa-smoke"
REPO = f"github.com/qa-smoke/{uuid.uuid4().hex[:8]}"  # a repository of its own: nothing else is touched


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {detail}"))
    if not ok:
        failures.append(name)


def sarif(rule="R1", message="bad", tool="x", extra_rules=None):
    return json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": tool, "rules": extra_rules or [{"id": rule}]}}, "results": [{
        "ruleId": rule, "level": "error", "message": {"text": message},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.js"}, "region": {"startLine": 3}}}]}]}]})


def upload(body, fmt=None, **fields):
    data = {"application": APP, "repository": REPO, "track": "main", **fields}
    if fmt:
        data["format"] = fmt
    return s.post(BASE + "/api/v1/uploads/direct", headers=H, files={"file": ("r.json", body)}, data=data)


def get(path, **kw):
    return s.get(BASE + path, **kw)


r = s.post(BASE + "/auth/local/login", json={"username": USER, "password": PASSWORD})
if r.status_code != 204:
    sys.exit(f"login failed: {r.status_code}")
H = {"X-CSRF-Token": get("/auth/session").json()["csrfToken"]}

# 1. A parser the client names must match the file (a SARIF file sent as trivy closed real findings).
check("baseline sarif upload", upload(sarif(), "sarif").status_code == 201)
n0 = get("/api/v1/findings", params={"q": f"app:{APP}", "limit": 1}).json()["total"]
for fmt in ("trivy", "cluster:trivy", "semgrep", "checkov", "grype"):
    r = upload(sarif(), fmt)
    check(f"format={fmt} on a SARIF file is refused", r.status_code == 400 and "format-mismatch" in r.text, f"{r.status_code} {r.text[:120]}")
check("a refused upload changes nothing", get("/api/v1/findings", params={"q": f"app:{APP}", "limit": 1}).json()["total"] == n0)

# 2. NUL bytes are a bad request or are replaced, never a 500.
r = upload(sarif(message="nul \\u0000 here", rule="U\\u0000N"), "sarif")
check("a NUL in a report is replaced", r.status_code == 201, f"{r.status_code} {r.text[:120]}")
check("%00 in a query is 400", get("/api/v1/findings", params={"q": "a\x00b"}).status_code == 400)
fid = get("/api/v1/findings", params={"q": f"app:{APP}", "limit": 1}).json()["items"][0]["finding"]["id"]
ver = get(f"/api/v1/findings/{fid}").json()["finding"]["version"]
r = s.patch(f"{BASE}/api/v1/findings/{fid}", headers={**H, "If-Match": f'"{ver}"'}, json={"note": "a\x00b"})
check("a NUL in a note is 400", r.status_code == 400, f"{r.status_code}")

# 3. Status codes and shapes.
r = upload(b"x" * (33 * 1024 * 1024), "sarif")
check("a report over 32 MiB is 413", r.status_code == 413, f"{r.status_code}")
check("export format=sarif is 400", get("/api/v1/findings/export", params={"format": "sarif"}).status_code == 400)
check("an empty page is [] not null", '"items":[]' in get("/api/v1/findings", params={"q": "cve:CVE-1900-0000"}).text.replace(" ", ""))

# 4. The answer says where it was filed.
body = upload(sarif(), "sarif").json()
check("the upload answer names the application", body.get("application") == APP, str(body))

# 5. Trivy SARIF keeps its CVE, package and category.
trivy = sarif(rule="CVE-2021-23337", tool="Trivy", message="Package: lodash\nInstalled Version: 4.17.20\nVulnerability CVE-2021-23337\nSeverity: HIGH\nFixed Version: 4.17.21\nLink: [x](https://avd.aquasec.com/nvd/cve-2021-23337)",
              extra_rules=[{"id": "CVE-2021-23337", "shortDescription": {"text": "lodash: command injection"}, "properties": {"tags": ["vulnerability", "security", "HIGH"]}}])
r = upload(trivy, "sarif", repository=REPO + "-trivy")
check("trivy sarif upload", r.status_code == 201, r.text[:150])
f = get("/api/v1/findings", params={"q": "cve:CVE-2021-23337 app:" + APP}).json()
row = (f.get("items") or [None])[0]
check("the CVE is a vulnerability id (the query finds it)", row is not None)
if row:
    x = row["finding"]
    check("category is sca, title is the rule's name", x["category"] == "sca" and "\n" not in x["title"], f"{x['category']} {x['title'][:60]!r}")
    det = get(f"/api/v1/findings/{x['id']}").json()
    pk = next((o["location"]["package"] for o in det.get("occurrences", []) if o["location"].get("package")), None)
    check("the package, version and fixed version are read", bool(pk) and pk["component_name"] == "lodash" and pk["fixed_version"] == "4.17.21", str(pk))

# 6. The vulnerability record and its impact.
r = get("/api/v1/vulnerabilities/CVE-2021-23337")
check("GET /vulnerabilities/{id}", r.status_code == 200 and r.json().get("links"), f"{r.status_code}")
r = get("/api/v1/vulnerabilities/CVE-2021-23337/impact")
imp = r.json() if r.ok else {}
check("GET /vulnerabilities/{id}/impact lists this application", any(a["slug"] == APP for a in imp.get("applications", [])), str(imp)[:150])
check("an id with a query in it is refused", get("/api/v1/vulnerabilities/CVE-1%20OR%20x/impact").status_code in (400, 404))

# 7. Inventory.
check("GET /inventory", get("/api/v1/inventory").status_code == 200)
r = get("/api/v1/inventory/components", params={"q": "lodash"})
check("GET /inventory/components", r.status_code == 200 and "components" in r.json(), f"{r.status_code}")
check("components limit is validated", get("/api/v1/inventory/components", params={"limit": 0}).status_code == 400)

# 8. Compliance per application, and the logo route.
apps = get("/api/v1/applications").json().get("items") or []
app = next((a for a in apps if a["slug"] == APP), None)
check("the smoke application exists", app is not None)
if app:
    r = get(f"/api/v1/applications/{app['id']}/compliance")
    comp = r.json() if r.ok else {}
    check("GET /applications/{id}/compliance", r.status_code == 200 and comp.get("frameworks"), f"{r.status_code} {r.text[:100]}")
    check("every verdict is meets, gaps or partial", all(f["verdict"] in ("meets", "gaps", "partial") for f in comp.get("frameworks", [])))
tax = get("/api/v1/taxonomies").json().get("items") or []
check("a built-in framework has no logo path", all(not t.get("logo") for t in tax if t.get("origin") == "builtin"))
check("a framework with no logoUrl has no logo", get("/api/v1/taxonomies/owasp-top10-2021/logo").status_code == 404)

# 9. Triage: a change of the justification alone is a decision.
f2 = get("/api/v1/findings", params={"q": f"app:{APP} state:open", "limit": 1}).json()["items"][0]["finding"]
def patch(body):
    v = get(f"/api/v1/findings/{f2['id']}").json()["finding"]["version"]
    return s.patch(f"{BASE}/api/v1/findings/{f2['id']}", headers={**H, "If-Match": f'"{v}"'}, json=body)
check("not_affected with a justification", patch({"state": "not_affected", "justification": "component_not_present", "impactStatement": "first"}).status_code == 200)
r = patch({"impactStatement": "second"})
check("an impact statement alone is saved", r.status_code == 200, f"{r.status_code} {r.text[:100]}")
patch({"state": "open"})

# 10. The API documents what it serves.
spec = get("/api/v1/openapi.json").json()
check("openapi.json exists", bool(spec.get("paths")))

print()
print(f"{len(failures)} failed" if failures else "all checks passed")
sys.exit(1 if failures else 0)
