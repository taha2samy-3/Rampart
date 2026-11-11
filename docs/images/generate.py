#!/usr/bin/env python3
"""Generates the Rampart documentation diagrams and logo as SVG files."""
import sys, os
from xml.sax.saxutils import escape

OUT = sys.argv[1]
FONT = "Inter, 'Segoe UI', 'Helvetica Neue', Arial, sans-serif"
INK, MUTED, LINE = "#0F172A", "#475569", "#64748B"
KIND = {  # fill, stroke, title colour
    "write":   ("#E6FAF8", "#0E9F9A", "#0B5E5B"),
    "read":    ("#EEF0FF", "#4353D6", "#2A3690"),
    "control": ("#FEF3C7", "#D97706", "#8A4B04"),
    "data":    ("#F1F5F9", "#64748B", "#1E293B"),
    "ext":     ("#FFFFFF", "#94A3B8", "#1E293B"),
    "core":    ("#2A3690", "#1E2A5E", "#FFFFFF"),
    "good":    ("#DCFCE7", "#16A34A", "#14532D"),
    "warn":    ("#FEE2E2", "#DC2626", "#7F1D1D"),
}
ARROW_COLORS = {"line": LINE, "write": "#0E9F9A", "read": "#4353D6", "control": "#D97706", "warn": "#DC2626"}


class Svg:
    def __init__(self, w, h, title, subtitle=None):
        self.w, self.h, self.p = w, h, []
        self.rect(0.75, 0.75, w - 1.5, h - 1.5, "#FFFFFF", "#E2E8F0", rx=14, sw=1.5)
        self.text(40, 42, title, 22, 700, INK, "start")
        if subtitle:
            self.text(40, 64, subtitle, 13, 400, MUTED, "start")

    def rect(self, x, y, w, h, fill, stroke, rx=10, sw=1.5, dash=None):
        d = f' stroke-dasharray="{dash}"' if dash else ""
        self.p.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"{d}/>')

    def text(self, x, y, s, size=13, weight=400, fill=INK, anchor="middle", style=""):
        st = f' font-style="{style}"' if style else ""
        self.p.append(f'<text x="{x}" y="{y}" font-size="{size}" font-weight="{weight}" fill="{fill}" text-anchor="{anchor}"{st}>{escape(s)}</text>')

    def box(self, x, y, w, h, title, lines=(), kind="data", tsize=14, lsize=12, dash=None):
        fill, stroke, tcol = KIND[kind]
        self.rect(x, y, w, h, fill, stroke, dash=dash)
        lcol = "#DBE1FF" if kind == "core" else MUTED
        n = len(lines)
        block = tsize + n * (lsize + 5)
        ty = y + (h - block) / 2 + tsize - 2
        self.text(x + w / 2, ty, title, tsize, 700, tcol)
        for i, ln in enumerate(lines):
            self.text(x + w / 2, ty + (i + 1) * (lsize + 5), ln, lsize, 400, lcol)

    def frame(self, x, y, w, h, label, kind="data", dash="6 5"):
        fill, stroke, tcol = KIND[kind]
        self.p.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="12" fill="{fill}" fill-opacity="0.35" stroke="{stroke}" stroke-width="1.5" stroke-dasharray="{dash}"/>')
        self.text(x + 14, y + 22, label, 13, 700, tcol, "start")

    def arrow(self, pts, color="line", dash=None, both=False, label=None, lpos=None, lanchor="middle", sw=1.8):
        c = ARROW_COLORS[color]
        d = f' stroke-dasharray="{dash}"' if dash else ""
        ms = f' marker-start="url(#a-{color})"' if both else ""
        pp = " ".join(f"{x},{y}" for x, y in pts)
        self.p.append(f'<polyline points="{pp}" fill="none" stroke="{c}" stroke-width="{sw}" stroke-linejoin="round"{d} marker-end="url(#a-{color})"{ms}/>')
        if label:
            if lpos is None:
                (x1, y1), (x2, y2) = pts[0], pts[-1]
                lpos = ((x1 + x2) / 2, (y1 + y2) / 2 - 7)
            self.text(lpos[0], lpos[1], label, 12, 500, MUTED, lanchor)

    def pill(self, x, y, w, h, s, fill, stroke, col, size=12, weight=600):
        self.rect(x, y, w, h, fill, stroke, rx=h / 2, sw=1.2)
        self.text(x + w / 2, y + h / 2 + size * 0.36, s, size, weight, col)

    def raw(self, s):
        self.p.append(s)

    def save(self, name):
        markers = "".join(
            f'<marker id="a-{k}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="{c}"/></marker>'
            for k, c in ARROW_COLORS.items())
        body = "\n".join(self.p)
        svg = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {self.w} {self.h}" width="{self.w}" height="{self.h}" '
               f'font-family="{FONT}" role="img">\n<defs>{markers}</defs>\n{body}\n</svg>\n')
        with open(os.path.join(OUT, name), "w") as f:
            f.write(svg)


# ---------------------------------------------------------------- 1. system context
def system_context():
    s = Svg(1200, 690, "System context", "What Rampart connects to. It consumes scanner output; it does not scan.")
    s.box(420, 270, 360, 180, "Rampart", ["ingest · deduplicate · correlate", "score risk · enforce SLA", "route remediation · report posture"], "core", 24, 13)
    left = [("CI pipelines and scanners", "SARIF · CycloneDX · native JSON", False),
            ("Dependency-Track", "SBOM analysis · SCA findings · triage", True),
            ("Kubernetes clusters", "PolicyReport · Trivy Operator reports", False),
            ("Vulnerability feeds", "NVD · OSV · EPSS · KEV · CWE", False),
            ("Identity provider", "OIDC · SAML · SCIM", False)]
    for i, (t, l, both) in enumerate(left):
        y = 100 + i * 100
        s.box(40, y, 290, 70, t, [l], "ext")
        s.arrow([(330, y + 35), (420, 300 + i * 30)], both=both)
    right = [("Jira · GitHub · GitLab", "tickets with two-way status sync", True),
             ("Slack · Teams · email · webhooks", "notifications · CloudEvents", False),
             ("Analysts and developers", "web UI (static SPA)", True),
             ("CLI · CI gate · MCP clients", "REST API, OpenAPI 3.1", True),
             ("SIEM and data lake", "OCSF export · audit stream", False)]
    for i, (t, l, both) in enumerate(right):
        y = 100 + i * 100
        s.box(870, y, 290, 70, t, [l], "ext")
        s.arrow([(780, 300 + i * 30), (870, y + 35)], both=both)
    s.box(360, 590, 480, 70, "Runs on Kubernetes", ["PostgreSQL (CloudNativePG) · object storage (S3 API) · CRDs + operator"], "data")
    s.arrow([(600, 450), (600, 590)])
    s.save("system-context.svg")


# ---------------------------------------------------------------- 2. architecture
def architecture():
    s = Svg(1200, 850, "Architecture overview", "One binary, many targets. The write path and the read path never share a process in production.")
    s.frame(30, 84, 1140, 742, "Kubernetes cluster", "ext")
    s.box(60, 118, 1080, 50, "Gateway API / Ingress  ·  one hostname, path routing",
          ["/ingest, /hooks → ingest-gateway   |   /api, /auth, /scim → query-api   |   / → web-ui"], "ext", 13, 12)
    # write path
    s.frame(60, 196, 520, 370, "Write path", "write")
    s.box(80, 236, 150, 70, "ingest-gateway", ["auth · idempotency", "upload · CI gate"], "write")
    s.box(250, 236, 150, 70, "parser", ["parse · normalize", "fingerprint · merge"], "write")
    s.box(420, 236, 140, 70, "enrich", ["aliases · CVSS", "EPSS · KEV"], "write")
    s.box(420, 346, 140, 70, "policy", ["risk · SLA · CEL", "read models"], "write")
    s.box(250, 346, 150, 70, "notify", ["Jira · Slack", "webhooks"], "write")
    s.box(80, 346, 150, 70, "sync", ["Dependency-Track", "pull · push · forward"], "write")
    s.box(80, 456, 150, 60, "scheduler", ["periodic jobs"], "write")
    s.arrow([(230, 271), (250, 271)], "write")
    s.arrow([(400, 271), (420, 271)], "write")
    s.arrow([(490, 306), (490, 346)], "write")
    s.arrow([(420, 381), (400, 381)], "write")
    s.arrow([(190, 346), (275, 306)], "write")
    s.text(405, 478, "Every step is a River job:", 12, 600, "#0B5E5B")
    s.text(405, 496, "transactional, retried, idempotent,", 12, 400, MUTED)
    s.text(405, 514, "scaled per queue by KEDA", 12, 400, MUTED)
    # read path
    s.frame(600, 196, 270, 370, "Read path", "read")
    s.box(620, 236, 230, 80, "query-api", ["REST /api/v1 · SSO sessions", "read models · SSE · exports"], "read")
    s.box(620, 346, 230, 70, "web-ui", ["static SPA (React)", "no secrets, no business logic"], "read")
    s.box(620, 446, 230, 60, "mcp (optional)", ["tools for AI assistants"], "read")
    s.arrow([(735, 346), (735, 316)], "read")
    s.arrow([(850, 476), (860, 476), (860, 290), (850, 290)], "read")
    # control plane
    s.frame(890, 196, 250, 370, "Control plane", "control")
    s.box(910, 236, 210, 116, "CRDs (desired state)", ["Application · ScanSource", "ReportIngest · policies", "Connector · IdentityProvider", "Tenant · AccessBinding"], "control")
    s.box(910, 392, 210, 80, "operator", ["reconcile → config rows", "status ← conditions, counts"], "control")
    s.arrow([(1015, 352), (1015, 392)], "control", both=True)
    s.text(1015, 506, "Findings never live in etcd", 12, 600, "#8A4B04")
    s.text(1015, 524, "CRs hold config and summaries", 12, 400, MUTED)
    # data
    s.frame(60, 606, 1080, 200, "State", "data")
    s.box(80, 646, 420, 136, "PostgreSQL (CloudNativePG)", ["findings · occurrences · assets · vulnerabilities", "policies · audit · read models", "River job queue + outbox · row-level security per tenant"], "data")
    s.box(520, 646, 240, 136, "Object storage (S3 API)", ["raw reports · SBOMs", "exports · backups"], "data")
    s.box(780, 646, 170, 136, "Valkey (optional)", ["rate limits", "session cache"], "data", dash="5 4")
    s.box(970, 646, 150, 136, "NATS JetStream", ["(optional)", "event fan-out"], "data", dash="5 4")
    s.arrow([(155, 168), (155, 236)], "write")
    s.arrow([(735, 168), (735, 236)], "read")
    s.arrow([(320, 566), (320, 606)], "write", label="read / write", lpos=(328, 590), lanchor="start")
    s.arrow([(735, 566), (735, 606)], "read", label="read", lpos=(743, 590), lanchor="start")
    s.arrow([(1015, 566), (1015, 606)], "control", label="config", lpos=(1023, 590), lanchor="start")
    s.save("architecture-overview.svg")


# ---------------------------------------------------------------- 3. ingestion pipeline
def ingestion():
    s = Svg(1200, 560, "Ingestion pipeline", "From an uploaded report to triaged, scored findings. The label above each step is the target that runs it.")
    steps = [("ingest-gateway", "1 · Upload", ["POST /uploads", "presigned PUT to S3", "complete + sha256"]),
             ("parser", "2 · Detect and parse", ["format sniffing", "streaming parser", "→ RawFinding"]),
             ("parser", "3 · Normalize", ["CVE · CWE · purl · CPE", "paths · severity", "taxonomy mapping"]),
             ("parser", "4 · Fingerprint", ["finding_key from", "DedupPolicy fields", "+ correlation_key"]),
             ("parser", "5 · Stage", ["COPY batches into", "occurrence_staging", "≤ 5 000 rows per tx"]),
             ("parser", "6 · Merge", ["INSERT … ON CONFLICT", "(tenant, finding_key)", "one statement per batch"]),
             ("parser", "7 · Reimport close", ["absent in this run", "→ fixed", "never on a failed run"]),
             ("enrich", "8 · Enrich", ["alias graph", "CVSS · EPSS · KEV", "fixed versions"]),
             ("policy", "9 · Score and SLA", ["RiskPolicy factors", "band → SLAPolicy", "due date, KEV cap"]),
             ("policy", "10 · Policies", ["CEL automation", "auto-triage · routing", "exceptions"]),
             ("policy", "11 · Read models", ["application_summary", "trend_daily", "→ query-api and UI"]),
             ("notify", "12 · Notify", ["tickets · chat", "webhooks · events", "CI gate result"])]
    xs = [30 + i * 195 for i in range(6)]
    for i, (tgt, t, lines) in enumerate(steps):
        row = i // 6
        x = xs[i % 6] if row == 0 else xs[5 - (i % 6)]
        y = 116 if row == 0 else 296
        kind = "read" if tgt == "ingest-gateway" else "write" if tgt == "parser" else "control" if tgt in ("enrich", "policy") else "data"
        s.text(x + 82, y - 8, tgt, 11, 600, MUTED)
        s.box(x, y, 165, 110, t, lines, kind, 13, 12)
        if i % 6 != 5:
            if row == 0:
                s.arrow([(x + 165, y + 55), (x + 195, y + 55)])
            else:
                s.arrow([(x, y + 55), (x - 30, y + 55)])
    s.arrow([(1087, 226), (1087, 280)])
    s.text(140, 463, "Every run reports", 13, 600, INK)
    for i, (lab, k) in enumerate([("created", "read"), ("updated", "write"), ("untouched", "data"), ("reactivated", "control"), ("closed", "good")]):
        f, st, c = KIND[k]
        s.pill(260 + i * 170, 440, 150, 36, lab, f, st, c)
    s.text(600, 520, "Parsers are pure functions with no database access. Every step after upload is an idempotent River job.", 13, 400, MUTED)
    s.save("ingestion-pipeline.svg")


# ---------------------------------------------------------------- 4. CRD control plane
def crds():
    s = Svg(1200, 640, "CRDs and the control plane", "API group rampart.aspm.dev/v1alpha1. Kubernetes holds configuration; PostgreSQL holds data.")
    groups = [("Inventory and tenancy", 96, 90, [["Tenant", "HierarchyNode", "Application", "AccessBinding"]]),
              ("Sources and ingestion", 201, 90, [["ScanSource", "ReportIngest", "ScheduledScan"]]),
              ("Policies", 306, 126, [["DedupPolicy", "RiskPolicy", "SLAPolicy", "Policy"], ["Exception", "RetentionPolicy"]]),
              ("Integrations and identity", 447, 90, [["Connector", "IdentityProvider", "ClusterFeedMirror"]])]
    for label, y, h, rows in groups:
        s.frame(40, y, 430, h, label, "control")
        for r, row in enumerate(rows):
            x = 56
            for name in row:
                w = round(len(name) * 6.9 + 20)
                s.pill(x, y + 38 + r * 38, w, 28, name, "#FFFFFF", "#D97706", "#8A4B04", 12, 600)
                x += w + 8
    s.box(550, 236, 200, 160, "operator", ["controller-runtime", "one controller per kind", "idempotent reconcile", "leader election"], "control", 16, 12)
    s.arrow([(470, 290), (550, 290)], "control", label="watch spec", lpos=(510, 282))
    s.arrow([(550, 342), (470, 342)], "control", label="write status", lpos=(510, 362))
    s.box(830, 110, 330, 140, "PostgreSQL · config tables", ["tenant · application · scan_source", "connector · policy_object", "role_binding · upstream config"], "data")
    s.arrow([(750, 276), (830, 200)], "control", label="upsert", lpos=(778, 226))
    s.box(830, 296, 330, 120, "Data-plane targets", ["gateway · parser · enrich · policy", "notify · sync · query-api", "read config from PostgreSQL only"], "write")
    s.arrow([(995, 250), (995, 296)])
    s.box(830, 462, 330, 90, "Managed clusters (watch only)", ["PolicyReport · OpenReports", "Trivy Operator reports → ingest runs"], "ext")
    s.arrow([(830, 507), (750, 370)], "control")
    s.rect(40, 572, 1120, 46, "#FEF3C7", "#D97706", rx=10, sw=1.2)
    s.text(600, 600, "Rule: a custom resource holds desired state and bounded summaries. Findings, occurrences and audit rows never live in etcd.", 13, 600, "#8A4B04")
    s.save("crd-control-plane.svg")


# ---------------------------------------------------------------- 5. Dependency-Track
def dtrack():
    s = Svg(1200, 600, "Dependency-Track integration", "Four independent flows. Dependency-Track stays the SCA system of record; Rampart adds context, risk, SLA and workflow.")
    s.frame(40, 90, 480, 440, "Rampart", "write")
    s.frame(800, 90, 360, 440, "Dependency-Track", "data")
    rows = [(140, "CI upload", "POST /ingest/v1/sbom, once", "ingest-gateway + sync", "forward SBOM job", "POST /api/v1/bom", "analysis · policy evaluation", "A · forward SBOM (CycloneDX)", True, "write"),
            (240, None, None, "ingest-gateway /hooks", "verify secret · debounce", "Webhook publisher", "NEW_VULNERABILITY · BOM_PROCESSED", "B · event is only a trigger", False, "control"),
            (340, "Findings", "one risk score, SLA, tickets", "sync → merge pipeline", "RawFindings · reimport-close", "GET project · finding · violation", "REST API v1, X-Api-Key", "C · pull findings, violations, SBOM", False, "read"),
            (440, "Analyst or policy", "not_affected · risk_accepted", "triage write-back", "state · justification · expiry", "PUT /api/v1/analysis", "analysis state · suppression · VEX", "D · write back triage", True, "write")]
    for y, lt, ll, mt, ml, rt, rl, lab, to_dt, col in rows:
        if lt:
            s.box(60, y, 200, 64, lt, [ll], "ext", 13, 11)
        s.box(300, y, 200, 64, mt, [ml], "write", 13, 11)
        s.box(820, y, 320, 64, rt, [rl], "data", 13, 11)
        if to_dt:
            s.arrow([(520, y + 32), (800, y + 32)], col, label=lab, lpos=(660, y + 22))
        else:
            s.arrow([(800, y + 32), (520, y + 32)], col, label=lab, lpos=(660, y + 22))
    s.arrow([(260, 172), (300, 172)])
    s.arrow([(300, 372), (260, 372)])
    s.arrow([(260, 472), (300, 472)])
    s.arrow([(400, 304), (400, 340)], "control")
    s.text(390, 327, "enqueue debounced sync", 11, 500, MUTED, "end")
    s.text(600, 566, "Project → application mapping: project property · tag · existing asset · purl or repository · parent project · CEL rule · default. Unmapped projects are listed, never dropped.", 12, 400, MUTED)
    s.save("dependency-track-flows.svg")


# ---------------------------------------------------------------- 6. finding lifecycle
def lifecycle():
    s = Svg(1200, 590, "Finding lifecycle", "States use the OpenVEX vocabulary. not_affected, risk_accepted, out_of_scope and duplicate are never reopened by a rescan.")
    s.arrow([(24, 270), (80, 270)], label="ingest", lpos=(50, 262))
    s.box(80, 240, 150, 60, "open", ["new, untriaged"], "read")
    s.box(310, 240, 190, 60, "under_investigation", ["being triaged"], "read")
    s.box(590, 240, 150, 60, "affected", ["confirmed"], "warn")
    s.box(960, 240, 170, 60, "fixed", ["closed"], "good")
    s.box(590, 100, 200, 60, "not_affected", ["+ one of 5 justifications"], "data")
    s.box(590, 380, 200, 60, "risk_accepted", ["time-boxed · SLA paused"], "control")
    s.box(900, 100, 240, 60, "out_of_scope · duplicate", ["manual, from any active state"], "data", dash="5 4")
    s.arrow([(230, 270), (310, 270)])
    s.arrow([(500, 270), (590, 270)])
    s.arrow([(740, 270), (960, 270)], label="rescan no longer reports it", lpos=(850, 262))
    s.arrow([(405, 240), (405, 130), (590, 130)], label="false positive or unreachable", lpos=(498, 122))
    s.arrow([(405, 300), (405, 410), (590, 410)], label="accept with expiry", lpos=(498, 402))
    s.arrow([(740, 250), (900, 150)], dash="5 4")
    s.arrow([(690, 440), (690, 500), (175, 500), (175, 300)], "control", label="expiry → open again", lpos=(430, 492))
    s.arrow([(1045, 300), (1045, 548), (125, 548), (125, 300)], "warn", label="seen again by a rescan → reactivated (unless doNotReactivate)", lpos=(585, 540))
    s.save("finding-lifecycle.svg")


# ---------------------------------------------------------------- 7. deployment modes
def deployment():
    s = Svg(1200, 560, "Deployment modes", "The same image runs every mode. Helm value: mode = monolithic | simple-scalable | distributed.")
    s.frame(30, 96, 360, 330, "monolithic   ·   -target=all", "write")
    s.box(60, 150, 300, 200, "1 Deployment", ["gateway · parser · enrich", "policy · notify · sync", "query-api · web-ui", "operator · scheduler"], "write", 16, 13)
    s.text(210, 392, "evaluation · small teams · single node", 12, 400, MUTED)
    s.frame(420, 96, 360, 330, "simple-scalable", "read")
    s.box(440, 150, 320, 84, "write", ["gateway · parser · enrich", "policy · notify · sync"], "write")
    s.box(440, 246, 320, 60, "read", ["query-api · web-ui"], "read")
    s.box(440, 318, 320, 50, "operator + scheduler", [], "control")
    s.text(600, 400, "mid-size · independent read and write scaling", 12, 400, MUTED)
    s.frame(810, 96, 360, 330, "distributed", "control")
    names = [("gateway", "read"), ("query-api", "read"), ("web-ui", "read"), ("parser", "write"), ("enrich", "write"), ("policy", "write"),
             ("notify", "write"), ("sync", "write"), ("scheduler", "write"), ("operator", "control")]
    for i, (n, k) in enumerate(names):
        s.box(830 + (i % 3) * 110, 150 + (i // 3) * 52, 100, 42, n, [], k, 12)
    s.text(1050, 334, "KEDA per worker queue", 12, 600, "#8A4B04")
    s.text(990, 400, "large · multi-tenant · read replicas", 12, 400, MUTED)
    s.box(30, 452, 1140, 74, "Shared state: PostgreSQL + object storage", ["Targets are stateless, so switching modes needs no data migration."], "data")
    s.save("deployment-modes.svg")


# ---------------------------------------------------------------- 8. SSO
def sso():
    s = Svg(1200, 660, "SSO login flow (OIDC, backend-for-frontend)", "The browser only ever holds an HttpOnly session cookie. Tokens stay on the server.")
    actors = [(150, "Browser (SPA)", "read"), (480, "query-api", "write"), (820, "Identity provider", "ext"), (1080, "PostgreSQL", "data")]
    for x, name, k in actors:
        s.box(x - 95, 86, 190, 44, name, [], k)
        s.raw(f'<line x1="{x}" y1="130" x2="{x}" y2="606" stroke="#CBD5E1" stroke-width="1.5" stroke-dasharray="4 5"/>')

    def msg(y, a, b, label, dashed=False, lx=None):
        s.arrow([(a, y), (b, y)], "line", dash="5 4" if dashed else None, label=label, lpos=(lx or (a + b) / 2, y - 8))

    msg(166, 150, 480, "1 · GET /auth/login?return_to=…")
    msg(206, 480, 150, "2 · 302 to IdP with state, nonce, PKCE challenge", True)
    msg(246, 150, 820, "3 · authorization request (code flow)", lx=650)
    msg(286, 820, 150, "4 · sign-in + MFA, then 302 with code", True, lx=650)
    msg(326, 150, 480, "5 · GET /auth/oidc/<idp>/callback?code&state")
    msg(366, 480, 820, "6 · token exchange (code + PKCE verifier)")
    msg(406, 820, 480, "7 · ID token, refresh token", True)
    s.rect(340, 424, 280, 48, "#E6FAF8", "#0E9F9A", rx=8, sw=1.2)
    s.text(480, 444, "validate signature, iss, aud, nonce", 12, 500, "#0B5E5B")
    s.text(480, 462, "map claims → user and teams (JIT)", 12, 500, "#0B5E5B")
    msg(500, 480, 1080, "8 · create session row")
    msg(540, 480, 150, "9 · Set-Cookie __Host-rampart_session (HttpOnly) + 302", True)
    msg(580, 150, 480, "10 · API calls: cookie + X-CSRF-Token")
    s.text(600, 636, "Also supported: SAML 2.0 · SCIM 2.0 provisioning · CI OIDC federation · API tokens · Kubernetes ServiceAccount tokens · device flow for the CLI", 12, 400, MUTED)
    s.save("sso-flow.svg")


# ---------------------------------------------------------------- 9. frontend layout
def frontend():
    import re as _re
    s = Svg(1200, 740, "Frontend layout: findings workbench", "Three docked panes divided by rules. No cards, no shadows. The score bar in each row shows what the risk is made of.")
    UI = "'Red Hat Text', 'Noto Sans Arabic', 'Segoe UI', Arial, sans-serif"
    MONO = "'Red Hat Mono', ui-monospace, Menlo, monospace"
    INK2, SUB, RULE, WASH, BR = "#1B2233", "#5B6679", "#D5DAE3", "#F3F5F8", "#4353D6"
    RISK = {"critical": "#B4232A", "high": "#D9622B", "medium": "#C99A1A", "low": "#6B7C93"}
    SEG = {"base": "#55607A", "threat": "#B4232A", "context": "#D9622B", "minus": "#19A38C"}
    X0, Y0, W, H = 30, 84, 1140, 630
    s.raw(f'<g font-family="{UI}">')
    s.rect(X0, Y0, W, H, "#FFFFFF", RULE, rx=6, sw=1.2)
    line = lambda x1, y1, x2, y2, c=RULE, w=1: s.raw(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{c}" stroke-width="{w}"/>')
    t = lambda x, y, txt, size=13, wt=400, fill=INK2, anchor="start", fam=None: s.raw(
        f'<text x="{x}" y="{y}" font-size="{size}" font-weight="{wt}" fill="{fill}" text-anchor="{anchor}"' + (f' font-family="{fam}"' if fam else "") + f'>{escape(txt)}</text>')
    # top bar
    mark = "".join(_re.findall(r"<polygon[^>]*/>", open(os.path.join(OUT, "logo-mark.svg")).read()))
    s.raw(f'<g transform="translate(46 94) scale(0.375)">{mark}</g>')
    t(78, 112, "rampart", 17, 800, INK2, fam="'Red Hat Display', " + UI)
    t(170, 111, "acme", 13, 600); t(206, 111, "/", 13, 400, SUB); t(218, 111, "Fintech", 13, 600)
    s.rect(420, 95, 380, 26, "#FFFFFF", RULE, rx=2, sw=1); t(432, 112, "Search findings, assets, CVEs", 12.5, 400, SUB)
    s.rect(760, 99, 32, 18, WASH, RULE, rx=2, sw=1); t(776, 112, "/", 11.5, 600, SUB, "middle")
    s.rect(1128, 96, 24, 24, INK2, INK2, rx=2, sw=0); t(1140, 112, "SA", 10.5, 700, "#FFFFFF", "middle")
    line(X0, 128, X0 + W, 128)
    # nav
    s.raw(f'<path d="M30 128H200V714H36a6 6 0 0 1-6-6Z" fill="{WASH}"/>'); line(200, 128, 200, 714)
    y = 158
    for grp in (["Overview", "Findings", "Applications", "Inventory", "Vulnerabilities"], ["Workflow", "Compliance"], ["Ingestion", "Policies", "Integrations", "Administration"]):
        for n in grp:
            if n == "Findings":
                s.rect(30, y - 18, 3, 26, BR, BR, rx=0, sw=0)
            t(50, y, n, 13, 700 if n == "Findings" else 400, INK2 if n == "Findings" else SUB)
            y += 30
        y += 16
    # query bar
    t(216, 154, "state:open  risk:critical,high  app:payments-api", 12.5, 500, INK2, fam=MONO)
    t(746, 154, "73 findings", 12.5, 600, INK2, "end"); t(828, 154, "Save view", 12.5, 600, BR, "end")
    line(200, 170, 840, 170)
    # facets
    line(356, 170, 356, 714)
    fy = 196
    for title, items in [("Risk", [("Critical", "12", True), ("High", "61", True), ("Medium", "240", False), ("Low", "118", False)]),
                         ("Detected by", [("Trivy", "140", False), ("Semgrep", "96", False), ("Grype", "88", False), ("Gitleaks", "9", False)]),
                         ("Deadline", [("Overdue", "7", False), ("Due this week", "19", False)]),
                         ("Signals", [("Known exploited", "4", False), ("Fix available", "203", False)])]:
        t(216, fy, title, 12.5, 700); fy += 22
        for a_, b_, on in items:
            s.rect(216, fy - 9, 9, 9, BR if on else "#FFFFFF", BR if on else "#9AA4B5", rx=1, sw=1)
            t(232, fy, a_, 12, 600 if on else 400, INK2 if on else SUB); t(344, fy, b_, 12, 400, SUB, "end")
            fy += 21
        fy += 16
    # table
    for cx, h_, anc in [(394, "Score", "start"), (496, "Finding", "start"), (702, "Asset", "start"), (828, "Due", "end")]:
        t(cx, 189, h_, 12, 600, SUB, anc)
    line(356, 198, 840, 198)
    rows = [(950, "critical", "CVE-2024-3094 in xz-utils", "liblzma 5.6.0, fixed in 5.6.1", "api, prod", "2 d left", (400, 450, 180, 80)),
            (905, "critical", "AWS access key committed", "config/deploy.env, line 14", "payments-api", "3 d over", (600, 250, 55, 0)),
            (860, "critical", "SQL injection in OrderRepo", "src/orders/repo.go", "payments-api", "5 d left", (600, 0, 260, 0)),
            (790, "high", "CVE-2023-44487 in x/net", "HTTP/2 rapid reset", "gateway, prod", "9 d left", (400, 210, 180, 0)),
            (720, "high", "S3 bucket is not encrypted", "infra/prod/storage.tf", "infra", "12 d left", (400, 0, 320, 0)),
            (690, "high", "Container runs as root", "deploy/worker.yaml", "worker, prod", "14 d left", (400, 0, 290, 0)),
            (640, "high", "Email change has no CSRF check", "POST /account/email", "web", "21 d left", (400, 0, 240, 0)),
            (410, "medium", "lodash 4.17.20 is outdated", "package-lock.json", "web", "60 d left", (200, 60, 150, 0)),
            (380, "medium", "Stack traces shown to users", "GET /api/orders", "api, staging", "75 d left", (200, 0, 180, 0))]
    for i, (score, band, title, sub, asset, due, segs) in enumerate(rows):
        y = 198 + i * 46
        if i == 0:
            s.rect(357, y + 1, 483, 45, WASH, WASH, rx=0, sw=0); s.rect(357, y + 1, 3, 45, BR, BR, rx=0, sw=0)
        line(368, y + 46, 840, y + 46, "#E6E9EF")
        c, gx, gy = RISK[band], 376, y + 24
        if band == "critical":
            s.raw(f'<polygon points="{gx},{gy-5.5} {gx+5.5},{gy} {gx},{gy+5.5} {gx-5.5},{gy}" fill="{c}"/>')
        elif band == "high":
            s.raw(f'<polygon points="{gx},{gy-5} {gx+5.5},{gy+4.5} {gx-5.5},{gy+4.5}" fill="{c}"/>')
        else:
            s.rect(gx - 4.5, gy - 4.5, 9, 9, c, c, rx=0, sw=0)
        s.raw(f'<text x="394" y="{y+29}" font-size="14" font-weight="700" fill="{INK2}" style="font-variant-numeric:tabular-nums">{score}</text>')
        bx = 430
        for key, v in zip(("base", "threat", "context"), segs[:3]):
            if v:
                s.rect(bx, y + 18, v * 0.06 - 1, 11, SEG[key], SEG[key], rx=0, sw=0); bx += v * 0.06
        if segs[3]:
            s.rect(bx + 1, y + 18, segs[3] * 0.06, 11, "#FFFFFF", SEG["minus"], rx=0, sw=1.2)
        t(496, y + 21, title, 13, 600); t(496, y + 37, sub, 11.5, 400, SUB)
        t(702, y + 29, asset, 12, 400, SUB)
        over = due.endswith("over")
        t(828, y + 29, due, 12, 700 if over else 400, RISK["critical"] if over else SUB, "end")
    line(356, 670, 840, 670)
    t(372, 697, "3 selected", 12.5, 700)
    bxx = 462
    for a_ in ["Change state", "Assign", "Create ticket", "Accept risk"]:
        t(bxx, 697, a_, 12.5, 600, BR); bxx += len(a_) * 7.0 + 26
    # inspector
    line(840, 128, 840, 714)
    ix = 860
    t(ix, 158, "CVE-2024-3094 in xz-utils", 16, 700)
    t(ix, 178, "Open, critical, due in 2 days. Owner: platform team.", 12, 400, SUB)
    s.raw(f'<text x="{ix}" y="226" font-size="30" font-weight="700" fill="{INK2}" style="font-variant-numeric:tabular-nums">950</text>')
    bx = ix + 70
    for key, v in (("base", 400), ("threat", 450), ("context", 180)):
        s.rect(bx, 206, v * 0.2 - 1.5, 20, SEG[key], SEG[key], rx=0, sw=0); bx += v * 0.2
    s.rect(bx + 2, 206, 16, 20, "#FFFFFF", SEG["minus"], rx=0, sw=1.5)
    fy = 258
    for key, lab, val in [("base", "Scanner severity: high", "400"), ("threat", "On the CISA exploited list", "300"), ("threat", "Likely to be exploited (EPSS 0.94)", "150"),
                          ("context", "Reachable from the internet", "100"), ("context", "Handles card data", "80"), ("minus", "Behind a web application firewall", "−80")]:
        if key == "minus":
            s.rect(ix, fy - 9, 9, 9, "#FFFFFF", SEG[key], rx=0, sw=1.2)
        else:
            s.rect(ix, fy - 9, 9, 9, SEG[key], SEG[key], rx=0, sw=0)
        t(ix + 18, fy, lab, 12.5, 400); s.raw(f'<text x="1150" y="{fy}" font-size="12.5" font-weight="600" fill="{INK2}" text-anchor="end" style="font-variant-numeric:tabular-nums">{val}</text>')
        fy += 23
    line(ix, fy - 4, 1150, fy - 4)
    tx = ix
    for i, tb in enumerate(["Overview", "Evidence", "Occurrences", "Activity"]):
        t(tx, fy + 24, tb, 12.5, 700 if i == 0 else 400, INK2 if i == 0 else SUB)
        if i == 0:
            line(tx, fy + 31, tx + 56, fy + 31, BR, 2)
        tx += len(tb) * 6.9 + 16
    fy += 62
    for k, v, mono in [("Package", "pkg:deb/debian/xz-utils@5.6.0", True), ("Fixed in", "5.6.1+really5.4.5", True), ("Detected by", "Trivy and Dependency-Track", False),
                       ("Asset", "ghcr.io/example/api", True), ("First seen", "3 days ago", False)]:
        t(ix, fy, k, 12, 400, SUB); t(ix + 84, fy, v, 11.5 if mono else 12, 400, INK2, fam=MONO if mono else None)
        fy += 24
    s.rect(ix, 664, 110, 32, BR, BR, rx=2, sw=0); t(ix + 55, 685, "Change state", 12.5, 700, "#FFFFFF", "middle")
    s.rect(ix + 120, 664, 84, 32, "#FFFFFF", "#9AA4B5", rx=2, sw=1); t(ix + 162, 685, "Accept risk", 12.5, 600, INK2, "middle")
    s.rect(ix + 214, 664, 76, 32, "#FFFFFF", "#9AA4B5", rx=2, sw=1); t(ix + 252, 685, "New ticket", 12.5, 600, INK2, "middle")
    s.raw('</g>')
    s.save("frontend-layout.svg")


# ---------------------------------------------------------------- 10. domain model
def domain():
    s = Svg(1200, 600, "Domain model", "Entity-oriented. One deduplicated Finding collects many per-tool Occurrences.")
    s.box(40, 96, 240, 50, "Tenant", [], "control")
    s.box(40, 186, 240, 50, "HierarchyNode", ["business unit tree"], "control", 13, 11)
    s.box(40, 276, 240, 60, "Application", ["criticality · exposure · owners"], "control", 14, 11)
    s.box(40, 386, 115, 50, "Service", [], "control", 13)
    s.box(165, 386, 115, 50, "Environment", [], "control", 13)
    s.arrow([(160, 146), (160, 186)])
    s.arrow([(160, 236), (160, 276)])
    s.arrow([(97, 336), (97, 386)])
    s.arrow([(222, 336), (222, 386)])
    s.box(360, 266, 210, 80, "Asset", ["repository · image · workload", "package · url · host · cloud"], "read")
    s.text(465, 368, "edges: builds · runs · contains", 11, 400, MUTED)
    s.arrow([(280, 306), (360, 306)])
    s.box(660, 100, 230, 60, "IngestRun", ["one report · context · stats"], "write", 14, 11)
    s.box(660, 250, 230, 112, "Finding", ["finding_key (fingerprint)", "state · severity · risk score", "SLA due · owner · tags"], "core", 16, 12)
    s.arrow([(570, 306), (660, 306)])
    s.arrow([(775, 160), (775, 250)], label="creates or updates", lpos=(783, 210), lanchor="start")
    s.box(970, 100, 200, 60, "Occurrence", ["per tool, per run · raw evidence"], "write", 14, 11)
    s.box(970, 190, 200, 50, "FindingEvent", ["append-only timeline"], "data", 13, 11)
    s.box(970, 270, 200, 50, "RiskAcceptance", ["expiry · approval"], "data", 13, 11)
    s.box(970, 350, 200, 50, "TicketLink", ["Jira · GitHub · GitLab"], "data", 13, 11)
    s.arrow([(890, 270), (970, 135)])
    s.arrow([(890, 290), (970, 215)])
    s.arrow([(890, 310), (970, 295)])
    s.arrow([(890, 335), (970, 375)])
    s.box(660, 450, 230, 70, "Vulnerability (global)", ["aliases · CVSS · EPSS · KEV · SSVC"], "data", 14, 11)
    s.box(360, 450, 210, 70, "Rule · Taxonomy (global)", ["CWE → OWASP · PCI · ISO · SSDF"], "data", 14, 11)
    s.arrow([(775, 362), (775, 450)])
    s.arrow([(680, 362), (560, 450)])
    s.text(600, 566, "Every tenant-owned row carries tenant_id with row-level security. Vulnerability, weakness and taxonomy tables are shared and read-only.", 12, 400, MUTED)
    s.save("domain-model.svg")


# ---------------------------------------------------------------- 11. risk score
def risk():
    s = Svg(1200, 500, "Explainable risk score", "Default policy, worked example. Score = clamp(base + Σ factors, 0, 1000). Every factor is a CEL expression in a RiskPolicy.")
    x0, scale = 300, 0.74
    factors = [("Base severity: high", 400, "#4353D6"), ("Listed in CISA KEV", 300, "#DC2626"), ("EPSS ≥ 0.5", 150, "#DC2626"),
               ("Internet-facing application", 100, "#D97706"), ("Handles PCI data", 80, "#D97706"), ("Behind a WAF (compensating control)", -80, "#16A34A")]
    cum, y = 0, 110
    for lab, pts, col in factors:
        a, b = (cum, cum + pts) if pts > 0 else (cum + pts, cum)
        s.text(x0 - 16, y + 19, lab, 13, 500, INK, "end")
        s.rect(x0 + a * scale, y, (b - a) * scale, 28, col, col, rx=4, sw=0)
        s.text(x0 + b * scale + 10, y + 19, ("+" if pts > 0 else "−") + str(abs(pts)), 13, 700, INK, "start")
        cum += pts
        y += 42
    s.text(x0 - 16, y + 21, "Risk score", 14, 700, INK, "end")
    s.rect(x0, y, cum * scale, 32, "#1E2A5E", "#1E2A5E", rx=4, sw=0)
    s.text(x0 + cum * scale + 10, y + 22, f"{cum}  →  band: critical", 14, 700, "#7F1D1D", "start")
    ay = y + 70
    s.raw(f'<line x1="{x0}" y1="{ay}" x2="{x0 + 1000 * scale}" y2="{ay}" stroke="#94A3B8" stroke-width="1.5"/>')
    for v, lab in [(0, "0"), (300, "300"), (600, "600"), (800, "800"), (1000, "1000")]:
        xx = x0 + v * scale
        s.raw(f'<line x1="{xx}" y1="{ay - 5}" x2="{xx}" y2="{ay + 5}" stroke="#94A3B8" stroke-width="1.5"/>')
        s.text(xx, ay + 22, lab, 11, 400, MUTED)
    for a, b, lab, k in [(0, 300, "low", "data"), (300, 600, "medium", "read"), (600, 800, "high", "control"), (800, 1000, "critical", "warn")]:
        s.text(x0 + (a + b) / 2 * scale, ay - 10, lab, 12, 700, KIND[k][2])
    s.text(600, 476, "The band selects the SLA. A KEV due date caps it. Scores recompute when intelligence or asset context changes, without a rescan.", 12, 400, MUTED)
    s.save("risk-score.svg")


# ---------------------------------------------------------------- 12. integration tiers
def integration_tiers():
    s = Svg(1200, 560, "Integration tiers", "Three kinds of integration, four levels of effort. Every tier implements the same contracts and passes the same conformance kit.")
    cols = [("0 · Standard format", ["no work", "anyone"], "data"), ("1 · Declarative YAML", ["hours", "tenant admin, data only"], "write"),
            ("2 · Plugin", ["days, any language", "platform admin, signed"], "control"), ("3 · Built-in Go", ["core repository", "maintainers"], "read")]
    rows = [("Parser", "report file in", [["SARIF · CycloneDX · SPDX", "OpenVEX · Generic JSON"], ["ParserMapping", "record path + CEL fields"], ["WASI module in a sandbox", "stdin → JSONL findings"], ["Parser interface", "Trivy · Semgrep · Gitleaks"]]),
            ("Source", "API pull in", [["Generic JSON push", "to the ingest API"], ["Declarative source", "auth · paging · cursor"], ["gRPC plugin, own pod", "Discover · Pull"], ["Source interface", "Dependency-Track"]]),
            ("Tracker · Notifier", "tickets and messages out", [["Signed webhook", "CloudEvents"], ["HTTP request templates", "create · update · get"], ["gRPC plugin, own pod", "CreateIssue · Send"], ["Tracker · Notifier", "Jira · Slack · Teams"]])]
    x0, cw, gap = 250, 220, 12
    for i, (t, lines, k) in enumerate(cols):
        s.box(x0 + i * (cw + gap), 96, cw, 84, t, lines, k, 14, 12)
    for r, (name, sub, cells) in enumerate(rows):
        y = 200 + r * 100
        s.text(40, y + 38, name, 15, 700, INK, "start")
        s.text(40, y + 58, sub, 12, 400, MUTED, "start")
        for i, lines in enumerate(cells):
            s.box(x0 + i * (cw + gap), y, cw, 84, lines[0], lines[1:], "ext", 13, 12)
    s.arrow([(250, 516), (1166, 516)], label="more effort, more capability", lpos=(708, 508))
    s.text(600, 542, "The core owns scheduling, retries, rate limits, secrets, tenancy and audit. An integration only translates.", 12, 400, MUTED)
    s.save("integration-tiers.svg")


for fn in (system_context, architecture, ingestion, crds, dtrack, lifecycle, deployment, sso, frontend, domain, risk, integration_tiers):
    fn()
print("ok", sorted(os.listdir(OUT)))
