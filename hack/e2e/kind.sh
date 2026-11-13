#!/usr/bin/env bash
# End-to-end test of the Helm chart and the operator on a throwaway kind cluster. It runs in CI.
#
# It refuses to run unless the current kubectl context is a local kind cluster, so it can never
# touch a real cluster even if someone starts it on a laptop by mistake.
#
# Required: IMAGE_REPO and IMAGE_TAG (the image already loaded into kind).
set -euo pipefail

: "${IMAGE_REPO:?set IMAGE_REPO}" "${IMAGE_TAG:?set IMAGE_TAG}"
NS=rampart-system
REL=rampart
CHART="$(cd "$(dirname "$0")/../.." && pwd)/deploy/helm/rampart"
SA="$REL"                       # the chart names the service account after the release
TEAM_NS=e2e-team
SECRET_VALUE="e2e-super-secret-token"

# --- safety guard -------------------------------------------------------------------------------
ctx="$(kubectl config current-context)"
server="$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')"
case "$ctx" in kind-*) ;; *) echo "refusing to run on context '$ctx': this test only runs on a kind cluster" >&2; exit 2 ;; esac
case "$server" in https://127.0.0.1:*|https://localhost:*|https://\[::1\]:*) ;; *) echo "refusing to run against '$server': not a local API server" >&2; exit 2 ;; esac

log() { printf '\n=== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
assert_eq() { [ "$1" = "$2" ] || fail "$3: got '$1', want '$2'"; }
assert_contains() { case "$1" in *"$2"*) ;; *) fail "$3: '$1' does not contain '$2'" ;; esac; }

dump() {
  echo; echo "##### diagnostics #####"
  kubectl get all,jobs,pvc,clusters.postgresql.cnpg.io -A 2>&1 | tail -60 || true
  kubectl -n "$NS" describe pods 2>&1 | tail -120 || true
  for r in "deploy/$REL" "job/$REL-migrate-1"; do
    echo "--- logs $r"
    kubectl -n "$NS" logs "$r" --all-containers --tail=80 2>&1 || true
    echo "--- previous logs $r"
    kubectl -n "$NS" logs "$r" --all-containers --previous --tail=80 2>&1 || true
  done
  kubectl -n "$NS" get events --sort-by=.lastTimestamp 2>&1 | tail -40 || true
}
trap 'dump' ERR

wait_until() { # wait_until <seconds> <description> <command...>
  local t=$1 d=$2; shift 2
  for _ in $(seq 1 "$t"); do if "$@" >/dev/null 2>&1; then return 0; fi; sleep 1; done
  fail "timed out waiting for: $d"
}

helm_args=(
  --namespace "$NS" --set "image.repository=$IMAGE_REPO" --set "image.tag=$IMAGE_TAG" --set image.pullPolicy=Never
  --set database.cnpg.instances=1 --set database.cnpg.storage.size=1Gi --set seaweedfs.persistence.size=1Gi
)

log "Install the CloudNativePG operator (the chart's bundled database needs it)"
helm repo add cnpg https://cloudnative-pg.github.io/charts >/dev/null
helm repo update cnpg >/dev/null
helm upgrade --install cnpg cnpg/cloudnative-pg --namespace cnpg-system --create-namespace --wait --timeout 5m

log "helm install (plain Job for migrations on install, D4)"
helm install "$REL" "$CHART" "${helm_args[@]}" --create-namespace --wait --wait-for-jobs --timeout 10m

log "Installed objects"
for crd in tenants applications scansources connectors; do kubectl get crd "$crd.rampart.aspm.dev" >/dev/null || fail "CRD $crd missing"; done
kubectl -n "$NS" wait --for=condition=complete "job/$REL-migrate-1" --timeout=60s
kubectl -n "$NS" rollout status "deploy/$REL" --timeout=120s
kubectl -n "$NS" get secret "$REL-db-app" "$REL-db-system" "$REL-session" "$REL-objectstore" >/dev/null

log "Pod hardening (non-root, read-only root filesystem, no privilege escalation)"
pod="$(kubectl -n "$NS" get pod -l "app.kubernetes.io/name=rampart,app.kubernetes.io/instance=$REL,app.kubernetes.io/component!=migrate" -o jsonpath='{.items[0].metadata.name}')"
assert_eq "$(kubectl -n "$NS" get pod "$pod" -o jsonpath='{.spec.securityContext.runAsNonRoot}')" "true" "runAsNonRoot"
assert_eq "$(kubectl -n "$NS" get pod "$pod" -o jsonpath='{.spec.containers[0].securityContext.readOnlyRootFilesystem}')" "true" "readOnlyRootFilesystem"
assert_eq "$(kubectl -n "$NS" get pod "$pod" -o jsonpath='{.spec.containers[0].securityContext.allowPrivilegeEscalation}')" "false" "allowPrivilegeEscalation"

log "HTTP surface through the Service"
kubectl -n "$NS" port-forward "svc/$REL" 18080:8080 19090:9090 >/tmp/pf.log 2>&1 &
pf=$!; trap 'kill $pf 2>/dev/null || true; dump' ERR
wait_until 30 "port-forward" curl -fsS http://127.0.0.1:19090/healthz
assert_eq "$(curl -fsS http://127.0.0.1:19090/readyz)" "ready" "/readyz"
assert_contains "$(curl -fsS http://127.0.0.1:19090/metrics)" "go_goroutines" "/metrics is real"
assert_contains "$(curl -fsS http://127.0.0.1:18080/api/v1/ui-config)" '"product":"Rampart"' "ui-config"
assert_eq "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18080/api/v1/findings)" "401" "findings without credentials"
assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -H 'X-Tenant-ID: 01931f6a-0000-7000-8000-000000000001' http://127.0.0.1:18080/api/v1/findings)" "401" "a forged tenant header is not credentials"
assert_eq "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18080/)" "200" "the embedded web UI is served"
csp="$(curl -sI http://127.0.0.1:18080/ | tr -d '\r' | grep -i '^content-security-policy' || true)"
assert_contains "$csp" "default-src 'self'" "CSP"

log "The first administrator: the password is in a Secret, sign-in works, and it is audited (D3)"
admin_pw="$(kubectl -n "$NS" get secret "$REL-admin" -o jsonpath='{.data.password}' | base64 -d)"
[ "${#admin_pw}" -ge 20 ] || fail "the generated administrator password is too short (${#admin_pw})"
assert_eq "$(kubectl -n "$NS" get secret "$REL-admin" -o jsonpath='{.data.username}' | base64 -d)" "admin" "administrator username"
assert_contains "$(curl -fsS http://127.0.0.1:18080/api/v1/ui-config)" '"type":"password"' "ui-config offers password sign-in (no identity provider is configured)"
jar="$(mktemp)"
assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -d '{"username":"admin","password":"definitely-not-it-123"}' http://127.0.0.1:18080/auth/local/login)" "401" "a wrong password"
assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -c "$jar" -H 'Content-Type: application/json' -d "{\"username\":\"admin\",\"password\":\"$admin_pw\"}" http://127.0.0.1:18080/auth/local/login)" "204" "the generated password signs in"
assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -H 'Content-Type: application/x-www-form-urlencoded' -d "username=admin&password=$admin_pw" http://127.0.0.1:18080/auth/local/login)" "415" "a form post (cross-site forms cannot send JSON)"
assert_contains "$(curl -fsS -b "$jar" http://127.0.0.1:18080/auth/session)" '"name":"Local administrator"' "the session belongs to the local administrator"
assert_contains "$(curl -fsS -b "$jar" http://127.0.0.1:18080/api/v1/me/permissions)" '"role":"admin"' "the local administrator is an admin"
rm -f "$jar"

log "The operator started in-cluster and has no errors"
logs="$(kubectl -n "$NS" logs "deploy/$REL" -c rampart --tail=500)"
assert_contains "$logs" "operator starting" "operator log"
case "$logs" in *'level=ERROR'*|*'"level":"ERROR"'*) fail "errors in the application log:\n$logs" ;; esac

log "Applying a Tenant, an Application and a ScanSource shows Ready=True (Phase 0 exit criterion)"
kubectl apply -f - <<YAML
apiVersion: rampart.aspm.dev/v1alpha1
kind: Tenant
metadata: {name: e2e}
spec: {displayName: "E2E", namespaces: ["$TEAM_NS"]}
YAML
kubectl wait --for=condition=Ready tenant/e2e --timeout=120s
kubectl get namespace "$TEAM_NS" >/dev/null || fail "the operator did not create the tenant namespace"
kubectl -n "$TEAM_NS" get rolebinding rampart-secret-reader >/dev/null || fail "the secret-reader binding is missing"
assert_eq "$(kubectl -n "$TEAM_NS" get rolebinding rampart-secret-reader -o jsonpath='{.roleRef.kind}/{.roleRef.name}')" "ClusterRole/$REL-tenant-secret-reader" "binding references only the reader role"

kubectl apply -f - <<YAML
apiVersion: rampart.aspm.dev/v1alpha1
kind: Application
metadata: {name: checkout, namespace: $TEAM_NS}
spec: {displayName: "Checkout", businessCriticality: critical, internetFacing: true}
---
apiVersion: v1
kind: Secret
metadata: {name: gh, namespace: $TEAM_NS}
stringData: {token: "$SECRET_VALUE"}
---
apiVersion: rampart.aspm.dev/v1alpha1
kind: ScanSource
metadata: {name: github, namespace: $TEAM_NS}
spec: {scannerFamily: semgrep, secretRef: {name: gh, key: token}}
---
apiVersion: rampart.aspm.dev/v1alpha1
kind: Connector
metadata: {name: e2e-webhook, namespace: $TEAM_NS}
spec:
  type: webhook
  direction: outbound
  webhook:
    url: "https://example.com/webhook"
    secretRef: {name: gh, key: token}
YAML
kubectl -n "$TEAM_NS" wait --for=condition=Ready application/checkout scansource/github connector/e2e-webhook --timeout=120s
[ -n "$(kubectl -n "$TEAM_NS" get application checkout -o jsonpath='{.status.applicationId}')" ] || fail "status.applicationId is empty"

log "An Application in a namespace no Tenant lists is not ready, and says why (D17, D20)"
kubectl create namespace orphan-ns >/dev/null
kubectl apply -f - <<YAML
apiVersion: rampart.aspm.dev/v1alpha1
kind: Application
metadata: {name: lost, namespace: orphan-ns}
spec: {displayName: "Lost"}
YAML
wait_until 60 "TenantNotFound" bash -c "[ \"\$(kubectl -n orphan-ns get application lost -o jsonpath='{.status.conditions[?(@.type==\"Ready\")].reason}')\" = TenantNotFound ]"

log "RBAC: Secrets are readable only inside tenant namespaces (D1)"
as="--as=system:serviceaccount:$NS:$SA"
assert_eq "$(kubectl auth can-i get secrets -n "$TEAM_NS" "$as")" "yes" "operator reads Secrets in a tenant namespace"
assert_eq "$(kubectl auth can-i get secrets -n kube-system "$as")" "no" "operator must not read kube-system Secrets"
assert_eq "$(kubectl auth can-i get secrets -n "$NS" "$as")" "no" "operator must not read its own namespace's Secrets"
assert_eq "$(kubectl auth can-i list secrets --all-namespaces "$as")" "no" "operator must not list Secrets cluster-wide"
assert_eq "$(kubectl auth can-i delete namespaces "$as")" "no" "operator must not delete namespaces"
assert_eq "$(kubectl auth can-i create clusterroles "$as")" "no" "operator must not create ClusterRoles"

log "Database: roles, bindings and encrypted secret material"
pg() { kubectl -n "$NS" exec "$REL-postgres-1" -c postgres -- psql -U postgres -d rampart -Atc "$1"; }
assert_eq "$(pg "select count(*) from local_admin where username='admin' and password_hash like '\$argon2id\$%'")" "1" "the local administrator is stored as an argon2id hash"
assert_eq "$(pg "select string_agg(action, ',' order by at) from audit_event where action like 'local_login%'")" "local_login_failed,local_login_success" "the sign-ins were audited"
case "$(kubectl -n "$NS" logs "deploy/$REL" -c rampart --tail=1000)" in *"$admin_pw"*) fail "the administrator password is in the application log" ;; esac
assert_eq "$(pg "select rolcanlogin::text||rolbypassrls::text from pg_roles where rolname='rampart_app'")" "truefalse" "rampart_app: login, RLS enforced"
assert_eq "$(pg "select rolcanlogin::text||rolbypassrls::text from pg_roles where rolname='rampart_system'")" "truetrue" "rampart_system: login, bypass RLS"
assert_eq "$(pg "select tenant_id is not null from tenant_namespace where namespace='$TEAM_NS'")" "t" "namespace ownership recorded (D20)"
assert_eq "$(pg "select count(*) from application where slug='checkout'")" "1" "application stored"
assert_eq "$(pg "select count(*) from connector where name='e2e-webhook'")" "1" "connector stored"
assert_eq "$(pg "select count(*) from secret_material")" "2" "two secrets synced (scansource and connector)"
assert_eq "$(pg "select count(*) from secret_material where position('$SECRET_VALUE'::bytea in encrypted_value) > 0")" "0" "no Secret is stored in plaintext"
assert_eq "$(pg "select count(*) from information_schema.tables where table_schema='river' and table_name='river_job'")" "1" "river schema"

before_session="$(kubectl -n "$NS" get secret "$REL-session" -o jsonpath='{.data.session\.key}')"
before_dbapp="$(kubectl -n "$NS" get secret "$REL-db-app" -o jsonpath='{.data.password}')"

log "helm upgrade (pre-upgrade migration hook, rolling update)"
helm upgrade "$REL" "$CHART" "${helm_args[@]}" --set resources.requests.cpu=400m --wait --wait-for-jobs --timeout 10m
assert_eq "$(helm -n "$NS" status "$REL" -o json | python3 -c 'import sys,json;print(json.load(sys.stdin)["info"]["status"])')" "deployed" "release status"
assert_eq "$(kubectl -n "$NS" get secret "$REL-session" -o jsonpath='{.data.session\.key}')" "$before_session" "the session key survives an upgrade (sessions stay valid)"
assert_eq "$(kubectl -n "$NS" get secret "$REL-db-app" -o jsonpath='{.data.password}')" "$before_dbapp" "the database password survives an upgrade"
kubectl wait --for=condition=Ready tenant/e2e --timeout=60s
kubectl -n "$TEAM_NS" wait --for=condition=Ready application/checkout --timeout=60s

log "helm rollback (no database restore needed, doc 15)"
helm rollback "$REL" 1 --namespace "$NS" --wait --timeout 10m
kubectl -n "$NS" rollout status "deploy/$REL" --timeout=120s
kubectl -n "$TEAM_NS" wait --for=condition=Ready application/checkout --timeout=60s

log "No restarts, no crash loops"
restarts="$(kubectl -n "$NS" get pods -o jsonpath='{range .items[*]}{.status.containerStatuses[*].restartCount}{" "}{end}')"
for n in $restarts; do [ "$n" -le 1 ] || fail "a container restarted $n times: $restarts"; done

kill "$pf" 2>/dev/null || true
trap - ERR
log "OK"
