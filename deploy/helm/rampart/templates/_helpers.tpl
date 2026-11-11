{{/*
Expand the name of the chart.
*/}}
{{- define "rampart.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "rampart.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "rampart.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "rampart.labels" -}}
helm.sh/chart: {{ include "rampart.chart" . }}
{{ include "rampart.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "rampart.selectorLabels" -}}
app.kubernetes.io/name: {{ include "rampart.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "rampart.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "rampart.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}


{{/*
CloudNativePG cluster name.
*/}}
{{- define "rampart.cnpgName" -}}
{{- printf "%s-postgres" (include "rampart.fullname" .) -}}
{{- end }}

{{/*
Database credentials as environment variables (D4). Least privilege per workload:
  role "runtime": rampart_app (RLS enforced) and rampart_system (tenant bootstrap).
  role "migrate": rampart_owner only, used by `rampart migrate up`.
Passwords come from Secrets, never from values. With the bundled CloudNativePG the
role passwords are chart-generated Secrets and the owner password is the one CNPG
generates for the initdb owner; otherwise database.existingSecret supplies the URLs.
*/}}
{{- define "rampart.dbEnv" -}}
{{- $root := .root -}}
{{- $full := include "rampart.fullname" $root -}}
{{- if $root.Values.database.cnpg.enabled -}}
{{- $host := printf "%s-rw" (include "rampart.cnpgName" $root) -}}
{{- if eq .role "migrate" }}
- name: DB_OWNER_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "rampart.cnpgName" $root }}-app
      key: password
- name: RAMPART_DATABASE_MIGRATE_URL
  value: "postgres://rampart_owner:$(DB_OWNER_PASSWORD)@{{ $host }}:5432/rampart?sslmode=require"
{{- else }}
- name: DB_APP_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ $full }}-db-app
      key: password
- name: DB_SYSTEM_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ $full }}-db-system
      key: password
- name: RAMPART_DATABASE_URL
  value: "postgres://rampart_app:$(DB_APP_PASSWORD)@{{ $host }}:5432/rampart?sslmode=require"
- name: RAMPART_DATABASE_DIRECT_URL
  value: "postgres://rampart_app:$(DB_APP_PASSWORD)@{{ $host }}:5432/rampart?sslmode=require"
- name: RAMPART_DATABASE_SYSTEM_URL
  value: "postgres://rampart_system:$(DB_SYSTEM_PASSWORD)@{{ $host }}:5432/rampart?sslmode=require"
{{- end }}
{{- else }}
{{- $secret := required "database.existingSecret is required when database.cnpg.enabled=false" $root.Values.database.existingSecret -}}
{{- if eq .role "migrate" }}
- name: RAMPART_DATABASE_MIGRATE_URL
  valueFrom: {secretKeyRef: {name: {{ $secret | quote }}, key: migrateUrl}}
{{- else }}
- name: RAMPART_DATABASE_URL
  valueFrom: {secretKeyRef: {name: {{ $secret | quote }}, key: url}}
- name: RAMPART_DATABASE_DIRECT_URL
  valueFrom: {secretKeyRef: {name: {{ $secret | quote }}, key: directUrl}}
- name: RAMPART_DATABASE_SYSTEM_URL
  valueFrom: {secretKeyRef: {name: {{ $secret | quote }}, key: systemUrl}}
{{- end }}
{{- end }}
{{- end }}
