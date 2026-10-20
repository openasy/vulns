{{- define "vulns.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{/* A release named vulns-agent (agents only) keeps its name: vulns-agent, not vulns-agent-agent. */}}
{{- define "vulns.agentName" -}}
{{- $full := include "vulns.fullname" . -}}
{{- if hasSuffix "agent" $full -}}
{{- $full -}}
{{- else -}}
{{- printf "%s-agent" $full | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "vulns.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
app.kubernetes.io/part-of: openasy
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "vulns.selector" -}}
app.kubernetes.io/name: vulns
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "vulns.agentSelector" -}}
app.kubernetes.io/name: vulns-agent
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* repository:tag, or repository@digest when a digest is set. The tag defaults to the chart's appVersion. */}}
{{- define "vulns.image" -}}
{{- if .image.digest -}}
{{- printf "%s@%s" .image.repository .image.digest -}}
{{- else -}}
{{- printf "%s:%s" .image.repository (default .appVersion .image.tag) -}}
{{- end -}}
{{- end -}}

{{- define "vulns.secretName" -}}
{{- default (include "vulns.fullname" .) .Values.auth.existingSecret -}}
{{- end -}}

{{/* The restricted Pod Security Standard (ADR 0022). */}}
{{- define "vulns.containerSecurity" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
runAsNonRoot: true
capabilities:
  drop: [ALL]
{{- end -}}

{{/* The address people open vulns at: cookies, passkeys and OIDC redirects use it. */}}
{{- define "vulns.url" -}}
{{- if .Values.vulns.url }}{{ trimSuffix "/" .Values.vulns.url }}
{{- else if .Values.vulns.ingress.enabled }}https://{{ .Values.vulns.ingress.host }}
{{- else }}http://localhost:8080
{{- end }}
{{- end }}
