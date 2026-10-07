{{/* Namespace for every namespaced object. */}}
{{- define "srek3s.namespace" -}}
{{ .Release.Namespace }}
{{- end }}

{{/* Shared part-of label. */}}
{{- define "srek3s.partOf" -}}
app.kubernetes.io/part-of: srek3s
{{- end }}
