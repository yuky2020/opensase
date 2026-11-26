{{- define "cp.name" -}}{{ .Release.Name }}-controlplane{{- end -}}
{{- define "cp.labels" -}}
app.kubernetes.io/name: opensase-controlplane
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
{{- define "cp.selector" -}}
app.kubernetes.io/name: opensase-controlplane
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "cp.replicas" -}}
{{- if eq .Values.database.type "postgres" }}{{ .Values.replicas }}{{ else }}1{{ end -}}
{{- end -}}
