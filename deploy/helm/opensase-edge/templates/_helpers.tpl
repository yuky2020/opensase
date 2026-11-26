{{- define "edge.name" -}}{{ .Release.Name }}-edge{{- end -}}
{{- define "edge.labels" -}}
app.kubernetes.io/name: opensase-edge
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
{{- define "edge.selector" -}}
app.kubernetes.io/name: opensase-edge
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
