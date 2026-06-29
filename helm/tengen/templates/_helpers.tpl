{{/*
Expand the name of the chart.
*/}}
{{- define "tengen.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "tengen.fullname" -}}
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
Chart label value.
*/}}
{{- define "tengen.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "tengen.labels" -}}
helm.sh/chart: {{ include "tengen.chart" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: tengen
{{ include "tengen.selectorLabels" . }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "tengen.selectorLabels" -}}
app.kubernetes.io/name: {{ include "tengen.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Component selector labels — pass component name as the argument.
Usage: {{ include "tengen.componentLabels" (dict "root" . "component" "router") }}
*/}}
{{- define "tengen.componentLabels" -}}
{{ include "tengen.selectorLabels" .root }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{/*
Service account name.
*/}}
{{- define "tengen.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "tengen.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Secret name — existing or chart-created.
*/}}
{{- define "tengen.secretName" -}}
{{- if .Values.existingSecret }}
{{- .Values.existingSecret }}
{{- else }}
{{- include "tengen.fullname" . }}
{{- end }}
{{- end }}

{{/*
RabbitMQ URL — subchart or external.
*/}}
{{- define "tengen.rabbitmqUrl" -}}
{{- if .Values.rabbitmq.enabled }}
{{- printf "amqp://%s:%s@%s-rabbitmq:5672/" .Values.rabbitmq.auth.username .Values.rabbitmq.auth.password .Release.Name }}
{{- else }}
{{- .Values.externalRabbitmq.url }}
{{- end }}
{{- end }}

{{/*
Image spec.
*/}}
{{- define "tengen.image" -}}
{{- $repo := .Values.image.repository | replace "NAMESPACE" .Release.Namespace }}
{{- printf "%s:%s" $repo .Values.image.tag }}
{{- end }}

{{/*
Common environment variables shared by all Tengen pods.
*/}}
{{- define "tengen.commonEnv" -}}
- name: GOOGLE_API_KEY
  valueFrom:
    secretKeyRef:
      name: {{ include "tengen.secretName" . }}
      key: google-api-key
      optional: true
- name: MODEL_NAME
  value: {{ .Values.modelName | quote }}
- name: RABBITMQ_URL
  {{- if .Values.existingSecret }}
  valueFrom:
    secretKeyRef:
      name: {{ .Values.existingSecret }}
      key: rabbitmq-url
      optional: true
  {{- else }}
  value: {{ include "tengen.rabbitmqUrl" . | quote }}
  {{- end }}
# -- n8n
- name: N8N_ROUTES_PATH
  value: {{ .Values.n8n.routesPath | quote }}
- name: N8N_TIMEOUT
  value: {{ .Values.n8n.timeout | quote }}
- name: N8N_MAX_RETRIES
  value: {{ .Values.n8n.maxRetries | quote }}
- name: N8N_BACKOFF_BASE
  value: {{ .Values.n8n.backoffBase | quote }}
# -- AWS
- name: AWS_REGION
  value: {{ .Values.aws.region | quote }}
{{- if .Values.aws.endpointUrl }}
- name: AWS_ENDPOINT_URL
  value: {{ .Values.aws.endpointUrl | quote }}
{{- end }}
{{- if .Values.aws.sqsQueueUrl }}
- name: SQS_QUEUE_URL
  value: {{ .Values.aws.sqsQueueUrl | quote }}
{{- end }}
# -- GCP
{{- if .Values.gcp.projectId }}
- name: GCP_PROJECT_ID
  value: {{ .Values.gcp.projectId | quote }}
{{- end }}
{{- if .Values.gcp.pubsubProjectId }}
- name: PUBSUB_PROJECT_ID
  value: {{ .Values.gcp.pubsubProjectId | quote }}
{{- end }}
{{- if .Values.gcp.pubsubSubscriptionId }}
- name: PUBSUB_SUBSCRIPTION_ID
  value: {{ .Values.gcp.pubsubSubscriptionId | quote }}
{{- end }}
{{- if .Values.gcp.pubsubEmulatorHost }}
- name: PUBSUB_EMULATOR_HOST
  value: {{ .Values.gcp.pubsubEmulatorHost | quote }}
{{- end }}
# -- Azure
- name: AZURE_TENANT_ID
  valueFrom:
    secretKeyRef:
      name: {{ include "tengen.secretName" . }}
      key: azure-tenant-id
      optional: true
- name: AZURE_CLIENT_ID
  valueFrom:
    secretKeyRef:
      name: {{ include "tengen.secretName" . }}
      key: azure-client-id
      optional: true
- name: AZURE_CLIENT_SECRET
  valueFrom:
    secretKeyRef:
      name: {{ include "tengen.secretName" . }}
      key: azure-client-secret
      optional: true
{{- if .Values.azure.subscriptionId }}
- name: AZURE_SUBSCRIPTION_ID
  value: {{ .Values.azure.subscriptionId | quote }}
{{- end }}
# -- CrowdStrike
- name: CROWDSTRIKE_CLIENT_ID
  valueFrom:
    secretKeyRef:
      name: {{ include "tengen.secretName" . }}
      key: crowdstrike-client-id
      optional: true
- name: CROWDSTRIKE_CLIENT_SECRET
  valueFrom:
    secretKeyRef:
      name: {{ include "tengen.secretName" . }}
      key: crowdstrike-client-secret
      optional: true
- name: CROWDSTRIKE_BASE_URL
  value: {{ .Values.crowdstrike.baseUrl | quote }}
# -- Kubernetes
{{- if .Values.k8s.kubeconfig }}
- name: K8S_KUBECONFIG
  value: {{ .Values.k8s.kubeconfig | quote }}
{{- end }}
# -- Splunk
- name: SPLUNK_HEC_URL
  valueFrom:
    secretKeyRef:
      name: {{ include "tengen.secretName" . }}
      key: splunk-hec-url
      optional: true
- name: SPLUNK_HEC_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ include "tengen.secretName" . }}
      key: splunk-hec-token
      optional: true
- name: SPLUNK_INDEX
  value: {{ .Values.splunk.index | quote }}
- name: SPLUNK_BATCH_SIZE
  value: {{ .Values.splunk.batchSize | quote }}
# -- PagerDuty
- name: PAGERDUTY_API_KEY
  valueFrom:
    secretKeyRef:
      name: {{ include "tengen.secretName" . }}
      key: pagerduty-api-key
      optional: true
{{- end }}

{{/*
n8n routes volume + volumeMount.
*/}}
{{- define "tengen.n8nRoutesVolume" -}}
- name: n8n-routes
  configMap:
    name: {{ include "tengen.fullname" . }}-n8n-routes
{{- end }}

{{- define "tengen.n8nRoutesVolumeMount" -}}
- name: n8n-routes
  mountPath: {{ dir .Values.n8n.routesPath }}
  readOnly: true
{{- end }}
