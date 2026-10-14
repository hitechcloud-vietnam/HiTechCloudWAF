{{/* ------------------------------------------------------------------ */}}
{{/* Names and labels                                                   */}}
{{/* ------------------------------------------------------------------ */}}

{{- define "hcw.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "hcw.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "hcw.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "hcw.labels" -}}
helm.sh/chart: {{ include "hcw.chart" . }}
app.kubernetes.io/name: {{ include "hcw.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: hitechcloud-waf
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/* Selector labels for one component: include "hcw.selectorLabels" (list . "waf") */}}
{{- define "hcw.selectorLabels" -}}
{{- $root := index . 0 -}}
app.kubernetes.io/name: {{ include "hcw.name" $root }}
app.kubernetes.io/instance: {{ $root.Release.Name }}
app.kubernetes.io/component: {{ index . 1 }}
{{- end -}}

{{- define "hcw.componentLabels" -}}
{{ include "hcw.labels" (index . 0) }}
app.kubernetes.io/component: {{ index . 1 }}
{{- end -}}

{{- define "hcw.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "hcw.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "hcw.image" -}}
{{- printf "%s:%s" .repository (toString (default "latest" .tag)) -}}
{{- end -}}

{{/* ------------------------------------------------------------------ */}}
{{/* Topology                                                           */}}
{{/* ------------------------------------------------------------------ */}}

{{/* "true" when more than one WAF pod can serve at the same time. */}}
{{- define "hcw.waf.multi" -}}
{{- if or (eq .Values.waf.kind "DaemonSet") .Values.autoscaling.enabled (gt (int .Values.waf.replicaCount) 1) -}}true{{- end -}}
{{- end -}}

{{/* "true" when the WAF pods use a PersistentVolumeClaim. */}}
{{- define "hcw.waf.usePVC" -}}
{{- if and .Values.waf.persistence.enabled (ne .Values.waf.kind "DaemonSet") -}}true{{- end -}}
{{- end -}}

{{/* Name of the Service that serves the console used by administrators. */}}
{{- define "hcw.consoleTarget" -}}
{{- if .Values.primary.enabled -}}
{{- printf "%s-primary" (include "hcw.fullname" .) -}}
{{- else -}}
{{- printf "%s-console" (include "hcw.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/* "true" when the console is served by exactly one engine. */}}
{{- define "hcw.singleConsole" -}}
{{- if or .Values.primary.enabled (not (include "hcw.waf.multi" .)) -}}true{{- end -}}
{{- end -}}

{{/* "true" when the chart CA is needed. */}}
{{- define "hcw.needCA" -}}
{{- if or .Values.controller.enabled .Values.waf.api.tls.generate -}}true{{- end -}}
{{- end -}}

{{/* Secret name holding the console certificate, empty when self-signed. */}}
{{- define "hcw.apiTLSSecret" -}}
{{- if .Values.waf.api.tls.existingSecret -}}
{{- .Values.waf.api.tls.existingSecret -}}
{{- else if include "hcw.needCA" . -}}
{{- printf "%s-api-tls" (include "hcw.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "hcw.caSecret" -}}
{{- default (printf "%s-ca" (include "hcw.fullname" .)) .Values.cluster.ca.existingSecret -}}
{{- end -}}

{{- define "hcw.authSecret" -}}
{{- default (printf "%s-auth" (include "hcw.fullname" .)) .Values.auth.existingSecret -}}
{{- end -}}

{{- define "hcw.clusterSecret" -}}
{{- default (printf "%s-cluster" (include "hcw.fullname" .)) .Values.cluster.existingSecret -}}
{{- end -}}

{{- define "hcw.controllerURL" -}}
{{- printf "https://%s-controller.%s.svc:%d" (include "hcw.fullname" .) .Release.Namespace (int .Values.controller.service.port) -}}
{{- end -}}

{{/* Lowest site containerPort below 1024, or empty. */}}
{{- define "hcw.waf.lowPort" -}}
{{- $low := 1024 -}}
{{- range .Values.waf.ports -}}
{{- if lt (int .containerPort) $low -}}{{- $low = int .containerPort -}}{{- end -}}
{{- end -}}
{{- if lt (int .Values.waf.api.port) $low -}}{{- $low = int .Values.waf.api.port -}}{{- end -}}
{{- if lt $low 1024 -}}{{ $low }}{{- end -}}
{{- end -}}

{{/* ------------------------------------------------------------------ */}}
{{/* Generated secrets (kept across upgrades through lookup)             */}}
{{/* ------------------------------------------------------------------ */}}

{{/* include "hcw.secretValue" (list $ secretName key explicitValue length) */}}
{{- define "hcw.secretValue" -}}
{{- $root := index . 0 -}}
{{- $name := index . 1 -}}
{{- $key := index . 2 -}}
{{- $explicit := index . 3 -}}
{{- $len := int (index . 4) -}}
{{- if $explicit -}}
{{- $explicit | b64enc -}}
{{- else -}}
{{- $existing := lookup "v1" "Secret" $root.Release.Namespace $name -}}
{{- if and $existing $existing.data (hasKey $existing.data $key) -}}
{{- index $existing.data $key -}}
{{- else -}}
{{- randAlphaNum $len | b64enc -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* ------------------------------------------------------------------ */}}
{{/* Validation                                                         */}}
{{/* ------------------------------------------------------------------ */}}

{{- define "hcw.validate" -}}
{{- if not (has .Values.waf.kind (list "Deployment" "DaemonSet")) -}}
{{- fail "waf.kind must be Deployment or DaemonSet" -}}
{{- end -}}
{{- if and .Values.autoscaling.enabled (eq .Values.waf.kind "DaemonSet") -}}
{{- fail "autoscaling.enabled works with waf.kind=Deployment only" -}}
{{- end -}}
{{- if and (include "hcw.waf.multi" .) (include "hcw.waf.usePVC" .) (not (has "ReadWriteMany" .Values.waf.persistence.accessModes)) -}}
{{- fail "several WAF pods cannot share a ReadWriteOnce data volume: set waf.persistence.enabled=false (configuration then comes from the primary through agent.enabled) or use waf.kind=DaemonSet with waf.persistence.hostPath" -}}
{{- end -}}
{{- if and (include "hcw.waf.multi" .) (not .Values.agent.enabled) -}}
{{- fail "several WAF pods need agent.enabled=true so that each pod receives the configuration of the primary engine" -}}
{{- end -}}
{{- if and .Values.agent.enabled (not .Values.controller.enabled) (not .Values.agent.controllerURL) -}}
{{- fail "agent.enabled needs controller.enabled=true or agent.controllerURL" -}}
{{- end -}}
{{- if and .Values.agent.enabled (not .Values.controller.enabled) (or (not .Values.agent.controllerCASecret) (not .Values.agent.nodeTokenSecret)) -}}
{{- fail "an external controller (agent.controllerURL) needs agent.controllerCASecret and agent.nodeTokenSecret" -}}
{{- end -}}
{{- if and .Values.agent.enabled .Values.agent.applyConfig .Values.controller.enabled (not .Values.primary.enabled) (not .Values.controller.primary.baseURL) -}}
{{- fail "agent.applyConfig replicates the primary engine: enable primary.enabled (or set controller.primary.baseURL)" -}}
{{- end -}}
{{- if and .Values.controller.enabled (not .Values.primary.enabled) (not .Values.controller.primary.baseURL) (include "hcw.waf.multi" .) -}}
{{- fail "controller.enabled with several WAF pods needs primary.enabled=true (or controller.primary.baseURL)" -}}
{{- end -}}
{{- if and .Values.dns.enabled (not .Values.controller.enabled) (or (not .Values.dns.controllerURL) (not .Values.dns.controllerCASecret) (not .Values.dns.tokenSecret)) -}}
{{- fail "dns.enabled needs controller.enabled=true, or dns.controllerURL + dns.controllerCASecret + dns.tokenSecret" -}}
{{- end -}}
{{- if and .Values.dns.enabled (not .Values.dns.zones) -}}
{{- fail "dns.enabled needs at least one entry in dns.zones" -}}
{{- end -}}
{{- end -}}

{{/* ------------------------------------------------------------------ */}}
{{/* waf.yaml                                                           */}}
{{/* ------------------------------------------------------------------ */}}

{{- define "hcw.waf.config" -}}
{{- $cfg := deepCopy (default dict .Values.waf.config) -}}
{{- $_ := set $cfg "data_dir" "/var/lib/hcw-waf" -}}
{{- $_ := set $cfg "challenge_secret_file" "/etc/hcw-waf/secrets/challenge-key" -}}
{{- $api := dict "listen" (printf ":%d" (int .Values.waf.api.port)) "token_file" "/etc/hcw-waf/secrets/api-token" -}}
{{- if include "hcw.apiTLSSecret" . -}}
{{- $_ := set $api "tls_cert" "/etc/hcw-waf/tls/tls.crt" -}}
{{- $_ := set $api "tls_key" "/etc/hcw-waf/tls/tls.key" -}}
{{- end -}}
{{- with .Values.waf.api.allow -}}
{{- $allow := . -}}
{{- if and $.Values.agent.enabled (not (has "127.0.0.1/32" $allow)) -}}
{{- $allow = append $allow "127.0.0.1/32" -}}
{{- end -}}
{{- $_ := set $api "allow" $allow -}}
{{- end -}}
{{- $_ := set $cfg "api" $api -}}
# Generated by the hitechcloud-waf chart from .Values.waf.config.
{{ toYaml $cfg }}
{{- end -}}

{{/* ------------------------------------------------------------------ */}}
{{/* Engine pod spec: include "hcw.waf.podSpec" (dict "root" $ "role" "waf"|"primary") */}}
{{/* ------------------------------------------------------------------ */}}

{{- define "hcw.waf.probe" -}}
{{- $root := index . 0 -}}
{{- $p := index . 1 -}}
{{- $mode := $root.Values.waf.probes.mode -}}
{{- if eq $mode "auto" -}}{{- $mode = ternary "tcp" "http" (gt (len $root.Values.waf.api.allow) 0) -}}{{- end -}}
{{- if eq $mode "tcp" }}
tcpSocket:
  port: console
{{- else }}
httpGet:
  path: /api/open/health
  port: console
  scheme: HTTPS
{{- end }}
periodSeconds: {{ $p.periodSeconds }}
timeoutSeconds: {{ $p.timeoutSeconds }}
failureThreshold: {{ $p.failureThreshold }}
{{- end -}}

{{- define "hcw.waf.podSpec" -}}
{{- $root := .root -}}
{{- $v := $root.Values -}}
{{- $role := .role -}}
{{- $isWaf := eq $role "waf" -}}
{{- $hostNet := and $isWaf $v.waf.hostNetwork -}}
{{- $low := include "hcw.waf.lowPort" $root -}}
{{- $fullname := include "hcw.fullname" $root -}}
{{- $agent := and $isWaf $v.agent.enabled -}}
{{- $sc := deepCopy $v.waf.containerSecurityContext -}}
{{- if and $low $hostNet -}}
{{- $_ := set $sc "allowPrivilegeEscalation" true -}}
{{- end -}}
serviceAccountName: {{ include "hcw.serviceAccountName" $root }}
automountServiceAccountToken: {{ $v.serviceAccount.automountServiceAccountToken }}
{{- with $v.imagePullSecrets }}
imagePullSecrets:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- if $hostNet }}
hostNetwork: true
dnsPolicy: {{ default "ClusterFirstWithHostNet" $v.waf.dnsPolicy }}
{{- else if $v.waf.dnsPolicy }}
dnsPolicy: {{ $v.waf.dnsPolicy }}
{{- end }}
{{- $prio := ternary $v.waf.priorityClassName $v.primary.priorityClassName $isWaf -}}
{{- with $prio }}
priorityClassName: {{ . }}
{{- end }}
terminationGracePeriodSeconds: {{ $v.waf.terminationGracePeriodSeconds }}
securityContext:
  {{- toYaml $v.waf.podSecurityContext | nindent 2 }}
  {{- if and $low (not $hostNet) $v.waf.unprivilegedPortSysctl }}
  sysctls:
    - name: net.ipv4.ip_unprivileged_port_start
      value: {{ $low | quote }}
  {{- end }}
{{- if $agent }}
initContainers:
  # Fills the pod-specific placeholders of agent.yaml.
  - name: agent-config
    image: {{ include "hcw.image" $v.clusterImage }}
    imagePullPolicy: {{ $v.clusterImage.pullPolicy }}
    command:
      - /bin/sh
      - -c
      - >-
        sed -e "s|__POD_NAME__|${POD_NAME}|g" -e "s|__POD_IP__|${POD_IP}|g"
        -e "s|__HOST_IP__|${HOST_IP}|g" -e "s|__NODE_NAME__|${NODE_NAME}|g"
        /etc/hcw/template/agent.yaml > /etc/hcw/agent/agent.yaml
    env:
      - name: POD_NAME
        valueFrom: {fieldRef: {fieldPath: metadata.name}}
      - name: POD_IP
        valueFrom: {fieldRef: {fieldPath: status.podIP}}
      - name: HOST_IP
        valueFrom: {fieldRef: {fieldPath: status.hostIP}}
      - name: NODE_NAME
        valueFrom: {fieldRef: {fieldPath: spec.nodeName}}
    securityContext:
      {{- toYaml $v.agent.containerSecurityContext | nindent 6 }}
    resources:
      {{- toYaml $v.agent.resources | nindent 6 }}
    volumeMounts:
      - name: agent-template
        mountPath: /etc/hcw/template
        readOnly: true
      - name: agent-config
        mountPath: /etc/hcw/agent
{{- end }}
containers:
  - name: waf
    image: {{ include "hcw.image" $v.image }}
    imagePullPolicy: {{ $v.image.pullPolicy }}
    args:
      - -config
      - /etc/hcw-waf/waf.yaml
      {{- range $v.waf.extraArgs }}
      - {{ . | quote }}
      {{- end }}
    {{- with $v.waf.extraEnv }}
    env:
      {{- toYaml . | nindent 6 }}
    {{- end }}
    ports:
      - name: console
        containerPort: {{ $v.waf.api.port }}
        protocol: TCP
      {{- range $v.waf.ports }}
      - name: {{ .name }}
        containerPort: {{ .containerPort }}
        protocol: {{ default "TCP" .protocol }}
      {{- end }}
    {{- with $v.waf.probes.startup }}
    {{- if .enabled }}
    startupProbe:
      {{- include "hcw.waf.probe" (list $root .) | trim | nindent 6 }}
    {{- end }}
    {{- end }}
    {{- with $v.waf.probes.liveness }}
    {{- if .enabled }}
    livenessProbe:
      {{- include "hcw.waf.probe" (list $root .) | trim | nindent 6 }}
    {{- end }}
    {{- end }}
    {{- with $v.waf.probes.readiness }}
    {{- if .enabled }}
    readinessProbe:
      {{- include "hcw.waf.probe" (list $root .) | trim | nindent 6 }}
    {{- end }}
    {{- end }}
    resources:
      {{- toYaml (ternary $v.waf.resources $v.primary.resources $isWaf) | nindent 6 }}
    securityContext:
      {{- toYaml $sc | nindent 6 }}
    volumeMounts:
      - name: config
        mountPath: /etc/hcw-waf/waf.yaml
        subPath: waf.yaml
        readOnly: true
      - name: auth
        mountPath: /etc/hcw-waf/secrets
        readOnly: true
      {{- if include "hcw.apiTLSSecret" $root }}
      - name: api-tls
        mountPath: /etc/hcw-waf/tls
        readOnly: true
      {{- end }}
      - name: data
        mountPath: /var/lib/hcw-waf
      - name: tmp
        mountPath: /tmp
      {{- with $v.waf.extraVolumeMounts }}
      {{- toYaml . | nindent 6 }}
      {{- end }}
  {{- if $agent }}
  - name: agent
    image: {{ include "hcw.image" $v.clusterImage }}
    imagePullPolicy: {{ $v.clusterImage.pullPolicy }}
    args: [agent, -config, /etc/hcw/agent/agent.yaml]
    resources:
      {{- toYaml $v.agent.resources | nindent 6 }}
    securityContext:
      {{- toYaml $v.agent.containerSecurityContext | nindent 6 }}
    volumeMounts:
      - name: agent-config
        mountPath: /etc/hcw/agent
        readOnly: true
      - name: agent-secrets
        mountPath: /etc/hcw/secrets
        readOnly: true
      - name: agent-ca
        mountPath: /etc/hcw/tls
        readOnly: true
      - name: agent-data
        mountPath: /var/lib/hcw
  {{- end }}
volumes:
  - name: config
    configMap:
      name: {{ $fullname }}-config
  - name: auth
    secret:
      secretName: {{ include "hcw.authSecret" $root }}
      defaultMode: 0440
      items:
        - {key: api-token, path: api-token}
        - {key: challenge-key, path: challenge-key}
  {{- with include "hcw.apiTLSSecret" $root }}
  - name: api-tls
    secret:
      secretName: {{ . }}
      defaultMode: 0440
      items:
        - {key: tls.crt, path: tls.crt}
        - {key: tls.key, path: tls.key}
  {{- end }}
  - name: data
    {{- if and (not $isWaf) $v.primary.persistence.enabled }}
    persistentVolumeClaim:
      claimName: {{ default (printf "%s-primary-data" $fullname) $v.primary.persistence.existingClaim }}
    {{- else if include "hcw.waf.usePVC" $root }}
    persistentVolumeClaim:
      claimName: {{ default (printf "%s-data" $fullname) $v.waf.persistence.existingClaim }}
    {{- else if and (eq $v.waf.kind "DaemonSet") $v.waf.persistence.enabled $v.waf.persistence.hostPath }}
    hostPath:
      # Must exist and belong to uid 10002 (fsGroup does not apply here).
      path: {{ $v.waf.persistence.hostPath }}
      type: Directory
    {{- else }}
    emptyDir: {}
    {{- end }}
  - name: tmp
    emptyDir:
      sizeLimit: 64Mi
  {{- if $agent }}
  - name: agent-template
    configMap:
      name: {{ $fullname }}-agent
  - name: agent-config
    emptyDir:
      sizeLimit: 1Mi
  - name: agent-data
    emptyDir:
      sizeLimit: 64Mi
  - name: agent-secrets
    projected:
      defaultMode: 0440
      sources:
        - secret:
            name: {{ default (include "hcw.clusterSecret" $root) $v.agent.nodeTokenSecret }}
            items:
              - {key: node-token, path: node.token}
        - secret:
            name: {{ include "hcw.authSecret" $root }}
            items:
              - {key: api-token, path: engine.token}
  - name: agent-ca
    secret:
      secretName: {{ default (include "hcw.caSecret" $root) $v.agent.controllerCASecret }}
      defaultMode: 0444
      items:
        - {key: {{ ternary "ca.crt" "tls.crt" (not (empty $v.agent.controllerCASecret)) }}, path: ca.crt}
  {{- end }}
  {{- with $v.waf.extraVolumes }}
  {{- toYaml . | nindent 2 }}
  {{- end }}
{{- $ns := ternary $v.waf.nodeSelector $v.primary.nodeSelector $isWaf -}}
{{- with $ns }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- $tol := ternary $v.waf.tolerations $v.primary.tolerations $isWaf -}}
{{- with $tol }}
tolerations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- $aff := ternary $v.waf.affinity $v.primary.affinity $isWaf -}}
{{- with $aff }}
affinity:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- if $isWaf }}
{{- with $v.waf.topologySpreadConstraints }}
topologySpreadConstraints:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}
{{- end -}}
