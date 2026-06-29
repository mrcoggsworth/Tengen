# Tengen OpenShift Installation Guide

This guide covers deploying Tengen to OpenShift using Helm (recommended) and
manual `oc` commands (fallback). It applies to both OpenShift Local (CRC) for
development and full OpenShift clusters for production.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Building the Container Image](#building-the-container-image)
  - [Podman Build](#podman-build)
  - [Push to OpenShift Internal Registry](#push-to-openshift-internal-registry)
  - [Push to OpenShift CRC Registry](#push-to-openshift-crc-registry)
- [Installation with Helm (Recommended)](#installation-with-helm-recommended)
  - [Quick Start](#quick-start)
  - [Custom values.yaml](#custom-valuesyaml)
  - [Using an Existing Secret](#using-an-existing-secret)
  - [External RabbitMQ](#external-rabbitmq)
  - [Enabling Optional Consumers](#enabling-optional-consumers)
  - [Verifying the Installation](#verifying-the-installation)
- [Manual Installation (Fallback)](#manual-installation-fallback)
  - [Create the Namespace](#create-the-namespace)
  - [Create the Secret](#create-the-secret)
  - [Create the n8n Routes ConfigMap](#create-the-n8n-routes-configmap)
  - [Deploy RabbitMQ](#deploy-rabbitmq)
  - [Deploy Tengen Components](#deploy-tengen-components)
  - [Create Services](#create-services)
  - [Create OpenShift Routes](#create-openshift-routes)
- [OpenShift CRC (Local Development)](#openshift-crc-local-development)
  - [CRC Setup](#crc-setup)
  - [CRC-Specific Image Build](#crc-specific-image-build)
  - [CRC Resource Limits](#crc-resource-limits)
  - [CRC Networking](#crc-networking)
- [Full OpenShift Cluster (Production)](#full-openshift-cluster-production)
  - [Production Checklist](#production-checklist)
  - [High Availability](#high-availability)
  - [Resource Sizing](#resource-sizing)
  - [Network Policies](#network-policies)
  - [Persistent Storage](#persistent-storage)
- [n8n Routing Spec Management](#n8n-routing-spec-management)
  - [Updating Routes Without Redeployment](#updating-routes-without-redeployment)
  - [Validating a Routes File](#validating-a-routes-file)
- [Upgrading](#upgrading)
- [Uninstalling](#uninstalling)
- [Troubleshooting and Debugging](#troubleshooting-and-debugging)
  - [Pods Not Starting](#pods-not-starting)
  - [ImagePullBackOff](#imagepullbackoff)
  - [CrashLoopBackOff](#crashloopbackoff)
  - [RabbitMQ Connection Failures](#rabbitmq-connection-failures)
  - [n8n Webhook Failures](#n8n-webhook-failures)
  - [Dashboard Not Loading](#dashboard-not-loading)
  - [Route Not Accessible](#route-not-accessible)
  - [OpenShift CRC-Specific Issues](#openshift-crc-specific-issues)
  - [Useful Debug Commands](#useful-debug-commands)

---

## Prerequisites

| Tool | Minimum Version | Purpose |
|------|-----------------|---------|
| `oc` | 4.12+ | OpenShift CLI |
| `podman` | 4.0+ | Container image build |
| `helm` | 3.12+ | Chart installation (recommended path) |
| `python` | 3.11+ | Local development / testing |

Verify your tools:

```bash
oc version
podman --version
helm version --short
```

You also need:

- **OpenShift cluster access** with permissions to create Deployments, Services,
  Routes, ConfigMaps, Secrets, and ServiceAccounts in your target namespace.
- **A Google API key** for the Gemini LLM agents (`GOOGLE_API_KEY`).
- **n8n instance** with webhook workflows configured and reachable from the
  OpenShift cluster.

---

## Building the Container Image

### Podman Build

Clone the repository and build the image:

```bash
git clone https://github.com/mrcoggsworth/Tengen.git
cd Tengen

podman build -t tengen:latest -f Dockerfile .
```

Verify the build:

```bash
podman images tengen
podman run --rm tengen:latest tengen.config --help 2>/dev/null || \
  podman run --rm tengen:latest python -c "from tengen.config import settings; print('OK')"
```

### Push to OpenShift Internal Registry

On a full OpenShift cluster, expose the internal registry and push:

```bash
# 1. Get the registry route (if exposed)
REGISTRY=$(oc get route default-route -n openshift-image-registry \
  -o jsonpath='{.spec.host}' 2>/dev/null)

# If the route does not exist, expose it:
oc patch configs.imageregistry.operator.openshift.io/cluster \
  --type merge -p '{"spec":{"defaultRoute":true}}'
REGISTRY=$(oc get route default-route -n openshift-image-registry \
  -o jsonpath='{.spec.host}')

# 2. Log in to the registry
podman login -u $(oc whoami) -p $(oc whoami -t) "${REGISTRY}"

# 3. Tag and push
NAMESPACE=tengen
podman tag tengen:latest "${REGISTRY}/${NAMESPACE}/tengen:latest"
podman push "${REGISTRY}/${NAMESPACE}/tengen:latest"
```

After pushing, pods in the `tengen` namespace can pull via the internal
service URL:

```
image-registry.openshift-image-registry.svc:5000/tengen/tengen:latest
```

### Push to OpenShift CRC Registry

CRC uses a self-signed certificate. You must trust it before pushing:

```bash
# 1. Start CRC and log in
crc start
eval $(crc oc-env)
oc login -u developer -p developer https://api.crc.testing:6443

# 2. Get the registry host
REGISTRY=$(oc get route default-route -n openshift-image-registry \
  -o jsonpath='{.spec.host}' 2>/dev/null)

# If the route is not exposed in CRC:
REGISTRY=default-route-openshift-image-registry.apps-crc.testing

# 3. Trust the CRC CA certificate (macOS)
oc extract secret/router-ca -n openshift-ingress-operator --to=/tmp --confirm
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain /tmp/tls.crt

# Trust the CRC CA certificate (Linux)
sudo cp /tmp/tls.crt /etc/pki/ca-trust/source/anchors/crc-registry.crt
sudo update-ca-trust

# 4. Log in and push
podman login -u $(oc whoami) -p $(oc whoami -t) "${REGISTRY}" --tls-verify=false

NAMESPACE=tengen
oc new-project ${NAMESPACE} 2>/dev/null || oc project ${NAMESPACE}
podman tag tengen:latest "${REGISTRY}/${NAMESPACE}/tengen:latest"
podman push "${REGISTRY}/${NAMESPACE}/tengen:latest" --tls-verify=false
```

---

## Installation with Helm (Recommended)

### Quick Start

```bash
# 1. Add the Bitnami repo (RabbitMQ subchart dependency)
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update

# 2. Build chart dependencies
cd Tengen
helm dependency build helm/tengen/

# 3. Create the namespace
oc new-project tengen 2>/dev/null || oc project tengen

# 4. Install
helm install tengen helm/tengen/ \
  --namespace tengen \
  --set secrets.googleApiKey="YOUR_GOOGLE_API_KEY"
```

The install output will display your deployed components, dashboard URL, and
ingest URL.

### Custom values.yaml

For anything beyond the defaults, create a `my-values.yaml`:

```yaml
# my-values.yaml

image:
  repository: image-registry.openshift-image-registry.svc:5000/tengen/tengen
  tag: "0.2.0"

secrets:
  googleApiKey: "AIza..."
  splunkHecUrl: "https://splunk.internal:8088"
  splunkHecToken: "your-hec-token"
  universalHttpToken: "my-ingest-bearer-token"

n8n:
  timeout: 60
  maxRetries: 5
  routes: |
    version: "1"
    routes:
      aws:
        cloudtrail:
          _default:
            webhook: https://n8n.internal/webhook/aws-cloudtrail
        _default:
          webhook: https://n8n.internal/webhook/aws-general
      _default:
        webhook: https://n8n.internal/webhook/catch-all

router:
  replicas: 2
  resources:
    requests:
      cpu: 500m
      memory: 512Mi
    limits:
      cpu: "2"
      memory: 1Gi

dashboard:
  route:
    host: tengen-dashboard.apps.mycluster.example.com

ingest:
  route:
    host: tengen-ingest.apps.mycluster.example.com
```

Install with custom values:

```bash
helm install tengen helm/tengen/ \
  --namespace tengen \
  -f my-values.yaml
```

### Using an Existing Secret

If you manage secrets externally (Vault, Sealed Secrets, etc.), create the
Secret first:

```bash
oc create secret generic tengen-secrets \
  --from-literal=google-api-key="AIza..." \
  --from-literal=rabbitmq-url="amqp://user:pass@rabbitmq.svc:5672/" \
  --from-literal=splunk-hec-url="https://splunk:8088" \
  --from-literal=splunk-hec-token="your-token" \
  --from-literal=splunk-es-host="" \
  --from-literal=splunk-es-token="" \
  --from-literal=pagerduty-api-key="" \
  --from-literal=universal-http-token="my-ingest-token" \
  --from-literal=azure-tenant-id="" \
  --from-literal=azure-client-id="" \
  --from-literal=azure-client-secret="" \
  --from-literal=crowdstrike-client-id="" \
  --from-literal=crowdstrike-client-secret="" \
  -n tengen
```

Then reference it:

```bash
helm install tengen helm/tengen/ \
  --namespace tengen \
  --set existingSecret=tengen-secrets
```

### External RabbitMQ

To use an existing RabbitMQ instance instead of deploying one:

```bash
helm install tengen helm/tengen/ \
  --namespace tengen \
  --set rabbitmq.enabled=false \
  --set externalRabbitmq.url="amqp://user:pass@rabbitmq.example.com:5672/" \
  --set secrets.googleApiKey="YOUR_KEY"
```

### Enabling Optional Consumers

Enable consumers for your event sources:

```bash
helm install tengen helm/tengen/ \
  --namespace tengen \
  --set secrets.googleApiKey="YOUR_KEY" \
  --set sqs.enabled=true \
  --set aws.sqsQueueUrl="https://sqs.us-east-1.amazonaws.com/123456789/alerts" \
  --set kafkaConsumer.enabled=true \
  --set kafka.bootstrapServers="kafka-0.kafka.svc:9092" \
  --set pubsub.enabled=true \
  --set gcp.pubsubProjectId="my-project" \
  --set gcp.pubsubSubscriptionId="tengen-alerts-sub" \
  --set splunkEs.enabled=true
```

### Verifying the Installation

```bash
# Check all pods are running
oc get pods -n tengen

# Check deployments
oc get deployments -n tengen

# Check routes
oc get routes -n tengen

# Check the dashboard is responding
DASHBOARD_URL=$(oc get route tengen-dashboard -n tengen -o jsonpath='{.spec.host}')
curl -sk "https://${DASHBOARD_URL}/api/overview"

# Check the ingest endpoint
INGEST_URL=$(oc get route tengen-ingest -n tengen -o jsonpath='{.spec.host}')
curl -sk -X POST "https://${INGEST_URL}/ingest" \
  -H "Content-Type: application/json" \
  -d '{"test": true}'

# Check RabbitMQ (if deployed as subchart)
oc port-forward svc/tengen-rabbitmq 15672:15672 -n tengen &
# Open http://localhost:15672 (guest/guest)
```

---

## Manual Installation (Fallback)

Use this when Helm is unavailable or you need fine-grained control over each
resource.

### Create the Namespace

```bash
oc new-project tengen
```

### Create the Secret

```bash
oc create secret generic tengen \
  --from-literal=google-api-key="YOUR_GOOGLE_API_KEY" \
  --from-literal=rabbitmq-url="amqp://guest:guest@tengen-rabbitmq:5672/" \
  --from-literal=splunk-hec-url="" \
  --from-literal=splunk-hec-token="" \
  --from-literal=splunk-es-host="" \
  --from-literal=splunk-es-token="" \
  --from-literal=pagerduty-api-key="" \
  --from-literal=universal-http-token="" \
  --from-literal=azure-tenant-id="" \
  --from-literal=azure-client-id="" \
  --from-literal=azure-client-secret="" \
  --from-literal=crowdstrike-client-id="" \
  --from-literal=crowdstrike-client-secret="" \
  -n tengen
```

### Create the n8n Routes ConfigMap

```bash
oc create configmap tengen-n8n-routes \
  --from-file=n8n_routes.yaml=n8n_routes.example.yaml \
  -n tengen
```

### Deploy RabbitMQ

```bash
cat <<'EOF' | oc apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tengen-rabbitmq
  namespace: tengen
spec:
  replicas: 1
  selector:
    matchLabels:
      app: tengen-rabbitmq
  template:
    metadata:
      labels:
        app: tengen-rabbitmq
    spec:
      containers:
        - name: rabbitmq
          image: rabbitmq:3.13-management-alpine
          ports:
            - containerPort: 5672
              name: amqp
            - containerPort: 15672
              name: management
          env:
            - name: RABBITMQ_DEFAULT_USER
              value: guest
            - name: RABBITMQ_DEFAULT_PASS
              value: guest
          readinessProbe:
            exec:
              command: ["rabbitmq-diagnostics", "ping"]
            initialDelaySeconds: 10
            periodSeconds: 10
          resources:
            requests:
              cpu: 200m
              memory: 256Mi
            limits:
              cpu: "1"
              memory: 512Mi
---
apiVersion: v1
kind: Service
metadata:
  name: tengen-rabbitmq
  namespace: tengen
spec:
  ports:
    - port: 5672
      targetPort: amqp
      name: amqp
    - port: 15672
      targetPort: management
      name: management
  selector:
    app: tengen-rabbitmq
EOF
```

Wait for RabbitMQ to become ready:

```bash
oc rollout status deployment/tengen-rabbitmq -n tengen --timeout=120s
```

### Deploy Tengen Components

Set the image reference (adjust for your registry):

```bash
IMAGE="image-registry.openshift-image-registry.svc:5000/tengen/tengen:latest"
```

**Router:**

```bash
cat <<EOF | oc apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tengen-router
  namespace: tengen
spec:
  replicas: 1
  selector:
    matchLabels:
      app: tengen
      component: router
  template:
    metadata:
      labels:
        app: tengen
        component: router
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
      containers:
        - name: router
          image: ${IMAGE}
          command: ["python", "-m", "tengen.router_main"]
          envFrom:
            - secretRef:
                name: tengen
          env:
            - name: RABBITMQ_URL
              valueFrom:
                secretKeyRef:
                  name: tengen
                  key: rabbitmq-url
            - name: N8N_ROUTES_PATH
              value: /etc/tengen/n8n_routes.yaml
            - name: N8N_TIMEOUT
              value: "30"
            - name: N8N_MAX_RETRIES
              value: "3"
            - name: N8N_BACKOFF_BASE
              value: "2"
            - name: MODEL_NAME
              value: gemini-2.0-flash
          volumeMounts:
            - name: n8n-routes
              mountPath: /etc/tengen
              readOnly: true
          resources:
            requests:
              cpu: 200m
              memory: 256Mi
            limits:
              cpu: "1"
              memory: 512Mi
      volumes:
        - name: n8n-routes
          configMap:
            name: tengen-n8n-routes
EOF
```

**Forwarder:**

```bash
cat <<EOF | oc apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tengen-forwarder
  namespace: tengen
spec:
  replicas: 1
  selector:
    matchLabels:
      app: tengen
      component: forwarder
  template:
    metadata:
      labels:
        app: tengen
        component: forwarder
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
      containers:
        - name: forwarder
          image: ${IMAGE}
          command: ["python", "-m", "tengen.forwarder_main"]
          env:
            - name: RABBITMQ_URL
              valueFrom:
                secretKeyRef:
                  name: tengen
                  key: rabbitmq-url
            - name: SPLUNK_HEC_URL
              valueFrom:
                secretKeyRef:
                  name: tengen
                  key: splunk-hec-url
            - name: SPLUNK_HEC_TOKEN
              valueFrom:
                secretKeyRef:
                  name: tengen
                  key: splunk-hec-token
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 256Mi
EOF
```

**Dashboard:**

```bash
cat <<EOF | oc apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tengen-dashboard
  namespace: tengen
spec:
  replicas: 1
  selector:
    matchLabels:
      app: tengen
      component: dashboard
  template:
    metadata:
      labels:
        app: tengen
        component: dashboard
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
      containers:
        - name: dashboard
          image: ${IMAGE}
          command: ["python", "-m", "tengen.dashboard_main"]
          env:
            - name: RABBITMQ_URL
              valueFrom:
                secretKeyRef:
                  name: tengen
                  key: rabbitmq-url
            - name: RABBITMQ_MGMT_URL
              value: http://tengen-rabbitmq:15672
            - name: RABBITMQ_USER
              value: guest
            - name: RABBITMQ_PASS
              value: guest
            - name: DASHBOARD_HOST
              value: "0.0.0.0"
            - name: DASHBOARD_PORT
              value: "8080"
          ports:
            - containerPort: 8080
              name: http
          livenessProbe:
            httpGet:
              path: /api/overview
              port: http
            initialDelaySeconds: 10
            periodSeconds: 30
          readinessProbe:
            httpGet:
              path: /api/overview
              port: http
            initialDelaySeconds: 5
            periodSeconds: 10
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 256Mi
EOF
```

**Ingest (Universal HTTP Consumer):**

```bash
cat <<EOF | oc apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tengen-ingest
  namespace: tengen
spec:
  replicas: 1
  selector:
    matchLabels:
      app: tengen
      component: ingest
  template:
    metadata:
      labels:
        app: tengen
        component: ingest
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
      containers:
        - name: ingest
          image: ${IMAGE}
          command: ["python", "-m", "tengen.consumers.universal_consumer"]
          env:
            - name: RABBITMQ_URL
              valueFrom:
                secretKeyRef:
                  name: tengen
                  key: rabbitmq-url
            - name: UNIVERSAL_HTTP_HOST
              value: "0.0.0.0"
            - name: UNIVERSAL_HTTP_PORT
              value: "8088"
            - name: UNIVERSAL_HTTP_TOKEN
              valueFrom:
                secretKeyRef:
                  name: tengen
                  key: universal-http-token
                  optional: true
          ports:
            - containerPort: 8088
              name: http
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 256Mi
EOF
```

### Create Services

```bash
cat <<'EOF' | oc apply -f -
apiVersion: v1
kind: Service
metadata:
  name: tengen-dashboard
  namespace: tengen
spec:
  ports:
    - port: 8080
      targetPort: 8080
      name: http
  selector:
    app: tengen
    component: dashboard
---
apiVersion: v1
kind: Service
metadata:
  name: tengen-ingest
  namespace: tengen
spec:
  ports:
    - port: 8088
      targetPort: 8088
      name: http
  selector:
    app: tengen
    component: ingest
EOF
```

### Create OpenShift Routes

```bash
oc create route edge tengen-dashboard \
  --service=tengen-dashboard \
  --port=http \
  --insecure-policy=Redirect \
  -n tengen

oc create route edge tengen-ingest \
  --service=tengen-ingest \
  --port=http \
  --insecure-policy=Redirect \
  -n tengen
```

Verify:

```bash
oc get routes -n tengen
```

---

## OpenShift CRC (Local Development)

### CRC Setup

Install and configure CRC with enough resources for Tengen:

```bash
# Download CRC from https://console.redhat.com/openshift/create/local

# Configure resources (minimum for Tengen + RabbitMQ)
crc config set cpus 6
crc config set memory 14336
crc config set disk-size 50

# Set up and start
crc setup
crc start

# Configure shell
eval $(crc oc-env)
oc login -u developer -p developer https://api.crc.testing:6443
```

### CRC-Specific Image Build

CRC can build images directly inside the cluster using `oc new-build`,
avoiding registry push entirely:

```bash
# Create the namespace
oc new-project tengen

# Create a BuildConfig from the Dockerfile
oc new-build --name=tengen --binary --strategy=docker -n tengen

# Start a build from local source
oc start-build tengen --from-dir=. --follow -n tengen
```

The resulting image is available at:
```
image-registry.openshift-image-registry.svc:5000/tengen/tengen:latest
```

This is the default `image.repository` in the Helm chart values.

### CRC Resource Limits

CRC has limited resources. Use a minimal values file:

```yaml
# crc-values.yaml
router:
  replicas: 1
  resources:
    requests:
      cpu: 50m
      memory: 128Mi
    limits:
      cpu: 500m
      memory: 256Mi

forwarder:
  replicas: 1
  resources:
    requests:
      cpu: 50m
      memory: 64Mi
    limits:
      cpu: 250m
      memory: 128Mi

dashboard:
  replicas: 1
  resources:
    requests:
      cpu: 50m
      memory: 64Mi
    limits:
      cpu: 250m
      memory: 128Mi

ingest:
  replicas: 1
  resources:
    requests:
      cpu: 50m
      memory: 64Mi
    limits:
      cpu: 250m
      memory: 128Mi

rabbitmq:
  enabled: true
  auth:
    username: guest
    password: guest
  persistence:
    enabled: false
  resources:
    requests:
      cpu: 100m
      memory: 128Mi
    limits:
      cpu: 500m
      memory: 256Mi
```

Install:

```bash
helm install tengen helm/tengen/ \
  --namespace tengen \
  -f crc-values.yaml \
  --set secrets.googleApiKey="YOUR_KEY"
```

### CRC Networking

CRC routes are accessible at `*.apps-crc.testing`. After installation:

```bash
# Dashboard
open "https://tengen-dashboard-tengen.apps-crc.testing"

# Ingest
curl -sk -X POST "https://tengen-ingest-tengen.apps-crc.testing/ingest" \
  -H "Content-Type: application/json" \
  -d '{"eventSource": "iam.amazonaws.com", "eventName": "CreateUser"}'
```

If DNS resolution fails, add the CRC IP to `/etc/hosts`:

```bash
CRC_IP=$(crc ip)
echo "${CRC_IP} tengen-dashboard-tengen.apps-crc.testing tengen-ingest-tengen.apps-crc.testing" \
  | sudo tee -a /etc/hosts
```

---

## Full OpenShift Cluster (Production)

### Production Checklist

Before deploying to production, verify:

- [ ] **Secrets**: Use `existingSecret` pointing to a Vault-managed or Sealed Secret.
      Never store API keys in `values.yaml` committed to source control.
- [ ] **Image tag**: Pin to a specific tag (e.g., `0.2.0`), not `latest`.
- [ ] **n8n connectivity**: Confirm pods can reach your n8n webhook URLs from within
      the cluster. Test with `oc debug` or a curl pod.
- [ ] **RabbitMQ**: Use an external, managed RabbitMQ instance with TLS, not the
      subchart. Set `rabbitmq.enabled=false` and `externalRabbitmq.url`.
- [ ] **Splunk HEC**: Verify the HEC endpoint is reachable and the token is valid.
- [ ] **TLS**: Routes use edge termination by default. For end-to-end TLS,
      configure `passthrough` termination and add TLS to the container.
- [ ] **Resource limits**: Size based on your event volume (see sizing guide below).
- [ ] **Network policies**: Restrict traffic to only necessary flows.
- [ ] **Pod disruption budgets**: Set for router and forwarder if running >1 replica.

### High Availability

```yaml
# production-values.yaml
router:
  replicas: 3
  resources:
    requests:
      cpu: 500m
      memory: 512Mi
    limits:
      cpu: "2"
      memory: 1Gi

forwarder:
  replicas: 2

dashboard:
  replicas: 2

ingest:
  replicas: 3

affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          labelSelector:
            matchExpressions:
              - key: app.kubernetes.io/name
                operator: In
                values:
                  - tengen
          topologyKey: kubernetes.io/hostname
```

### Resource Sizing

Rough guidelines based on events per second (EPS):

| Component | < 10 EPS | 10-100 EPS | 100-1000 EPS |
|-----------|----------|------------|--------------|
| Router | 1 replica, 256Mi | 2 replicas, 512Mi | 3+ replicas, 1Gi |
| Forwarder | 1 replica, 128Mi | 1 replica, 256Mi | 2+ replicas, 512Mi |
| Dashboard | 1 replica, 128Mi | 1 replica, 256Mi | 2 replicas, 256Mi |
| Ingest | 1 replica, 128Mi | 2 replicas, 256Mi | 3+ replicas, 512Mi |
| RabbitMQ | 256Mi | 512Mi | 1Gi+ (clustered) |

The router is the most CPU-intensive component (LLM agent inference). Scale it
first when throughput is constrained.

### Network Policies

Restrict traffic to only necessary paths:

```bash
cat <<'EOF' | oc apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: tengen-internal
  namespace: tengen
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: tengen
  policyTypes:
    - Ingress
    - Egress
  ingress:
    # Allow traffic from OpenShift router (for Routes)
    - from:
        - namespaceSelector:
            matchLabels:
              network.openshift.io/policy-group: ingress
    # Allow internal pod-to-pod
    - from:
        - podSelector:
            matchLabels:
              app.kubernetes.io/name: tengen
  egress:
    # Allow DNS
    - to: []
      ports:
        - port: 53
          protocol: UDP
        - port: 53
          protocol: TCP
    # Allow RabbitMQ
    - to:
        - podSelector:
            matchLabels:
              app.kubernetes.io/name: rabbitmq
      ports:
        - port: 5672
    # Allow n8n webhooks (external)
    - to: []
      ports:
        - port: 443
        - port: 80
    # Allow Splunk HEC (external)
    - to: []
      ports:
        - port: 8088
    # Allow Gemini API (external)
    - to: []
      ports:
        - port: 443
EOF
```

### Persistent Storage

RabbitMQ needs persistent storage in production. The Bitnami subchart handles
this with a PVC:

```yaml
rabbitmq:
  persistence:
    enabled: true
    size: 20Gi
    storageClass: gp3  # Adjust to your cluster's storage class
```

If using an external RabbitMQ, no PVCs are needed for Tengen itself — all
Tengen pods are stateless.

---

## n8n Routing Spec Management

### Updating Routes Without Redeployment

The `RouteResolver` watches the ConfigMap file for changes. Update the routes
by replacing the ConfigMap:

```bash
# Edit your local n8n_routes.yaml, then:
oc create configmap tengen-n8n-routes \
  --from-file=n8n_routes.yaml=my-updated-routes.yaml \
  -o yaml --dry-run=client | oc apply -f -n tengen
```

The kubelet syncs mounted ConfigMaps within ~60 seconds. The route resolver
detects the file mtime change and reloads automatically. No pod restart needed.

To force immediate reload (restart the router pod):

```bash
oc rollout restart deployment/tengen-router -n tengen
```

If you used Helm, update via `helm upgrade`:

```bash
helm upgrade tengen helm/tengen/ \
  --namespace tengen \
  --reuse-values \
  -f my-updated-values.yaml
```

### Validating a Routes File

Before applying, validate the YAML structure:

```bash
python -c "
import yaml, sys
with open('my-updated-routes.yaml') as f:
    data = yaml.safe_load(f)
routes = data.get('routes', {})
if '_default' not in routes:
    print('WARNING: No root _default route. Unmatched events will raise NoRouteError.')
print(f'Loaded {len(routes)} top-level entries.')
for vendor, node in routes.items():
    if vendor.startswith('_'):
        continue
    print(f'  {vendor}:', 'leaf' if 'webhook' in (node or {}) else f'{len([k for k in (node or {}) if not k.startswith(\"_\") and k != \"description\"])} categories')
"
```

---

## Upgrading

### Helm Upgrade

```bash
# Rebuild the image
podman build -t tengen:0.2.1 -f Dockerfile .
podman tag tengen:0.2.1 "${REGISTRY}/tengen/tengen:0.2.1"
podman push "${REGISTRY}/tengen/tengen:0.2.1"

# Upgrade the release
helm upgrade tengen helm/tengen/ \
  --namespace tengen \
  --reuse-values \
  --set image.tag="0.2.1"
```

### Manual Upgrade

```bash
# Build and push the new image
podman build -t tengen:0.2.1 -f Dockerfile .
podman tag tengen:0.2.1 "${REGISTRY}/tengen/tengen:0.2.1"
podman push "${REGISTRY}/tengen/tengen:0.2.1"

# Update each deployment
for DEPLOY in tengen-router tengen-forwarder tengen-dashboard tengen-ingest; do
  oc set image deployment/${DEPLOY} \
    "*=${REGISTRY}/tengen/tengen:0.2.1" \
    -n tengen
done
```

### Rolling vs Recreate

All Tengen pods are stateless and use the default `RollingUpdate` strategy.
During an upgrade:

- **Router/Forwarder**: Zero downtime. Old pods continue processing while new
  pods start. Events are not lost (RabbitMQ provides the durability).
- **Dashboard**: Brief overlap. Both versions serve traffic until old pods
  terminate.
- **Ingest**: Zero downtime. The Route distributes traffic to both old and new
  pods during rollout.

---

## Uninstalling

### Helm

```bash
helm uninstall tengen -n tengen

# If you want to remove the namespace entirely:
oc delete project tengen
```

### Manual

```bash
oc delete deployment tengen-router tengen-forwarder tengen-dashboard tengen-ingest -n tengen
oc delete deployment tengen-rabbitmq -n tengen
oc delete svc tengen-dashboard tengen-ingest tengen-rabbitmq -n tengen
oc delete route tengen-dashboard tengen-ingest -n tengen
oc delete configmap tengen-n8n-routes -n tengen
oc delete secret tengen -n tengen

# Remove the namespace:
oc delete project tengen
```

---

## Troubleshooting and Debugging

### Pods Not Starting

```bash
# Check pod status
oc get pods -n tengen

# Describe a pod for events
oc describe pod <pod-name> -n tengen

# Common causes:
# - Insufficient resources: check "FailedScheduling" events
# - Missing secrets: check "CreateContainerConfigError"
# - Image not found: check "ImagePullBackOff"
```

### ImagePullBackOff

The pod cannot pull the container image.

```bash
# Check the exact error
oc describe pod <pod-name> -n tengen | grep -A5 "Events:"

# Verify the image exists
oc get is tengen -n tengen

# Verify the image stream tag
oc get istag tengen:latest -n tengen

# If using the internal registry, verify the pod's service account can pull:
oc policy add-role-to-user system:image-puller \
  system:serviceaccount:tengen:default \
  --namespace=tengen

# If the image was pushed with --tls-verify=false (CRC), ensure the
# deployment references the internal service URL, not the external route:
#   image-registry.openshift-image-registry.svc:5000/tengen/tengen:latest
```

### CrashLoopBackOff

The container starts but crashes immediately.

```bash
# Check logs from the most recent crash
oc logs <pod-name> -n tengen --previous

# Common causes:

# 1. Missing GOOGLE_API_KEY
#    Error: "GOOGLE_API_KEY environment variable not set"
#    Fix: Set the secret value

# 2. RabbitMQ not ready
#    Error: "Connection refused" or "pika.exceptions.AMQPConnectionError"
#    Fix: Wait for RabbitMQ to be ready, check RABBITMQ_URL

# 3. n8n routes file not found
#    Error: "FileNotFoundError: /etc/tengen/n8n_routes.yaml"
#    Fix: Verify the ConfigMap is mounted correctly:
oc get configmap tengen-n8n-routes -n tengen
oc describe pod <pod-name> -n tengen | grep -A5 "Mounts:"

# 4. Python import error
#    Error: "ModuleNotFoundError"
#    Fix: Rebuild the image — the source may be stale
```

### RabbitMQ Connection Failures

```bash
# 1. Check RabbitMQ pod
oc get pods -l app.kubernetes.io/name=rabbitmq -n tengen

# 2. Check RabbitMQ service
oc get svc -l app.kubernetes.io/name=rabbitmq -n tengen

# 3. Test connectivity from a debug pod
oc debug deployment/tengen-router -n tengen -- \
  python -c "import pika; pika.BlockingConnection(pika.URLParameters('amqp://guest:guest@tengen-rabbitmq:5672/'))"

# 4. Check RabbitMQ logs
oc logs deployment/tengen-rabbitmq -n tengen

# 5. If using external RabbitMQ, verify network reachability:
oc debug deployment/tengen-router -n tengen -- \
  python -c "import socket; s=socket.create_connection(('rabbitmq.example.com', 5672), timeout=5); print('OK'); s.close()"
```

### n8n Webhook Failures

```bash
# 1. Check router logs for n8n dispatch errors
oc logs deployment/tengen-router -n tengen | grep -i "n8n\|webhook\|N8nRequestFailed"

# 2. Test n8n connectivity from inside the cluster
oc debug deployment/tengen-router -n tengen -- \
  python -c "
import httpx
r = httpx.post('https://n8n.example.com/webhook/test', json={'test': True}, timeout=10)
print(r.status_code, r.text[:200])
"

# 3. Verify the routing spec is loaded
oc exec deployment/tengen-router -n tengen -- \
  cat /etc/tengen/n8n_routes.yaml

# 4. Check for TLS/certificate issues (common with internal n8n)
oc debug deployment/tengen-router -n tengen -- \
  python -c "
import httpx
try:
    r = httpx.get('https://n8n.internal/webhook/health', timeout=5)
    print('OK:', r.status_code)
except httpx.ConnectError as e:
    print('Connection error:', e)
except Exception as e:
    print('Error:', type(e).__name__, e)
"

# 5. If n8n uses self-signed certificates, you may need to add the CA to
#    the container. Mount the CA as a ConfigMap and set:
#    SSL_CERT_FILE=/etc/ssl/certs/n8n-ca.crt
```

### Dashboard Not Loading

```bash
# 1. Check dashboard pod
oc logs deployment/tengen-dashboard -n tengen

# 2. Test the service directly (bypass the Route)
oc port-forward svc/tengen-dashboard 8080:8080 -n tengen
curl http://localhost:8080/api/overview

# 3. If the Route works but the page is blank, check the static files
oc exec deployment/tengen-dashboard -n tengen -- \
  ls -la /app/tengen/dashboard/static/

# 4. Check the RabbitMQ management API connection (dashboard uses it)
oc exec deployment/tengen-dashboard -n tengen -- \
  python -c "
import httpx
r = httpx.get('http://tengen-rabbitmq:15672/api/overview', auth=('guest','guest'), timeout=5)
print(r.status_code)
"
```

### Route Not Accessible

```bash
# 1. Check the Route exists and has a host
oc get routes -n tengen

# 2. Check the Route status
oc describe route tengen-dashboard -n tengen

# 3. Verify the service has endpoints
oc get endpoints tengen-dashboard -n tengen

# 4. If endpoints are empty, the selector doesn't match any pods:
oc get pods -l app.kubernetes.io/component=dashboard -n tengen

# 5. Test with port-forward to bypass the Route entirely
oc port-forward svc/tengen-dashboard 8080:8080 -n tengen

# 6. Check if the OpenShift router (HAProxy) is healthy
oc get pods -n openshift-ingress
```

### OpenShift CRC-Specific Issues

**CRC won't start / not enough resources:**

```bash
# Check CRC status
crc status

# Increase resources if needed
crc stop
crc config set cpus 8
crc config set memory 16384
crc start
```

**DNS resolution fails for `*.apps-crc.testing`:**

```bash
# Get the CRC IP
CRC_IP=$(crc ip)

# Add entries to /etc/hosts
echo "${CRC_IP} tengen-dashboard-tengen.apps-crc.testing" | sudo tee -a /etc/hosts
echo "${CRC_IP} tengen-ingest-tengen.apps-crc.testing" | sudo tee -a /etc/hosts
```

**Certificate errors when pushing images:**

```bash
# Push with TLS verification disabled (CRC only — never in production)
podman push "${REGISTRY}/tengen/tengen:latest" --tls-verify=false
```

**Pods stuck in Pending due to resource pressure:**

```bash
# Check node resources
oc describe node crc | grep -A10 "Allocated resources"

# Reduce resource requests in values or delete other workloads
oc get pods -A | grep Running | wc -l
```

### Useful Debug Commands

```bash
# Get all Tengen resources at a glance
oc get all -l app.kubernetes.io/name=tengen -n tengen

# Follow logs from all Tengen pods
oc logs -l app.kubernetes.io/name=tengen -n tengen --all-containers -f

# Follow logs from a specific component
oc logs -l app.kubernetes.io/component=router -n tengen -f

# Open an interactive shell in a running pod
oc exec -it deployment/tengen-router -n tengen -- /bin/bash

# Open a debug pod with the same image (if the container crashes)
oc debug deployment/tengen-router -n tengen

# Check resource usage
oc adm top pods -n tengen

# Check events (useful for scheduling and pull errors)
oc get events -n tengen --sort-by='.lastTimestamp'

# Export the current state for review
oc get all,configmap,secret,route -n tengen -o yaml > tengen-export.yaml

# Check n8n routes ConfigMap content
oc get configmap tengen-n8n-routes -n tengen -o jsonpath='{.data.n8n_routes\.yaml}'

# Verify the image digest
oc get istag tengen:latest -n tengen -o jsonpath='{.image.dockerImageReference}'

# Force a fresh pull of the image
oc import-image tengen:latest --from=${REGISTRY}/tengen/tengen:latest \
  --confirm -n tengen
```
