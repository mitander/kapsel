#!/usr/bin/env bash
set -euo pipefail

cluster_name="kapsel-effect-gateway-test-$$-${RANDOM}"
node_image="kindest/node:v1.33.12@sha256:3f5c8443c620245e4d355cfe09e96a91ead32ceaa569d3f1ca9edf0cb2fe2ff4"
fixture_image="registry.k8s.io/pause:3.10.1"
target_image="registry.k8s.io/pause@sha256:278fb9dbcca9518083ad1e11276933a2e96f23de604a3a08cc3c80002767d24c"
webhook_image="kapsel-recovery-policy-webhook:${cluster_name}"
log_directory="${TMPDIR:-/tmp}/kapsel-kind-logs-$$"
workspace=$(mktemp -d "${TMPDIR:-/tmp}/kapsel-kind-workspace.XXXXXX")
kubeconfig="$workspace/kubeconfig"
cluster_owned=0
webhook_image_owned=0

phase() {
  printf '[kind %s/9] %s\n' "$1" "$2"
}

monotonic_ns() {
  python3 -c 'import time; print(time.monotonic_ns())'
}

elapsed_ms() {
  python3 -c "print((${2} - ${1}) // 1000000)"
}

cleanup() {
  status=$?
  trap - EXIT INT TERM
  set +e
  if [[ $status -ne 0 && $cluster_owned -eq 1 ]]; then
    mkdir -p "$log_directory"
    if kind export logs "$log_directory" --name "$cluster_name"; then
      printf 'kind failure logs: %s\n' "$log_directory" >&2
    else
      printf 'could not export kind failure logs: %s\n' "$log_directory" >&2
    fi
  fi
  if [[ $cluster_owned -eq 1 ]]; then
    phase 9 "deleting owned cluster $cluster_name"
    cleanup_started=$(monotonic_ns)
    if ! kind delete cluster --name "$cluster_name"; then
      printf 'could not delete owned kind cluster: %s\n' "$cluster_name" >&2
      if [[ $status -eq 0 ]]; then
        status=1
      fi
    fi
    cleanup_finished=$(monotonic_ns)
    printf '[kind timing] cleanup_ms=%s\n' "$(elapsed_ms "$cleanup_started" "$cleanup_finished")"
  fi
  if [[ $webhook_image_owned -eq 1 ]]; then
    docker image rm "$webhook_image" >/dev/null 2>&1 || true
  fi
  rm -rf "$workspace"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

printf '[kind] checking Docker-compatible runtime, kind, kubectl, and OpenSSL prerequisites\n'
docker info >/dev/null
if ! command -v kubectl >/dev/null 2>&1; then
  printf 'kubectl 1.30 or newer is required\n' >&2
  exit 1
fi
kubectl_version=$(kubectl version --client=true -o json)
read -r kubectl_major kubectl_minor < <(
  python3 -c '
import json, re, sys
version = json.load(sys.stdin)["clientVersion"]
minor = re.match(r"[0-9]+", version["minor"])
if minor is None:
    raise SystemExit("cannot parse kubectl minor version")
print(version["major"], minor.group(0))
' <<<"$kubectl_version"
)
if ((kubectl_major < 1 || (kubectl_major == 1 && kubectl_minor < 30))); then
  printf 'kubectl 1.30 or newer is required; found %s.%s\n' \
    "$kubectl_major" "$kubectl_minor" >&2
  exit 1
fi
if ! command -v openssl >/dev/null 2>&1; then
  printf 'OpenSSL is required for the disposable admission-webhook certificate\n' >&2
  exit 1
fi
kind_version=$(kind version)
if [[ ! $kind_version =~ ^kind\ v([0-9]+)\.([0-9]+)\.([0-9]+)([[:space:]]|$) ]]; then
  printf 'cannot parse kind version: %s\n' "$kind_version" >&2
  exit 1
fi
kind_major=${BASH_REMATCH[1]}
kind_minor=${BASH_REMATCH[2]}
if ((kind_major == 0 && kind_minor < 32)); then
  printf 'kind 0.32 or newer is required; found: %s\n' "$kind_version" >&2
  exit 1
fi
if ! existing_clusters=$(kind get clusters); then
  printf 'could not enumerate kind clusters; refusing to create one\n' >&2
  exit 1
fi
if grep -Fqx "$cluster_name" <<<"$existing_clusters"; then
  printf 'refusing to use existing kind cluster: %s\n' "$cluster_name" >&2
  exit 1
fi
if docker image inspect "$webhook_image" >/dev/null 2>&1; then
  printf 'refusing to replace existing Docker image tag: %s\n' "$webhook_image" >&2
  exit 1
fi
phase 1 "precompiling Kapsel tests"
cargo test --locked -p kapsel --no-run
phase 2 "creating disposable cluster $cluster_name"
cluster_owned=1
cluster_started=$(monotonic_ns)
kind create cluster \
  --name "$cluster_name" \
  --image "$node_image" \
  --kubeconfig "$kubeconfig" \
  --wait 120s
export KUBECONFIG="$kubeconfig"
cluster_finished=$(monotonic_ns)
printf '[kind timing] cluster_create_ms=%s\n' "$(elapsed_ms "$cluster_started" "$cluster_finished")"

phase 3 "loading two pinned fixture images"
printf '[kind] loading %s\n' "$fixture_image"
docker exec "${cluster_name}-control-plane" crictl pull "$fixture_image"
printf '[kind] loading %s\n' "$target_image"
docker exec "${cluster_name}-control-plane" crictl pull "$target_image"

phase 4 "installing the instrumented recovery-policy admission webhook"
docker build --tag "$webhook_image" tests/fixtures/recovery-policy-webhook
webhook_image_owned=1
kind load docker-image --name "$cluster_name" "$webhook_image"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$workspace/tls.key" \
  -out "$workspace/tls.crt" \
  -subj '/CN=recovery-policy-webhook.kapsel-recovery-policy-webhook.svc' \
  -addext 'subjectAltName=DNS:recovery-policy-webhook.kapsel-recovery-policy-webhook.svc' \
  >/dev/null 2>&1
ca_bundle=$(base64 <"$workspace/tls.crt" | tr -d '\n')
kubectl create namespace kapsel-recovery-policy-webhook
kubectl -n kapsel-recovery-policy-webhook create secret tls recovery-policy-webhook-tls \
  --cert="$workspace/tls.crt" \
  --key="$workspace/tls.key"
kubectl -n kapsel-recovery-policy-webhook apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: recovery-policy-webhook
spec:
  replicas: 1
  selector:
    matchLabels:
      app: recovery-policy-webhook
  template:
    metadata:
      labels:
        app: recovery-policy-webhook
    spec:
      containers:
        - name: webhook
          image: $webhook_image
          imagePullPolicy: IfNotPresent
          ports:
            - containerPort: 8443
          readinessProbe:
            tcpSocket:
              port: 8443
          volumeMounts:
            - name: tls
              mountPath: /tls
              readOnly: true
      volumes:
        - name: tls
          secret:
            secretName: recovery-policy-webhook-tls
---
apiVersion: v1
kind: Service
metadata:
  name: recovery-policy-webhook
spec:
  selector:
    app: recovery-policy-webhook
  ports:
    - port: 443
      targetPort: 8443
EOF
kubectl -n kapsel-recovery-policy-webhook rollout status \
  deployment/recovery-policy-webhook \
  --timeout=60s
kubectl apply -f - <<EOF
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: kapsel-recovery-policy
webhooks:
  - name: recovery-policy.kapsel.dev
    admissionReviewVersions: ["v1"]
    sideEffects: NoneOnDryRun
    failurePolicy: Fail
    timeoutSeconds: 5
    clientConfig:
      service:
        namespace: kapsel-recovery-policy-webhook
        name: recovery-policy-webhook
        path: /admit
      caBundle: $ca_bundle
    namespaceSelector:
      matchLabels:
        kapsel.dev/recovery-policy: "true"
    rules:
      - apiGroups: ["apps"]
        apiVersions: ["v1"]
        operations: ["UPDATE"]
        resources: ["deployments"]
        scope: Namespaced
EOF

phase 5 "running healthy rollout proof"
scenario_started=$(monotonic_ns)
KAPSEL_KIND_TEST=1 cargo test --locked \
  -p kapsel \
  kind_tests::kind_changes_exactly_one_container_through_the_gateway \
  -- \
  --ignored \
  --exact \
  --nocapture
scenario_finished=$(monotonic_ns)
printf '[kind timing] healthy_ms=%s\n' "$(elapsed_ms "$scenario_started" "$scenario_finished")"

phase 6 "running failed-rollout and receipt-inspection proof"
scenario_started=$(monotonic_ns)
KAPSEL_KIND_TEST=1 cargo test --locked \
  -p kapsel \
  kind_tests::kind_failed_rollout_recovers_and_inspects_classifier_complete_receipt \
  -- \
  --ignored \
  --exact \
  --nocapture
scenario_finished=$(monotonic_ns)
printf '[kind timing] failed_ms=%s\n' "$(elapsed_ms "$scenario_started" "$scenario_finished")"

phase 7 "running deleted-after-patch bounded-unknown proof"
scenario_started=$(monotonic_ns)
KAPSEL_KIND_TEST=1 cargo test --locked \
  -p kapsel \
  kind_tests::kind_deleted_after_patch_recovers_to_classifier_complete_unknown_receipt \
  -- \
  --ignored \
  --exact \
  --nocapture
scenario_finished=$(monotonic_ns)
printf '[kind timing] unknown_ms=%s\n' "$(elapsed_ms "$scenario_started" "$scenario_finished")"

phase 8 "running stale-replay admission-side-effect proof"
scenario_started=$(monotonic_ns)
KAPSEL_KIND_TEST=1 cargo test --locked \
  -p kapsel \
  kind_tests::kind_stale_exact_replay_reaches_admission_without_a_second_persisted_change \
  -- \
  --ignored \
  --exact \
  --nocapture
scenario_finished=$(monotonic_ns)
printf '[kind timing] recovery_policy_ms=%s\n' \
  "$(elapsed_ms "$scenario_started" "$scenario_finished")"
