#!/usr/bin/env bash
# Disposable-environment harness for the reconnectable agent action workflow experiment.
#
# Provisions one disposable kind cluster and one disposable Linux service container running the
# current unpublished `kapseld` composition behind its documented fixed paths, then exposes the
# operator and fixed-client steps of the experiment as explicit commands. Real-agent sessions drive
# the same fixed client boundary. Deterministic regressions remain owned by the existing crates;
# this harness exists so setup, invocation, fault injection, reconnect, inspection, and cleanup
# are reproducible without private state.
#
# Requirements: Docker, kind 0.32+, kubectl 1.30+, OpenSSL 3, jq, python3.
# Inputs:
#   KAPSEL_OPERATOR_BIN      host `kapsel` binary for operator provisioning and inspection
#   KAPSEL_SERVICE_BIN_DIR   directory with Linux `kapseld` and `kapsel-service-client` binaries
#                            built with `cargo build --locked --release -p kapseld --features
#                            test-harness`
set -euo pipefail

cluster_name="kapsel-agent-action-test-$$-${RANDOM}"
node_image="kindest/node:v1.33.12@sha256:3f5c8443c620245e4d355cfe09e96a91ead32ceaa569d3f1ca9edf0cb2fe2ff4"
fixture_image="registry.k8s.io/pause:3.10"
initial_image="registry.k8s.io/pause@sha256:ee6521f290b2168b6e0935a181d4cff9be1ac3f505666ef0e3c98fae8199917a"
healthy_image="registry.k8s.io/pause@sha256:278fb9dbcca9518083ad1e11276933a2e96f23de604a3a08cc3c80002767d24c"
unhealthy_image="registry.example.invalid/kapsel/unhealthy@sha256:1111111111111111111111111111111111111111111111111111111111111111"
experiment_image="kapsel-agent-action-experiment:${cluster_name}"
namespace="demo"
deployment="agent-api"
container_name="api"
service_account="kapsel-service"
authorization_key_id="owner-key"
receipt_key_id="receipt-key"
# Identity IDs are container-local and chosen to stay outside ordinary Debian ranges.
kapsel_uid=4100
kapsel_gid=4100
callers_gid=4200
caller_uid=4200
cluster_owned=0
image_owned=0
container_owned=0
workspace=""

phase() {
  printf '[agent-action %s] %s\n' "$1" "$2"
}

fail() {
  printf 'agent-action failure: %s\n' "$1" >&2
  return 1
}

cleanup() {
  if [[ $container_owned -eq 1 ]]; then
    docker rm -f "${cluster_name}-service" >/dev/null 2>&1 || true
  fi
  if [[ $image_owned -eq 1 ]]; then
    docker image rm "$experiment_image" >/dev/null 2>&1 || true
  fi
  if [[ $cluster_owned -eq 1 ]]; then
    kind delete cluster --name "$cluster_name" >/dev/null 2>&1 || true
  fi
}

require_inputs() {
  if [[ -n ${KAPSEL_OPERATOR_BIN:-} && -x ${KAPSEL_OPERATOR_BIN:-} && ! -L ${KAPSEL_OPERATOR_BIN:-} ]]; then
    :
  else
    fail "set KAPSEL_OPERATOR_BIN to the host kapsel operator binary"
  fi
  local directory=${KAPSEL_SERVICE_BIN_DIR:-}
  if [[ -x $directory/kapseld && -x $directory/kapsel-service-client && ! -L $directory/kapseld ]]; then
    :
  else
    fail "KAPSEL_SERVICE_BIN_DIR must contain kapseld and kapsel-service-client built with --features test-harness"
  fi
}

require_workspace() {
  if [[ -n ${KAPSEL_EXPERIMENT_WORKSPACE:-} ]]; then
    workspace=$KAPSEL_EXPERIMENT_WORKSPACE
  elif [[ -z $workspace ]]; then
    workspace=$(ls -dt /tmp/kap27-experiment.* 2>/dev/null | head -1 || true)
  fi
  [[ -n $workspace && -d $workspace ]] || fail "no experiment workspace; run the up command first"
  [[ -f $workspace/admin-kubeconfig.yaml ]] || fail "workspace $workspace has no admin kubeconfig"
  if [[ -f $workspace/cluster-name ]]; then
    cluster_name=$(cat "$workspace/cluster-name")
  fi
}

kubectl_admin() {
  kubectl --kubeconfig "$workspace/admin-kubeconfig.yaml" "$@"
}

write_operator_key_material() {
  # OpenSSL 3 generates the Ed25519 keypairs; the PKCS8 seed bytes become the operator signing
  # seeds and the raw 32-byte public keys become the service trust inputs.
  local name
  for name in authorization receipt; do
    openssl genpkey -algorithm ed25519 -outform DER -out "$workspace/${name}.key.der"
    openssl pkey -inform DER -in "$workspace/${name}.key.der" -pubout -outform DER \
      -out "$workspace/${name}.pub.der"
    python3 - "$workspace" "$name" <<'PY'
import sys

workspace, name = sys.argv[1], sys.argv[2]
key = open(f"{workspace}/{name}.key.der", "rb").read()
pub = open(f"{workspace}/{name}.pub.der", "rb").read()
PKCS8_SEED_PREFIX = bytes.fromhex("302e020100300506032b657004220420")
RAW_PUB_PREFIX = bytes.fromhex("302a300506032b6570032100")
assert key[:16] == PKCS8_SEED_PREFIX and len(key) == 48, "unexpected Ed25519 PKCS8 layout"
assert pub[:12] == RAW_PUB_PREFIX and len(pub) == 44, "unexpected Ed25519 public DER layout"
open(f"{workspace}/{name}.seed", "wb").write(key[16:])
open(f"{workspace}/{name}.pub", "wb").write(pub[12:])
PY
  done
}

write_receipt_trust() {
  # Encodes the repository's bounded receipt-trust document: magic, then tag + u32 length records.
  # Snapshot grants require the v3 receipt purpose.
  python3 - "$workspace" <<'PY'
import struct, sys, time

workspace = sys.argv[1]
magic = b"KAPSEL-KAP0038-K8S-TRUST-V2\x00"
purpose = b"kapsel.kap0038.kubernetes-effect-receipt.v3"
now = int(time.time())
out = bytearray(magic)
for tag, value in [
    (1, b"receipt-key"),
    (2, open(f"{workspace}/receipt.pub", "rb").read()),
    (3, purpose),
    (4, struct.pack(">q", now - 60)),
    (5, struct.pack(">q", now + 7 * 24 * 3600)),
]:
    out += bytes([tag]) + struct.pack(">I", len(value)) + value
open(f"{workspace}/receipt-trust.bin", "wb").write(bytes(out))
PY
}

write_service_kubeconfig() {
  local path=$1 address token ca
  address=$(docker inspect -f '{{.NetworkSettings.Networks.kind.IPAddress}}' "${cluster_name}-control-plane")
  ca=$(kubectl_admin config view --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')
  token=$(kubectl_admin create token "$service_account" --namespace "$namespace" --duration=4h)
  cat > "$path" <<EOF
apiVersion: v1
kind: Config
clusters:
- name: kapsel-experiment
  cluster:
    server: https://${address}:6443
    certificate-authority-data: ${ca}
users:
- name: kapsel-service
  user:
    token: ${token}
contexts:
- name: kapsel-experiment
  context:
    cluster: kapsel-experiment
    user: kapsel-service
current-context: kapsel-experiment
EOF
}

container_up() {
  local bin_dir=$1
  cat > "$workspace/Containerfile" <<EOF
FROM debian:bookworm-slim
COPY kapseld /usr/libexec/kapsel/kapseld
COPY kapsel-service-client /usr/bin/kapsel-service-client
RUN groupadd -g ${kapsel_gid} kapsel \\
 && groupadd -g ${callers_gid} kapsel-service-callers \\
 && useradd -u ${kapsel_uid} -g ${kapsel_gid} -M -d /nonexistent -s /usr/sbin/nologin kapsel \\
 && useradd -u ${caller_uid} -g ${callers_gid} -M -d /nonexistent -s /usr/sbin/nologin kapsel-service-caller \\
 && mkdir -p /etc/kapsel /var/lib/kapsel/receipts /run/kapsel \\
 && apt-get update -qq && apt-get install -y -qq --no-install-recommends procps && rm -rf /var/lib/apt/lists/* \
 && chown ${kapsel_uid}:${callers_gid} /etc/kapsel /var/lib/kapsel /var/lib/kapsel/receipts /run/kapsel \\
 && chmod 0700 /etc/kapsel /var/lib/kapsel /var/lib/kapsel/receipts \\
 && chmod 0750 /run/kapsel
EOF
  cp "$bin_dir/kapseld" "$workspace/kapseld"
  cp "$bin_dir/kapsel-service-client" "$workspace/kapsel-service-client"
  docker build --quiet -f "$workspace/Containerfile" --tag "$experiment_image" "$workspace" >/dev/null
  image_owned=1
  # The container joins the kind network so the service kubeconfig can target the pinned API
  # server address with its real certificate identity.
  docker run --detach --name "${cluster_name}-service" --network kind \
    "$experiment_image" sleep infinity >/dev/null
  container_owned=1
}

install_file_as_service_owner() {
  local source=$1 target=$2
  docker cp "$source" "${cluster_name}-service:$target" >/dev/null
  docker exec --user 0 "${cluster_name}-service" chown "${kapsel_uid}:${callers_gid}" "$target"
  docker exec --user 0 "${cluster_name}-service" chmod 0600 "$target"
}

write_operator_document() {
  docker exec -i --user 0 "${cluster_name}-service" tee /etc/kapsel/operator.json >/dev/null <<EOF
{
  "signed_authorization_grant": "/etc/kapsel/grant.bin",
  "authorization_key_id": "${authorization_key_id}",
  "authorization_public_key": "/etc/kapsel/authorization.pub",
  "kubeconfig": "/etc/kapsel/kubeconfig.yaml",
  "journal": "/var/lib/kapsel/journal.sqlite3",
  "receipt_directory": "/var/lib/kapsel/receipts",
  "receipt_signing_seed": "/etc/kapsel/receipt.seed",
  "receipt_signing_key_id": "${receipt_key_id}"
}
EOF
  docker exec --user 0 "${cluster_name}-service" \
    chown "${kapsel_uid}:${callers_gid}" /etc/kapsel/operator.json
  docker exec --user 0 "${cluster_name}-service" chmod 0600 /etc/kapsel/operator.json
}

command_up() {
  local bin_dir=${KAPSEL_SERVICE_BIN_DIR:-}
  require_inputs
  workspace=$(mktemp -d /tmp/kap27-experiment.XXXXXX)
  printf '[agent-action] workspace %s\n' "$workspace"

  phase 1 "creating disposable kind cluster $cluster_name"
  kind create cluster --name "$cluster_name" --image "$node_image" \
    --wait 90s --kubeconfig "$workspace/admin-kubeconfig.yaml" >/dev/null
  cluster_owned=1
  trap cleanup EXIT
  printf '%s' "$cluster_name" > "$workspace/cluster-name"

  phase 2 "loading pinned fixture images"
  docker exec "${cluster_name}-control-plane" crictl pull "$fixture_image" >/dev/null
  docker exec "${cluster_name}-control-plane" crictl pull "$healthy_image" >/dev/null

  phase 3 "creating $namespace/$deployment with a 60-second ready window"
  kubectl_admin create namespace "$namespace"
  kubectl_admin -n "$namespace" create deployment "$deployment" --image "$initial_image" --replicas 1
  kubectl_admin -n "$namespace" patch deployment "$deployment" --type merge -p \
    '{"spec":{"minReadySeconds":60,"progressDeadlineSeconds":180,"template":{"spec":{"containers":[{"name":"'"$container_name"'","image":"'"$initial_image"'","imagePullPolicy":"IfNotPresent"}]}}}}' \
    >/dev/null
  kubectl_admin -n "$namespace" wait deployment/"$deployment" \
    --for condition=Available --timeout 300s >/dev/null

  phase 4 "creating the scoped service identity and kubeconfig"
  kubectl_admin -n "$namespace" create serviceaccount "$service_account"
  kubectl_admin -n "$namespace" create role "$service_account" \
    --verb get,patch --resource deployments --resource-name "$deployment"
  kubectl_admin -n "$namespace" create rolebinding "$service_account" \
    --role "$service_account" --serviceaccount "$namespace:$service_account"
  write_service_kubeconfig "$workspace/service-kubeconfig.yaml"

  phase 5 "building and starting the service container"
  container_up "$bin_dir"

  phase 6 "installing operator material"
  write_operator_key_material
  write_receipt_trust
  install_file_as_service_owner "$workspace/authorization.pub" /etc/kapsel/authorization.pub
  install_file_as_service_owner "$workspace/authorization.seed" /etc/kapsel/authorization.seed
  install_file_as_service_owner "$workspace/receipt.seed" /etc/kapsel/receipt.seed
  install_file_as_service_owner "$workspace/service-kubeconfig.yaml" /etc/kapsel/kubeconfig.yaml
  write_operator_document
  # Keep the environment alive after a successful setup; failures above still clean up.
  trap - EXIT
  printf '[agent-action] environment ready; workspace %s\n' "$workspace"
}

command_grant() {
  local operation_id=$1 image=$2
  require_inputs
  require_workspace
  local authorization="$workspace/authorization-${operation_id}.json"
  cat > "$authorization" <<EOF
{
  "authorization_id": "auth-${operation_id}",
  "operation_id": "${operation_id}",
  "namespace": "${namespace}",
  "deployment": "${deployment}",
  "container": "${container_name}",
  "immutable_image_digest": "${image}"
}
EOF
  # Operator-owned snapshot acquisition: the operator binary reads the exact Deployment through
  # the administrator kubeconfig and signs the observed UID and resource version.
  "$KAPSEL_OPERATOR_BIN" provision-snapshot-grant \
    --authorization "$authorization" \
    --signing-seed "$workspace/authorization.seed" \
    --signing-key-id "$authorization_key_id" \
    --output "$workspace/grant-${operation_id}.bin" \
    --kubeconfig "$workspace/admin-kubeconfig.yaml"
  install_file_as_service_owner "$workspace/grant-${operation_id}.bin" /etc/kapsel/grant.bin
  printf '[agent-action] snapshot grant %s installed at %s\n' "$operation_id" "$(date -u +%H:%M:%S)"
}

command_client() {
  require_workspace
  docker exec --user "${caller_uid}:${callers_gid}" "${cluster_name}-service" \
    /usr/bin/kapsel-service-client "$@"
}

command_service_pid() {
  require_workspace
  docker exec --user 0 "${cluster_name}-service" \
    pgrep -f '/usr/libexec/kapsel/kapseld' | head -1
}

command_start_service() {
  require_workspace
  local pause=${1:-}
  local -a env_args=()
  if [[ $pause == after_apply || $pause == after_receipt_publish ]]; then
    docker exec --user 0 "${cluster_name}-service" mkdir -p /var/lib/kapsel/control
    docker exec --user 0 "${cluster_name}-service" \
      chown "${kapsel_uid}:${callers_gid}" /var/lib/kapsel/control
    docker exec --user 0 "${cluster_name}-service" chmod 0700 /var/lib/kapsel/control
    env_args=(-e "KAPSEL_DEMO_PAUSE=${pause}" -e "KAPSEL_DEMO_CONTROL_DIRECTORY=/var/lib/kapsel/control")
    printf '[agent-action] pause seam %s armed with control markers in /var/lib/kapsel/control\n' "$pause"
  fi
  docker exec -d "${env_args[@]}" --user "${kapsel_uid}:${callers_gid}" "${cluster_name}-service" \
    /usr/libexec/kapsel/kapseld \
    --operator-config /etc/kapsel/operator.json \
    --socket /run/kapsel/kapseld.sock
  sleep 1
  local pid
  pid=$(command_service_pid || true)
  [[ -n $pid ]] || fail "kapseld did not start"
  printf '[agent-action] kapseld running with pid %s\n' "$pid"
}

command_stop_service() {
  require_workspace
  local pid
  pid=$(command_service_pid || true)
  if [[ -n $pid ]]; then
    docker exec --user 0 "${cluster_name}-service" kill -9 "$pid"
    printf '[agent-action] kapseld pid %s received SIGKILL (process loss)\n' "$pid"
  else
    printf '[agent-action] kapseld is not running\n'
  fi
}

command_change_target() {
  require_workspace
  local mode=$1
  case $mode in
    modify)
      # An unrelated intervening write: bump a deployment annotation so the resourceVersion moves
      # while the object identity stays the same.
      kubectl_admin -n "$namespace" annotate deployment "$deployment" \
        "kapsel-experiment/invalidated-at=$(date -u +%s)" --overwrite >/dev/null
      ;;
    recreate)
      kubectl_admin -n "$namespace" delete deployment "$deployment" --wait now >/dev/null
      kubectl_admin -n "$namespace" create deployment "$deployment" --image "$initial_image" --replicas 1
      kubectl_admin -n "$namespace" patch deployment "$deployment" --type merge -p \
        '{"spec":{"minReadySeconds":60,"progressDeadlineSeconds":180,"template":{"spec":{"containers":[{"name":"'"$container_name"'","image":"'"$initial_image"'","imagePullPolicy":"IfNotPresent"}]}}}}' \
        >/dev/null
      ;;
    *) fail "change-target expects modify or recreate" ;;
  esac
  printf '[agent-action] target %s at %s\n' "$mode" "$(date -u +%H:%M:%S)"
}

command_inspect() {
  local operation_id=$1
  require_inputs
  require_workspace
  command_client receipt "$operation_id" "/tmp/receipt-${operation_id}.bin" >/dev/null
  docker cp "${cluster_name}-service:/tmp/receipt-${operation_id}.bin" \
    "$workspace/receipt-${operation_id}.bin" >/dev/null
  docker exec --user 0 "${cluster_name}-service" rm -f "/tmp/receipt-${operation_id}.bin"
  "$KAPSEL_OPERATOR_BIN" inspect \
    --receipt "$workspace/receipt-${operation_id}.bin" \
    --trust "$workspace/receipt-trust.bin" \
    --evaluation-time-unix-s "$(date +%s)"
}

command_down() {
  require_workspace
  cleanup
  trap - EXIT
  printf '[agent-action] environment removed\n'
}

main() {
  local command=${1:-}
  shift || true
  case $command in
    up) command_up ;;
    grant) command_grant "$@" ;;
    start-service) command_start_service "$@" ;;
    stop-service) command_stop_service ;;
    service-pid) command_service_pid ;;
    change-target) command_change_target "$@" ;;
    client) command_client "$@" ;;
    inspect) command_inspect "$@" ;;
    down) command_down ;;
    *) printf 'usage: %s {up|grant <operation-id> <image>|start-service [seam]|stop-service|service-pid|change-target <modify|recreate>|client ...|inspect <operation-id>|down}\n' "$0" >&2
      return 1 ;;
  esac
}

main "$@"
