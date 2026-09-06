//! Black-box contract tests for the fixed MCP stdio adapter.

#![allow(
    clippy::unwrap_used,
    reason = "controlled fixture failures must fail the end-to-end test immediately"
)]

use std::{
    fs,
    io::{Read as _, Write as _},
    net::TcpListener,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
};

use ed25519_dalek::SigningKey;
use kapsel::{provision_exact_grant, ExactAuthorization, GrantProvisioning};
use rusqlite::Connection;
use sha2::{Digest, Sha256};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);
const IMAGE: &str = concat!(
    "registry.example/agent-api@sha256:",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
);

struct Fixture {
    root: PathBuf,
    request: PathBuf,
    operator_config: PathBuf,
    server: Option<thread::JoinHandle<()>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn private_directory(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn private_file(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[derive(Clone, Copy)]
enum ReceiverPlan {
    Unavailable,
    DeploymentNotFound,
    ContainerNotFound,
    InvalidTarget,
    Succeeded,
    Failed,
    Unknown,
    TransientThenSucceeded,
}

fn fixture() -> Fixture {
    fixture_with_receiver(ReceiverPlan::Unavailable)
}

fn successful_fixture() -> Fixture {
    fixture_with_receiver(ReceiverPlan::Succeeded)
}

fn target_rejection_fixture(receiver_plan: ReceiverPlan) -> Fixture {
    fixture_with_receiver(receiver_plan)
}

fn transient_fixture() -> Fixture {
    fixture_with_receiver(ReceiverPlan::TransientThenSucceeded)
}

fn fixture_with_receiver(receiver_plan: ReceiverPlan) -> Fixture {
    let root = std::env::temp_dir().join(format!(
        "kapsel-e2e-mcp-{}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&root);
    private_directory(&root);
    let root = fs::canonicalize(root).unwrap();
    private_directory(&root.join("receipts"));

    let authorization_seed = [41_u8; 32];
    let authorization_key = SigningKey::from_bytes(&authorization_seed);
    let authorization = ExactAuthorization {
        approved_target: None,
        authorization_id: "mcp-auth-1".into(),
        operation_id: "mcp-op-1".into(),
        namespace: "demo".into(),
        deployment: "agent-api".into(),
        container: "api".into(),
        immutable_image_digest: IMAGE.into(),
    };
    let grant = provision_exact_grant(&GrantProvisioning {
        authorization: &authorization,
        signing_seed: &authorization_seed,
        signing_key_id: "mcp-authorization-key",
    })
    .unwrap();
    private_file(&root.join("grant.bin"), &grant);
    private_file(
        &root.join("authorization.pub"),
        &authorization_key.verifying_key().to_bytes(),
    );
    private_file(&root.join("receipt.seed"), &[42_u8; 32]);
    let (address, server) = match receiver_plan {
        ReceiverPlan::Unavailable => (String::from("127.0.0.1:9"), None),
        receiver_plan => {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = thread::spawn(move || serve_outcome(&listener, receiver_plan));
            (address.to_string(), Some(server))
        },
    };
    private_file(
        &root.join("kubeconfig.yaml"),
        format!(
            concat!(
                "apiVersion: v1\nkind: Config\nclusters:\n- name: fixture\n",
                "  cluster:\n    server: http://{address}\ncontexts:\n- name: fixture\n",
                "  context:\n    cluster: fixture\n    user: fixture\n",
                "current-context: fixture\nusers:\n- name: fixture\n  user: {{}}\n"
            ),
            address = address
        )
        .as_bytes(),
    );
    let request = root.join("request.json");
    private_file(
        &request,
        format!(
            concat!(
                "{{\"operation_id\":\"mcp-op-1\",\"namespace\":\"demo\",",
                "\"deployment\":\"agent-api\",\"container\":\"api\",",
                "\"immutable_image_digest\":\"{IMAGE}\"}}"
            ),
            IMAGE = IMAGE
        )
        .as_bytes(),
    );
    let operator_config = root.join("operator.json");
    private_file(
        &operator_config,
        format!(
            concat!(
                "{{\"signed_authorization_grant\":\"{}/grant.bin\",",
                "\"authorization_key_id\":\"mcp-authorization-key\",",
                "\"authorization_public_key\":\"{}/authorization.pub\",",
                "\"kubeconfig\":\"{}/kubeconfig.yaml\",",
                "\"journal\":\"{}/journal.sqlite3\",",
                "\"receipt_directory\":\"{}/receipts\",",
                "\"receipt_signing_seed\":\"{}/receipt.seed\",",
                "\"receipt_signing_key_id\":\"mcp-receipt-key\"}}"
            ),
            root.display(),
            root.display(),
            root.display(),
            root.display(),
            root.display(),
            root.display()
        )
        .as_bytes(),
    );
    Fixture {
        root,
        request,
        operator_config,
        server,
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the fixed target and receiver response plans stay visible together"
)]
fn serve_outcome(listener: &TcpListener, receiver_plan: ReceiverPlan) {
    if matches!(receiver_plan, ReceiverPlan::DeploymentNotFound) {
        serve_response(
            listener,
            "404 Not Found",
            &serde_json::json!({
                "apiVersion": "v1", "kind": "Status", "status": "Failure",
                "reason": "NotFound", "message": "SECRET_PROVIDER_CANARY", "code": 404
            })
            .to_string(),
        );
        return;
    }
    let old_image = concat!(
        "registry.example/agent-api@sha256:",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    if matches!(
        receiver_plan,
        ReceiverPlan::ContainerNotFound | ReceiverPlan::InvalidTarget
    ) {
        let containers = if matches!(receiver_plan, ReceiverPlan::ContainerNotFound) {
            serde_json::json!([{"name": "other", "image": old_image}])
        } else {
            serde_json::json!([{"name": "api", "image": old_image}])
        };
        let metadata = if matches!(receiver_plan, ReceiverPlan::InvalidTarget) {
            serde_json::json!({"name": "agent-api", "namespace": "demo", "generation": 1})
        } else {
            serde_json::json!({"name": "agent-api", "namespace": "demo", "uid": "uid-1",
                "resourceVersion": "1", "generation": 1})
        };
        serve_response(
            listener,
            "200 OK",
            &serde_json::json!({
                "apiVersion": "apps/v1", "kind": "Deployment", "metadata": metadata,
                "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "agent-api"}},
                    "template": {"metadata": {"labels": {"app": "agent-api"}},
                        "spec": {"containers": containers}}},
                "status": {"observedGeneration": 1}
            })
            .to_string(),
        );
        return;
    }
    if matches!(receiver_plan, ReceiverPlan::TransientThenSucceeded) {
        serve_response(
            listener,
            "500 Internal Server Error",
            &serde_json::json!({
                "apiVersion": "v1", "kind": "Status", "status": "Failure",
                "reason": "InternalError", "message": "SECRET_TRANSIENT_CANARY", "code": 500
            })
            .to_string(),
        );
    }
    let failed = matches!(receiver_plan, ReceiverPlan::Failed);
    let responses = [
        serde_json::json!({
            "apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": "agent-api", "namespace": "demo", "uid": "uid-1",
                "resourceVersion": "1", "generation": 1},
            "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "agent-api"}},
                "template": {"metadata": {"labels": {"app": "agent-api"}},
                    "spec": {"containers": [{"name": "api", "image": old_image}]}}},
            "status": {"observedGeneration": 1}
        }),
        serde_json::json!({
            "apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": "agent-api", "namespace": "demo", "uid": "uid-1",
                "resourceVersion": "2", "generation": 2},
            "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "agent-api"}},
                "template": {"metadata": {"labels": {"app": "agent-api"}},
                    "spec": {"containers": [{"name": "api", "image": IMAGE}]}}}
        }),
        serde_json::json!({
            "apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": "agent-api", "namespace": "demo",
                "uid": if matches!(receiver_plan, ReceiverPlan::Unknown) {
                    "other-uid"
                } else {
                    "uid-1"
                },
                "resourceVersion": "3", "generation": 2,
                "annotations": {"kapsel.dev/kap0038-operation-id": "mcp-op-1"}},
            "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "agent-api"}},
                "template": {"metadata": {"labels": {"app": "agent-api"}},
                    "spec": {"containers": [{"name": "api", "image": IMAGE}]}}},
            "status": {"observedGeneration": 2,
                "updatedReplicas": i32::from(!failed),
                "availableReplicas": i32::from(!failed),
                "unavailableReplicas": i32::from(failed),
                "conditions": [if failed {
                    serde_json::json!({"type": "Progressing", "status": "False",
                        "reason": "ProgressDeadlineExceeded"})
                } else {
                    serde_json::json!({"type": "Available", "status": "True",
                        "reason": "MinimumReplicasAvailable"})
                }]}
        }),
    ];
    for body in responses.map(|value| value.to_string()) {
        serve_response(listener, "200 OK", &body);
    }
}

fn serve_response(listener: &TcpListener, status: &str, body: &str) {
    let (mut stream, _) = listener.accept().unwrap();
    let mut request = [0_u8; 4096];
    let _ = stream.read(&mut request).unwrap();
    write!(
        stream,
        concat!(
            "HTTP/1.1 {}\r\ncontent-type: application/json\r\n",
            "content-length: {}\r\nconnection: close\r\n\r\n"
        ),
        status,
        body.len()
    )
    .unwrap();
    stream.write_all(body.as_bytes()).unwrap();
}

fn run_session(fixture: &Fixture, messages: &[serde_json::Value]) -> Vec<serde_json::Value> {
    let mut child = spawn_mcp(fixture);
    let mut input = child.stdin.take().unwrap();
    for message in messages {
        serde_json::to_writer(&mut input, message).unwrap();
        input.write_all(b"\n").unwrap();
    }
    drop(input);
    let output = child.wait_with_output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert!(output
        .stdout
        .split_inclusive(|byte| *byte == b'\n')
        .all(|line| line.len() <= 8 * 1024));
    parse_responses(&output.stdout)
}

fn spawn_mcp(fixture: &Fixture) -> std::process::Child {
    Command::new(env!("CARGO_BIN_EXE_kapsel"))
        .args([
            "mcp",
            "--operator-config",
            fixture.operator_config.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn run_raw_session(fixture: &Fixture, bytes: &[u8]) -> std::process::Output {
    let mut child = spawn_mcp(fixture);
    let mut input = child.stdin.take().unwrap();
    input.write_all(bytes).unwrap();
    drop(input);
    child.wait_with_output().unwrap()
}

fn parse_responses(bytes: &[u8]) -> Vec<serde_json::Value> {
    String::from_utf8(bytes.to_vec())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn operation_messages() -> [serde_json::Value; 3] {
    [
        serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                "clientInfo": {"name": "test", "version": "1"}}
        }),
        serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "kubernetes.set_deployment_image", "arguments": {
                "operation_id": "mcp-op-1", "namespace": "demo",
                "deployment": "agent-api", "container": "api",
                "immutable_image_digest": IMAGE
            }}
        }),
    ]
}

fn mcp_operation(fixture: &Fixture) -> serde_json::Value {
    let responses = run_session(fixture, &operation_messages());
    assert_eq!(responses.len(), 2);
    responses[1].clone()
}

fn local_operation(fixture: &Fixture) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_kapsel"))
        .args([
            "operate",
            "--request",
            fixture.request.to_str().unwrap(),
            "--operator-config",
            fixture.operator_config.to_str().unwrap(),
        ])
        .output()
        .unwrap()
}

fn tool_report(response: &serde_json::Value) -> serde_json::Value {
    serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").unwrap();
    }
    output
}

#[test]
fn initialization_lists_exactly_the_fixed_request_only_tool() {
    let fixture = fixture();
    let responses = run_session(
        &fixture,
        &[
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": "initialize-1",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "kapsel-test", "version": "1"}
                }
            }),
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized"
            }),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {}
            }),
        ],
    );

    assert_eq!(responses.len(), 2);
    assert_eq!(
        responses[0],
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": "initialize-1",
            "result": {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "kapsel", "version": "0.2.0"}
            }
        })
    );
    let tools = responses[1]["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 1);
    assert_eq!(
        tools[0],
        serde_json::json!({
            "name": "kubernetes.set_deployment_image",
            "description": "Request one authorized immutable Kubernetes Deployment image change.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "operation_id": {
                        "type": "string", "minLength": 1, "maxLength": 128,
                        "pattern": "^[A-Za-z0-9._:-]+$"
                    },
                    "namespace": {
                        "type": "string", "minLength": 1, "maxLength": 63,
                        "pattern": "^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$"
                    },
                    "deployment": {"type": "string", "minLength": 1, "maxLength": 253},
                    "container": {
                        "type": "string", "minLength": 1, "maxLength": 63,
                        "pattern": "^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$"
                    },
                    "immutable_image_digest": {
                        "type": "string", "minLength": 1, "maxLength": 512
                    }
                },
                "required": [
                    "operation_id", "namespace", "deployment", "container",
                    "immutable_image_digest"
                ],
                "additionalProperties": false
            }
        })
    );
}

#[test]
fn lifecycle_and_dispatch_errors_remain_bounded() {
    let fixture = fixture();
    let responses = run_session(
        &fixture,
        &[
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
            serde_json::json!({
                "jsonrpc": "2.0", "id": "init", "method": "initialize",
                "params": {"protocolVersion": "1900-01-01", "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1"}}
            }),
            serde_json::json!({
                "jsonrpc": "2.0", "id": 2, "method": "initialize",
                "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1"}}
            }),
            serde_json::json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}),
            serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            serde_json::json!({"jsonrpc": "2.0", "id": 4, "method": "resources/list"}),
            serde_json::json!({
                "jsonrpc": "2.0", "id": 5, "method": "tools/call",
                "params": {"name": "second.tool", "arguments": {}}
            }),
            serde_json::json!({
                "jsonrpc": "2.0", "id": 6, "method": "tools/call",
                "params": {"name": "kubernetes.set_deployment_image",
                    "arguments": {"operation_id": 7}}
            }),
            serde_json::json!({
                "jsonrpc": "2.0", "method": "notifications/cancelled",
                "params": {"requestId": 999, "reason": "SECRET_CANCEL_CANARY"}
            }),
            serde_json::json!({"jsonrpc": "2.0", "method": "tools/list"}),
            serde_json::json!({
                "jsonrpc": "2.0", "method": "tools/call",
                "params": {"name": "kubernetes.set_deployment_image", "arguments": {}}
            }),
            serde_json::json!({"jsonrpc": "2.0", "id": null, "method": "tools/list"}),
            serde_json::json!({"jsonrpc": "2.0", "id": true, "method": "tools/list"}),
            serde_json::json!({
                "jsonrpc": "2.0", "id": "x".repeat(129), "method": "tools/list"
            }),
            serde_json::json!({"jsonrpc": "2.0", "id": "list", "method": "tools/list"}),
        ],
    );

    assert_eq!(responses.len(), 11);
    assert_eq!(responses[0]["error"]["code"], -32600);
    assert_eq!(responses[1]["id"], "init");
    assert_eq!(responses[1]["result"]["protocolVersion"], "2025-11-25");
    assert_eq!(responses[2]["error"]["code"], -32600);
    assert_eq!(responses[3]["error"]["code"], -32600);
    assert_eq!(responses[4]["error"]["code"], -32601);
    assert_eq!(responses[5]["error"]["code"], -32602);
    assert_eq!(responses[6]["error"]["code"], -32602);
    assert_eq!(responses[7]["error"]["code"], -32600);
    assert_eq!(responses[7]["id"], serde_json::Value::Null);
    assert_eq!(responses[8]["error"]["code"], -32600);
    assert_eq!(responses[8]["id"], serde_json::Value::Null);
    assert_eq!(responses[9]["error"]["code"], -32600);
    assert_eq!(responses[9]["id"], serde_json::Value::Null);
    assert_eq!(responses[10]["id"], "list");
    let serialized = serde_json::to_vec(&responses).unwrap();
    assert!(!serialized
        .windows(b"SECRET_CANCEL_CANARY".len())
        .any(|window| window == b"SECRET_CANCEL_CANARY"));
    assert!(serialized.len() < 8 * 1024);
}

#[test]
fn mutable_image_and_exact_grant_mismatch_are_request_rejections() {
    let fixture = fixture();
    let call = |id: u64, container: &str, image: &str| {
        serde_json::json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {"name": "kubernetes.set_deployment_image", "arguments": {
                "operation_id": "mcp-op-1", "namespace": "demo",
                "deployment": "agent-api", "container": container,
                "immutable_image_digest": image
            }}
        })
    };
    let responses = run_session(
        &fixture,
        &[
            serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1"}}
            }),
            serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            call(2, "api", "registry.example/agent-api:latest"),
            call(3, "other", IMAGE),
        ],
    );
    for response in &responses[1..] {
        assert_eq!(response["result"]["isError"], true);
        assert_eq!(
            response["result"]["content"][0]["text"],
            r#"{"status":"ERROR","error_class":"request_rejected"}"#
        );
    }
    private_file(
        &fixture.request,
        format!(
            concat!(
                "{{\"operation_id\":\"mcp-op-1\",\"namespace\":\"demo\",",
                "\"deployment\":\"agent-api\",\"container\":\"other\",",
                "\"immutable_image_digest\":\"{IMAGE}\"}}"
            ),
            IMAGE = IMAGE
        )
        .as_bytes(),
    );
    let local = local_operation(&fixture);
    assert_eq!(local.status.code(), Some(2));
    let local_failure: serde_json::Value = serde_json::from_slice(&local.stdout).unwrap();
    assert_eq!(local_failure["error_class"], "command_input");
    assert_eq!(
        fs::read_dir(fixture.root.join("receipts")).unwrap().count(),
        0
    );
}

#[test]
fn application_outcomes_preserve_domain_parity_across_cli_and_mcp() {
    for (plan, expected_state, expected_result, expected_rejection) in [
        (
            ReceiverPlan::DeploymentNotFound,
            "NOT_ATTEMPTED",
            None,
            Some("DEPLOYMENT_NOT_FOUND"),
        ),
        (
            ReceiverPlan::ContainerNotFound,
            "NOT_ATTEMPTED",
            None,
            Some("CONTAINER_NOT_FOUND"),
        ),
        (
            ReceiverPlan::InvalidTarget,
            "NOT_ATTEMPTED",
            None,
            Some("INVALID_TARGET"),
        ),
        (
            ReceiverPlan::Succeeded,
            "FINALIZED",
            Some("SUCCEEDED"),
            None,
        ),
        (ReceiverPlan::Failed, "FINALIZED", Some("FAILED"), None),
        (ReceiverPlan::Unknown, "FINALIZED", Some("UNKNOWN"), None),
    ] {
        let mut fixture = target_rejection_fixture(plan);
        let response = mcp_operation(&fixture);
        assert_eq!(response["result"]["isError"], false);
        let report = tool_report(&response);
        assert_eq!(report["state"], expected_state);
        assert_eq!(
            report["result"],
            expected_result.map_or(serde_json::Value::Null, serde_json::Value::from)
        );
        assert_eq!(
            report["target_rejection"],
            expected_rejection.map_or(serde_json::Value::Null, serde_json::Value::from)
        );
        fixture.server.take().unwrap().join().unwrap();

        let local = local_operation(&fixture);
        assert_eq!(local.status.code(), Some(0));
        let local_report: serde_json::Value = serde_json::from_slice(&local.stdout).unwrap();
        for field in [
            "operation_id",
            "state",
            "result",
            "target_rejection",
            "receipt_file",
            "receipt_sha256",
        ] {
            assert_eq!(report[field], local_report[field], "field {field}");
        }

        if expected_state == "NOT_ATTEMPTED" {
            assert_eq!(report["receipt_file"], serde_json::Value::Null);
            assert_eq!(report["receipt_sha256"], serde_json::Value::Null);
            assert_eq!(
                fs::read_dir(fixture.root.join("receipts")).unwrap().count(),
                0
            );
        } else {
            let receipt_file = report["receipt_file"].as_str().unwrap();
            let receipt = fs::read(fixture.root.join("receipts").join(receipt_file)).unwrap();
            let digest = sha256_hex(&receipt);
            assert_eq!(report["receipt_sha256"], digest);
            assert!(receipt_file.ends_with(&format!("-{digest}.receipt")));
        }
    }
}

#[test]
fn operation_failure_and_restart_preserve_cli_mcp_parity() {
    let mut fixture = transient_fixture();
    let failed = mcp_operation(&fixture);
    assert_eq!(failed["result"]["isError"], true);
    assert_eq!(
        failed["result"]["content"][0]["text"],
        r#"{"status":"ERROR","error_class":"operation_failure"}"#
    );
    let recovered = mcp_operation(&fixture);
    assert_eq!(recovered["result"]["isError"], false);
    let recovered_report = tool_report(&recovered);
    assert_eq!(recovered_report["result"], "SUCCEEDED");
    fixture.server.take().unwrap().join().unwrap();
    let local_replay = local_operation(&fixture);
    assert_eq!(local_replay.status.code(), Some(0));
    let local_report: serde_json::Value = serde_json::from_slice(&local_replay.stdout).unwrap();
    for field in [
        "operation_id",
        "state",
        "result",
        "target_rejection",
        "receipt_file",
        "receipt_sha256",
    ] {
        assert_eq!(
            recovered_report[field], local_report[field],
            "field {field}"
        );
    }

    let mut fixture = transient_fixture();
    let failed = local_operation(&fixture);
    assert_eq!(failed.status.code(), Some(4));
    let failure: serde_json::Value = serde_json::from_slice(&failed.stdout).unwrap();
    assert_eq!(failure["error_class"], "operation_failure");
    let recovered = mcp_operation(&fixture);
    assert_eq!(recovered["result"]["isError"], false);
    assert_eq!(tool_report(&recovered)["result"], "SUCCEEDED");
    fixture.server.take().unwrap().join().unwrap();
}

#[test]
fn clean_eof_opens_and_reopens_the_journal_without_lifecycle_work() {
    let fixture = fixture();
    for _ in 0..2 {
        let output = run_raw_session(&fixture, b"");
        assert_eq!(output.status.code(), Some(0));
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
    let connection = Connection::open(fixture.root.join("journal.sqlite3")).unwrap();
    assert_eq!(
        connection
            .query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))
            .unwrap(),
        3
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM kubernetes_image_operations",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
}

#[test]
fn untrusted_operator_configuration_exits_before_protocol_traffic() {
    let fixture = fixture();
    private_file(&fixture.root.join("authorization.pub"), &[99_u8; 32]);
    let child = spawn_mcp(&fixture);
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    assert_eq!(
        output.stderr,
        b"Kapsel command failure: operator_configuration\n"
    );
    assert!(output.stderr.len() < 4096);
    for canary in [
        b"grant.bin".as_slice(),
        b"authorization.pub",
        b"receipt.seed",
    ] {
        assert!(!output
            .stderr
            .windows(canary.len())
            .any(|window| window == canary));
    }
    let local = local_operation(&fixture);
    assert_eq!(local.status.code(), Some(3));
    let failure: serde_json::Value = serde_json::from_slice(&local.stdout).unwrap();
    assert_eq!(failure["error_class"], "operator_configuration");
}

#[test]
fn duplicate_and_oversized_frames_fail_without_disclosure() {
    let fixture = fixture();
    let output = run_raw_session(
        &fixture,
        concat!(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"#,
            r#""protocolVersion":"2025-11-25","#,
            r#""protocolVersion":"SECRET_DUPLICATE_CANARY","capabilities":{},"#,
            r#""clientInfo":{"name":"test","version":"1"}}}"#,
            "\n"
        )
        .as_bytes(),
    );
    assert_eq!(output.status.code(), Some(0));
    let responses = parse_responses(&output.stdout);
    assert_eq!(responses[0]["error"]["code"], -32700);
    assert!(!output
        .stdout
        .windows(b"SECRET_DUPLICATE_CANARY".len())
        .any(|window| window == b"SECRET_DUPLICATE_CANARY"));

    let output = run_raw_session(
        &fixture,
        concat!(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"#,
            r#""protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"#,
            r#""name":"test","name":"SECRET_NESTED_CANARY","version":"1"}}}"#,
            "\n"
        )
        .as_bytes(),
    );
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(parse_responses(&output.stdout)[0]["error"]["code"], -32700);
    assert!(!output
        .stdout
        .windows(b"SECRET_NESTED_CANARY".len())
        .any(|window| window == b"SECRET_NESTED_CANARY"));

    let output = run_raw_session(&fixture, &vec![b'x'; 16 * 1024 + 1]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.len() < 4096);
}

#[test]
fn framing_boundaries_reject_incomplete_utf8_and_batch_input() {
    let fixture = fixture();

    let output = run_raw_session(&fixture, &[0xff, b'\n']);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(parse_responses(&output.stdout)[0]["error"]["code"], -32700);

    let output = run_raw_session(&fixture, b"[]\n");
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(parse_responses(&output.stdout)[0]["error"]["code"], -32600);

    let output = run_raw_session(&fixture, br#"{"jsonrpc":"2.0"}"#);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());

    let initialize = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"#,
        r#""protocolVersion":"2025-11-25","capabilities":{},"#,
        r#""clientInfo":{"name":"test","version":"1"}}}"#
    );
    let mut exact_frame = initialize.as_bytes().to_vec();
    exact_frame.resize(16 * 1024 - 1, b' ');
    exact_frame.push(b'\n');
    let output = run_raw_session(&fixture, &exact_frame);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(parse_responses(&output.stdout)[0]["id"], 1);

    let maximum_id = "i".repeat(128);
    let maximum_id_frame = serde_json::json!({
        "jsonrpc": "2.0",
        "id": maximum_id,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1"}
        }
    })
    .to_string()
        + "\n";
    let output = run_raw_session(&fixture, maximum_id_frame.as_bytes());
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(parse_responses(&output.stdout)[0]["id"], maximum_id);
    assert!(output.stdout.len() <= 8 * 1024);

    let oversized_id = "i".repeat(129);
    let oversized_id_frame = serde_json::json!({
        "jsonrpc": "2.0",
        "id": oversized_id,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1"}
        }
    })
    .to_string()
        + "\n";
    let output = run_raw_session(&fixture, oversized_id_frame.as_bytes());
    assert_eq!(output.status.code(), Some(0));
    let response = &parse_responses(&output.stdout)[0];
    assert_eq!(response["id"], serde_json::Value::Null);
    assert_eq!(response["error"]["code"], -32600);
}

#[test]
fn tool_call_matches_the_local_request_and_typed_outcome() {
    let mut fixture = successful_fixture();
    let responses = run_session(
        &fixture,
        &[
            serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                    "clientInfo": {"name": "kapsel-test", "version": "1"}}
            }),
            serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            serde_json::json!({
                "jsonrpc": "2.0", "id": "call-1", "method": "tools/call",
                "params": {
                    "name": "kubernetes.set_deployment_image",
                    "_meta": {"progressToken": "ignored-but-valid"},
                    "arguments": {
                        "operation_id": "mcp-op-1", "namespace": "demo",
                        "deployment": "agent-api", "container": "api",
                        "immutable_image_digest": IMAGE
                    }
                }
            }),
            serde_json::json!({
                "jsonrpc": "2.0", "id": "call-2", "method": "tools/call",
                "params": {
                    "name": "kubernetes.set_deployment_image",
                    "arguments": {
                        "operation_id": "mcp-op-1", "namespace": "demo",
                        "deployment": "agent-api", "container": "api",
                        "immutable_image_digest": IMAGE
                    }
                }
            }),
        ],
    );
    assert_eq!(responses.len(), 3);
    assert_eq!(responses[1]["id"], "call-1");
    assert_eq!(responses[1]["result"]["isError"], false);
    let report: serde_json::Value = serde_json::from_str(
        responses[1]["result"]["content"][0]["text"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(report["operation_id"], "mcp-op-1");
    assert_eq!(report["state"], "FINALIZED");
    assert_eq!(report["result"], "SUCCEEDED");
    assert_eq!(report["target_rejection"], serde_json::Value::Null);
    assert_eq!(responses[2]["id"], "call-2");
    assert_eq!(
        responses[2]["result"]["content"][0]["text"],
        responses[1]["result"]["content"][0]["text"]
    );
    fixture.server.take().unwrap().join().unwrap();

    let local = Command::new(env!("CARGO_BIN_EXE_kapsel"))
        .args([
            "operate",
            "--request",
            fixture.request.to_str().unwrap(),
            "--operator-config",
            fixture.operator_config.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(local.status.code(), Some(0));
    let local_report: serde_json::Value = serde_json::from_slice(&local.stdout).unwrap();
    for field in [
        "operation_id",
        "state",
        "result",
        "target_rejection",
        "receipt_file",
        "receipt_sha256",
    ] {
        assert_eq!(report[field], local_report[field], "field {field}");
    }
}
