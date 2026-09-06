//! Black-box contract tests for the production operation command.

#![allow(
    clippy::unwrap_used,
    reason = "controlled fixture failures must fail the end-to-end test immediately"
)]

use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
    thread,
};

use ed25519_dalek::SigningKey;
use kapsel::{provision_exact_grant, ExactAuthorization, GrantProvisioning};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);
const IMAGE: &str = concat!(
    "registry.example/agent-api@sha256:",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
);

struct Fixture {
    root: PathBuf,
    request: PathBuf,
    operator_config: PathBuf,
    server_address: SocketAddr,
    server: Option<thread::JoinHandle<()>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            for _ in 0..4 {
                let _ = TcpStream::connect(self.server_address);
            }
            let _ = server.join();
        }
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

fn fixture() -> Fixture {
    fixture_with_receiver(false)
}

fn successful_fixture() -> Fixture {
    fixture_with_receiver(true)
}

fn recoverable_fixture() -> Fixture {
    fixture_with_plan(true, true)
}

fn fixture_with_receiver(successful: bool) -> Fixture {
    fixture_with_plan(successful, false)
}

#[allow(
    clippy::too_many_lines,
    clippy::useless_concat,
    reason = "split literals keep the black-box fixture within repository line limits"
)]
fn fixture_with_plan(successful: bool, transient_first: bool) -> Fixture {
    let root = std::env::temp_dir().join(format!(
        "kapsel-e2e-operation-{}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&root);
    private_directory(&root);
    let root = fs::canonicalize(root).unwrap();
    private_directory(&root.join("receipts"));

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let mut responses = if successful {
            let old_image = concat!(
                "registry.example/agent-api@sha256:",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            );
            vec![
                format!(
                    concat!(
                        "{{\"apiVersion\":\"apps/v1\",\"kind\":\"Deployment\",",
                        "\"metadata\":{{\"name\":\"agent-api\",\"namespace\":\"demo\",",
                        "\"uid\":\"uid-1\",\"resourceVersion\":\"1\",\"generation\":1}},",
                        "\"spec\":{{\"replicas\":1,\"selector\":{{\"matchLabels\":{{",
                        "\"app\":\"agent-api\"}}}},\"template\":{{\"metadata\":{{\"labels\":{{",
                        "\"app\":\"agent-api\"}}}},\"spec\":{{\"containers\":[{{",
                        "\"name\":\"api\",\"image\":\"{old_image}\"}}]}}}}}},",
                        "\"status\":{{\"observedGeneration\":1}}}}"
                    ),
                    old_image = old_image
                ),
                format!(
                    concat!(
                        "{{\"apiVersion\":\"apps/v1\",\"kind\":\"Deployment\",",
                        "\"metadata\":{{\"name\":\"agent-api\",\"namespace\":\"demo\",",
                        "\"uid\":\"uid-1\",\"resourceVersion\":\"2\",\"generation\":2}},",
                        "\"spec\":{{\"replicas\":1,\"selector\":{{\"matchLabels\":{{",
                        "\"app\":\"agent-api\"}}}},\"template\":{{\"metadata\":{{\"labels\":{{",
                        "\"app\":\"agent-api\"}}}},\"spec\":{{\"containers\":[{{",
                        "\"name\":\"api\",\"image\":\"{IMAGE}\"}}]}}}}}}}}"
                    ),
                    IMAGE = IMAGE
                ),
                format!(
                    concat!(
                        "{{\"apiVersion\":\"apps/v1\",\"kind\":\"Deployment\",",
                        "\"metadata\":{{\"name\":\"agent-api\",\"namespace\":\"demo\",",
                        "\"uid\":\"uid-1\",\"resourceVersion\":\"3\",\"generation\":2,",
                        "\"annotations\":{{\"kapsel.dev/kap0038-operation-id\":",
                        "\"command-op-1\",\"provider\":\"SECRET_PROVIDER_CANARY\"}}}},",
                        "\"spec\":{{\"replicas\":1,\"selector\":{{\"matchLabels\":{{",
                        "\"app\":\"agent-api\"}}}},\"template\":{{\"metadata\":{{\"labels\":{{",
                        "\"app\":\"agent-api\"}}}},\"spec\":{{\"containers\":[{{",
                        "\"name\":\"api\",\"image\":\"{IMAGE}\"}}]}}}}}},",
                        "\"status\":{{\"observedGeneration\":2,\"updatedReplicas\":1,",
                        "\"availableReplicas\":1,\"unavailableReplicas\":0,\"conditions\":[{{",
                        "\"type\":\"Available\",\"status\":\"True\",",
                        "\"reason\":\"MinimumReplicasAvailable\"}}]}}}}"
                    ),
                    IMAGE = IMAGE
                ),
            ]
        } else {
            vec![serde_json::json!({
                "apiVersion": "v1",
                "kind": "Status",
                "status": "Failure",
                "reason": "NotFound",
                "message": "SECRET_PROVIDER_CANARY",
                "code": 404
            })
            .to_string()]
        };
        if transient_first {
            responses.insert(
                0,
                serde_json::json!({
                    "apiVersion": "v1",
                    "kind": "Status",
                    "status": "Failure",
                    "reason": "InternalError",
                    "code": 500
                })
                .to_string(),
            );
        }
        for (index, body) in responses.into_iter().enumerate() {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request);
            let status = if transient_first && index == 0 {
                "500 Internal Server Error"
            } else if successful {
                "200 OK"
            } else {
                "404 Not Found"
            };
            if write!(
                stream,
                concat!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\n",
                    "content-length: {}\r\nconnection: close\r\n\r\n"
                ),
                body.len(),
                status = status
            )
            .is_err()
                || stream.write_all(body.as_bytes()).is_err()
            {
                break;
            }
        }
    });

    let authorization_seed = [41_u8; 32];
    let authorization_key = SigningKey::from_bytes(&authorization_seed);
    let authorization = ExactAuthorization {
        approved_target: None,
        authorization_id: "command-auth-1".into(),
        operation_id: "command-op-1".into(),
        namespace: "demo".into(),
        deployment: "agent-api".into(),
        container: "api".into(),
        immutable_image_digest: IMAGE.into(),
    };
    let grant = provision_exact_grant(&GrantProvisioning {
        authorization: &authorization,
        signing_seed: &authorization_seed,
        signing_key_id: "command-authorization-key",
    })
    .unwrap();
    private_file(&root.join("grant.bin"), &grant);
    private_file(
        &root.join("authorization.pub"),
        &authorization_key.verifying_key().to_bytes(),
    );
    private_file(&root.join("receipt.seed"), &[42_u8; 32]);
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
                "{{\"operation_id\":\"command-op-1\",\"namespace\":\"demo\",",
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
                "\"authorization_key_id\":\"command-authorization-key\",",
                "\"authorization_public_key\":\"{}/authorization.pub\",",
                "\"kubeconfig\":\"{}/kubeconfig.yaml\",",
                "\"journal\":\"{}/journal.sqlite3\",",
                "\"receipt_directory\":\"{}/receipts\",",
                "\"receipt_signing_seed\":\"{}/receipt.seed\",",
                "\"receipt_signing_key_id\":\"command-receipt-key\"}}"
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
        server_address: address,
        server: Some(server),
    }
}

#[test]
fn exact_request_uses_separately_supplied_operator_configuration() {
    let mut fixture = fixture();
    let output = Command::new(env!("CARGO_BIN_EXE_kapsel"))
        .args([
            "operate",
            "--request",
            fixture.request.to_str().unwrap(),
            "--operator-config",
            fixture.operator_config.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        concat!(
            "{\"command\":\"operate\",\"operation_id\":\"command-op-1\",",
            "\"state\":\"NOT_ATTEMPTED\",\"result\":null,",
            "\"target_rejection\":\"DEPLOYMENT_NOT_FOUND\",",
            "\"receipt_file\":null,\"receipt_sha256\":null,",
            "\"approved_target\":null,\"attempt_target\":null,",
            "\"observed_target\":null}\n"
        )
    );
    assert!(output.stderr.is_empty());
    assert!(!fs::read(fixture.root.join("journal.sqlite3"))
        .unwrap()
        .windows(b"SECRET_PROVIDER_CANARY".len())
        .any(|window| window == b"SECRET_PROVIDER_CANARY"));
    fixture.server.take().unwrap().join().unwrap();

    let restarted = Command::new(env!("CARGO_BIN_EXE_kapsel"))
        .args([
            "operate",
            "--request",
            fixture.request.to_str().unwrap(),
            "--operator-config",
            fixture.operator_config.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(restarted.status.code(), Some(0));
    assert!(String::from_utf8(restarted.stdout)
        .unwrap()
        .contains("\"state\":\"NOT_ATTEMPTED\""));
    assert_unrelated_grant_cannot_replace_journal_authority(&fixture);
}

/// A different grant must not adopt the durable operation's original authority.
fn assert_unrelated_grant_cannot_replace_journal_authority(fixture: &Fixture) {
    let mut unrelated = fixture_with_receiver(false);
    let unrelated_authorization = ExactAuthorization {
        approved_target: None,
        authorization_id: "unrelated-auth".into(),
        operation_id: "unrelated-op".into(),
        namespace: "demo".into(),
        deployment: "agent-api".into(),
        container: "api".into(),
        immutable_image_digest: IMAGE.into(),
    };
    let unrelated_grant = provision_exact_grant(&GrantProvisioning {
        authorization: &unrelated_authorization,
        signing_seed: &[41_u8; 32],
        signing_key_id: "command-authorization-key",
    })
    .unwrap();
    private_file(&unrelated.root.join("grant.bin"), &unrelated_grant);
    let unrelated_request = fs::read_to_string(&unrelated.request)
        .unwrap()
        .replace("command-op-1", "unrelated-op");
    private_file(&unrelated.request, unrelated_request.as_bytes());
    let unrelated_config = fs::read_to_string(&unrelated.operator_config)
        .unwrap()
        .replace(
            unrelated.root.join("journal.sqlite3").to_str().unwrap(),
            fixture.root.join("journal.sqlite3").to_str().unwrap(),
        );
    private_file(&unrelated.operator_config, unrelated_config.as_bytes());
    let unrelated_output = Command::new(env!("CARGO_BIN_EXE_kapsel"))
        .args([
            "operate",
            "--request",
            unrelated.request.to_str().unwrap(),
            "--operator-config",
            unrelated.operator_config.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(unrelated_output.status.code(), Some(0));
    unrelated.server.take().unwrap().join().unwrap();

    let selected = Command::new(env!("CARGO_BIN_EXE_kapsel"))
        .args([
            "operate",
            "--request",
            fixture.request.to_str().unwrap(),
            "--operator-config",
            fixture.operator_config.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let selected_stdout = String::from_utf8(selected.stdout).unwrap();
    assert!(selected_stdout.contains("\"operation_id\":\"command-op-1\""));
    assert!(!selected_stdout.contains("unrelated-op"));
}

#[test]
fn ordinary_restart_resumes_an_eligible_authorized_operation() {
    let mut fixture = recoverable_fixture();
    let run = || {
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
    };

    let first = run();
    assert_eq!(
        first.status.code(),
        Some(4),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(String::from_utf8(first.stdout)
        .unwrap()
        .contains("\"error_class\":\"operation_failure\""));
    let restarted = run();
    assert_eq!(restarted.status.code(), Some(0));
    assert!(String::from_utf8(restarted.stdout)
        .unwrap()
        .contains("\"state\":\"FINALIZED\""));
    fixture.server.take().unwrap().join().unwrap();
}

#[test]
fn valid_operation_mutates_and_publishes_a_secret_free_receipt() {
    let mut fixture = successful_fixture();
    let output = Command::new(env!("CARGO_BIN_EXE_kapsel"))
        .env("HTTPS_PROXY", "http://[")
        .args([
            "operate",
            "--request",
            fixture.request.to_str().unwrap(),
            "--operator-config",
            fixture.operator_config.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("\"state\":\"FINALIZED\""));
    assert!(stdout.contains("\"result\":\"SUCCEEDED\""));
    assert!(!stdout.contains("SECRET_PROVIDER_CANARY"));
    let receipts: Vec<_> = fs::read_dir(fixture.root.join("receipts"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(receipts.len(), 1);
    for bytes in [
        fs::read(fixture.root.join("journal.sqlite3")).unwrap(),
        fs::read(&receipts[0]).unwrap(),
    ] {
        assert!(!bytes
            .windows(b"SECRET_PROVIDER_CANARY".len())
            .any(|window| window == b"SECRET_PROVIDER_CANARY"));
    }
    fixture.server.take().unwrap().join().unwrap();
}

#[test]
fn command_grammar_rejects_unknown_duplicate_missing_positional_and_non_utf8_input() {
    use std::os::unix::ffi::OsStringExt as _;

    let cases = [
        vec![],
        vec![std::ffi::OsString::from("unknown")],
        vec![
            "inspect".into(),
            "--receipt".into(),
            "one".into(),
            "--receipt".into(),
            "two".into(),
        ],
        vec!["inspect".into(), "--receipt".into()],
        vec!["inspect".into(), "positional".into()],
        vec![std::ffi::OsString::from_vec(vec![0xff])],
    ];
    for arguments in cases {
        let output = Command::new(env!("CARGO_BIN_EXE_kapsel"))
            .args(arguments)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.len() < 4096);
        assert!(output.stderr.len() < 4096);
        for canary in [b"positional".as_slice(), &[0xff]] {
            assert!(!output
                .stdout
                .windows(canary.len())
                .any(|window| window == canary));
            assert!(!output
                .stderr
                .windows(canary.len())
                .any(|window| window == canary));
        }
    }
}

#[test]
fn request_json_rejects_duplicate_unknown_missing_wrong_type_trailing_and_oversized_shapes() {
    let canonical = format!(
        concat!(
            "{{\"operation_id\":\"command-op-1\",\"namespace\":\"demo\",",
            "\"deployment\":\"agent-api\",\"container\":\"api\",",
            "\"immutable_image_digest\":\"{IMAGE}\"}}"
        ),
        IMAGE = IMAGE
    );
    let cases = [
        canonical.replace(
            "\"operation_id\":\"command-op-1\"",
            "\"operation_id\":\"command-op-1\",\"operation_id\":\"duplicate\"",
        ),
        canonical.replace(
            "\"namespace\":\"demo\"",
            "\"namespace\":\"demo\",\"unknown\":\"value\"",
        ),
        canonical.replace("\"namespace\":\"demo\",", ""),
        canonical.replace("\"container\":\"api\"", "\"container\":1"),
        format!("{canonical}\n{{}}"),
    ];
    for bytes in cases {
        let fixture = fixture();
        private_file(&fixture.request, bytes.as_bytes());
        let output = Command::new(env!("CARGO_BIN_EXE_kapsel"))
            .args([
                "operate",
                "--request",
                fixture.request.to_str().unwrap(),
                "--operator-config",
                fixture.operator_config.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.len() < 4096);
        assert!(output.stderr.len() < 4096);
    }

    let exact = successful_fixture();
    let mut exact_bytes = canonical.into_bytes();
    exact_bytes.resize(16 * 1024, b' ');
    private_file(&exact.request, &exact_bytes);
    let output = Command::new(env!("CARGO_BIN_EXE_kapsel"))
        .args([
            "operate",
            "--request",
            exact.request.to_str().unwrap(),
            "--operator-config",
            exact.operator_config.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));

    let oversized = fixture();
    exact_bytes.push(b' ');
    private_file(&oversized.request, &exact_bytes);
    let output = Command::new(env!("CARGO_BIN_EXE_kapsel"))
        .args([
            "operate",
            "--request",
            oversized.request.to_str().unwrap(),
            "--operator-config",
            oversized.operator_config.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn malformed_or_mutable_agent_intent_has_a_bounded_input_exit() {
    let mutable = serde_json::json!({
        "operation_id": "command-op-1",
        "namespace": "demo",
        "deployment": "agent-api",
        "container": "api",
        "immutable_image_digest": "registry.example/agent-api:latest"
    })
    .to_string();
    for replacement in [b"not-json".as_slice(), mutable.as_bytes()] {
        let fixture = fixture();
        private_file(&fixture.request, replacement);
        let output = Command::new(env!("CARGO_BIN_EXE_kapsel"))
            .args([
                "operate",
                "--request",
                fixture.request.to_str().unwrap(),
                "--operator-config",
                fixture.operator_config.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            "{\"command\":\"operate\",\"status\":\"ERROR\",\"error_class\":\"command_input\"}\n"
        );
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            "Kapsel command failure: command_input\n"
        );
    }
}

#[test]
fn exact_tuple_mismatch_is_rejected_as_agent_input() {
    let fixture = fixture();
    let mismatched = fs::read_to_string(&fixture.request)
        .unwrap()
        .replace("\"container\":\"api\"", "\"container\":\"other\"");
    private_file(&fixture.request, mismatched.as_bytes());
    let output = Command::new(env!("CARGO_BIN_EXE_kapsel"))
        .args([
            "operate",
            "--request",
            fixture.request.to_str().unwrap(),
            "--operator-config",
            fixture.operator_config.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8(output.stdout)
        .unwrap()
        .contains("\"error_class\":\"command_input\""));
}

#[test]
fn unsafe_operator_path_fails_before_journal_creation() {
    let fixture = fixture();
    let unsafe_config = fs::read_to_string(&fixture.operator_config)
        .unwrap()
        .replace(
            fixture.root.join("journal.sqlite3").to_str().unwrap(),
            "relative-journal.sqlite3",
        );
    private_file(&fixture.operator_config, unsafe_config.as_bytes());
    let output = Command::new(env!("CARGO_BIN_EXE_kapsel"))
        .args([
            "operate",
            "--request",
            fixture.request.to_str().unwrap(),
            "--operator-config",
            fixture.operator_config.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert!(!fixture.root.join("journal.sqlite3").exists());
    assert!(!Path::new("relative-journal.sqlite3").exists());
}

#[test]
fn unsafe_operator_authority_files_fail_before_journal_creation() {
    let fixture = fixture();
    let key = fixture.root.join("authorization.pub");
    let target = fixture.root.join("authorization-target.pub");
    fs::rename(&key, &target).unwrap();
    std::os::unix::fs::symlink(&target, &key).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_kapsel"))
        .args([
            "operate",
            "--request",
            fixture.request.to_str().unwrap(),
            "--operator-config",
            fixture.operator_config.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert!(!fixture.root.join("journal.sqlite3").exists());

    let special = fixture_with_receiver(false);
    let key = special.root.join("authorization.pub");
    fs::remove_file(&key).unwrap();
    let short_socket = PathBuf::from(format!(
        "/tmp/kapsel-special-{}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_file(&short_socket);
    let _socket = std::os::unix::net::UnixListener::bind(&short_socket).unwrap();
    fs::rename(&short_socket, &key).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_kapsel"))
        .args([
            "operate",
            "--request",
            special.request.to_str().unwrap(),
            "--operator-config",
            special.operator_config.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert!(!special.root.join("journal.sqlite3").exists());
}

#[test]
fn kubeconfig_requires_selected_embedded_authority_and_rejects_plugins_and_oversize() {
    let mutations: [fn(String) -> String; 8] = [
        |value| value.replace("current-context: fixture\n", ""),
        |value| value.replace("current-context: fixture", "current-context: missing"),
        |value| {
            value.replace(
                "    server:",
                "    certificate-authority: /tmp/ca.pem\n    server:",
            )
        },
        |value| value.replace("  user: {}", "  user:\n    tokenFile: /tmp/token"),
        |value| {
            value.replace(
                "  user: {}",
                "  user:\n    client-certificate: /tmp/client.crt",
            )
        },
        |value| value.replace("  user: {}", "  user:\n    client-key: /tmp/client.key"),
        |value| {
            value.replace(
                "  user: {}",
                "  user:\n    auth-provider:\n      name: hostile",
            )
        },
        |value| {
            value.replace(
                "  user: {}",
                "  user:\n    exec:\n      command: /tmp/hostile",
            )
        },
    ];
    for mutate in mutations {
        let fixture = fixture();
        let kubeconfig = fixture.root.join("kubeconfig.yaml");
        let changed = mutate(fs::read_to_string(&kubeconfig).unwrap());
        private_file(&kubeconfig, changed.as_bytes());
        let output = Command::new(env!("CARGO_BIN_EXE_kapsel"))
            .args([
                "operate",
                "--request",
                fixture.request.to_str().unwrap(),
                "--operator-config",
                fixture.operator_config.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(3));
        assert!(!fixture.root.join("journal.sqlite3").exists());
        assert!(output.stdout.len() < 4096);
        assert!(output.stderr.len() < 4096);
    }

    let exact = successful_fixture();
    let kubeconfig = exact.root.join("kubeconfig.yaml");
    let mut exact_bytes = fs::read(&kubeconfig).unwrap();
    exact_bytes.resize(16 * 1024, b' ');
    private_file(&kubeconfig, &exact_bytes);
    let output = Command::new(env!("CARGO_BIN_EXE_kapsel"))
        .args([
            "operate",
            "--request",
            exact.request.to_str().unwrap(),
            "--operator-config",
            exact.operator_config.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));

    let oversized = fixture();
    let kubeconfig = oversized.root.join("kubeconfig.yaml");
    exact_bytes.push(b' ');
    private_file(&kubeconfig, &exact_bytes);
    let output = Command::new(env!("CARGO_BIN_EXE_kapsel"))
        .args([
            "operate",
            "--request",
            oversized.request.to_str().unwrap(),
            "--operator-config",
            oversized.operator_config.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert!(!oversized.root.join("journal.sqlite3").exists());
}

#[test]
fn untrusted_operator_grant_fails_before_journal_creation() {
    let fixture = fixture();
    private_file(&fixture.root.join("authorization.pub"), &[99_u8; 32]);
    let output = Command::new(env!("CARGO_BIN_EXE_kapsel"))
        .args([
            "operate",
            "--request",
            fixture.request.to_str().unwrap(),
            "--operator-config",
            fixture.operator_config.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(3));
    assert!(!fixture.root.join("journal.sqlite3").exists());
    assert!(output.stdout.len() < 4096);
    assert!(output.stderr.len() < 4096);
}

#[test]
fn operator_can_provision_an_exact_grant() {
    let root = std::env::temp_dir().join(format!(
        "kapsel-e2e-provision-{}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&root);
    private_directory(&root);
    let authorization = root.join("authorization.json");
    let seed = root.join("owner.seed");
    let grant = root.join("grant.bin");
    private_file(
        &authorization,
        format!(
            concat!(
                "{{\"authorization_id\":\"auth-1\",\"operation_id\":\"op-1\",",
                "\"namespace\":\"demo\",\"deployment\":\"agent-api\",",
                "\"container\":\"api\",\"immutable_image_digest\":\"{IMAGE}\"}}"
            ),
            IMAGE = IMAGE
        )
        .as_bytes(),
    );
    private_file(&seed, &[7_u8; 32]);
    let output = Command::new(env!("CARGO_BIN_EXE_kapsel"))
        .args([
            "provision-grant",
            "--authorization",
            authorization.to_str().unwrap(),
            "--signing-seed",
            seed.to_str().unwrap(),
            "--signing-key-id",
            "owner-key",
            "--output",
            grant.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "{\"command\":\"provision-grant\",\"status\":\"PROVISIONED\"}\n"
    );
    assert!(grant.exists());
    assert_eq!(
        fs::metadata(&grant).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let grant_before = fs::read(&grant).unwrap();

    let collision = Command::new(env!("CARGO_BIN_EXE_kapsel"))
        .args([
            "provision-grant",
            "--authorization",
            authorization.to_str().unwrap(),
            "--signing-seed",
            seed.to_str().unwrap(),
            "--signing-key-id",
            "owner-key",
            "--output",
            grant.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(collision.status.code(), Some(3));
    assert_eq!(fs::read(&grant).unwrap(), grant_before);

    for (name, bytes) in [
        ("short.seed", vec![7_u8; 31]),
        ("long.seed", vec![7_u8; 33]),
    ] {
        let selected_seed = root.join(name);
        let selected_output = root.join(format!("{name}.grant"));
        private_file(&selected_seed, &bytes);
        let output = Command::new(env!("CARGO_BIN_EXE_kapsel"))
            .args([
                "provision-grant",
                "--authorization",
                authorization.to_str().unwrap(),
                "--signing-seed",
                selected_seed.to_str().unwrap(),
                "--signing-key-id",
                "owner-key",
                "--output",
                selected_output.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(3));
        assert!(!selected_output.exists());
    }
    fs::remove_dir_all(root).unwrap();
}
