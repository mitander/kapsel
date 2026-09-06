//! Fixed-root ordinary startup inputs for the Kapsel service.

use std::{
    fs::File,
    io::Read as _,
    os::{
        fd::AsRawFd as _,
        unix::{fs::MetadataExt as _, net::UnixStream as StdUnixStream},
    },
    path::{Path, PathBuf},
};

use kapsel::{open_application_from_fixed_operator_document, Application, ApplicationError};
use rustix::fs::{chmodat, open, openat, statat, unlinkat, AtFlags, FileType, Mode, OFlags, Stat};
use tokio::net::UnixListener;

const OPERATOR_DOCUMENT_BYTES_MAX: usize = 16 * 1024;
const GRANT_BYTES_MAX: usize = 4 * 1024;
const KEY_BYTES: usize = 32;
const KUBECONFIG_BYTES_MAX: usize = 16 * 1024;
const JOURNAL_BYTES_MAX: u64 = 64 * 1024 * 1024;

pub(crate) struct InstallationInputs {
    _configuration_root: File,
    _state_root: File,
    _receipt_root: File,
    runtime_root: File,
    configuration_path: PathBuf,
    document: Vec<u8>,
    grant: Vec<u8>,
    authorization_key: Vec<u8>,
    kubeconfig: Vec<u8>,
    receipt_seed: Vec<u8>,
    journal_path: PathBuf,
    receipt_path: PathBuf,
    journal_access_path: PathBuf,
    receipt_access_path: PathBuf,
    socket_access_path: PathBuf,
}

impl InstallationInputs {
    pub(crate) fn open_at(root: &Path) -> std::io::Result<Self> {
        let installation_root = root.to_path_buf();
        let root = File::from(open(root, directory_flags(), Mode::empty())?);
        let etc = open_directory(&root, "etc")?;
        let configuration = open_directory(&etc, "kapsel")?;
        require_owned_directory(&configuration, 0o700)?;
        let var = open_directory(&root, "var")?;
        let lib = open_directory(&var, "lib")?;
        let state = open_directory(&lib, "kapsel")?;
        require_owned_directory(&state, 0o700)?;
        let receipts = open_directory(&state, "receipts")?;
        require_owned_directory(&receipts, 0o700)?;
        let run = open_directory(&root, "run")?;
        let runtime = open_directory(&run, "kapsel")?;
        require_owned_directory(&runtime, 0o750)?;
        validate_optional_private_file(&state, "journal.sqlite3", JOURNAL_BYTES_MAX)?;
        validate_optional_private_file(&state, "journal.sqlite3.kap0038-worker.lock", 0)?;
        let document =
            read_private_file(&configuration, "operator.json", OPERATOR_DOCUMENT_BYTES_MAX)?;
        let grant = read_private_file(&configuration, "grant.bin", GRANT_BYTES_MAX)?;
        let authorization_key = read_private_file(&configuration, "authorization.pub", KEY_BYTES)?;
        let kubeconfig =
            read_private_file(&configuration, "kubeconfig.yaml", KUBECONFIG_BYTES_MAX)?;
        let receipt_seed = read_private_file(&configuration, "receipt.seed", KEY_BYTES)?;
        let configuration_path = installation_root.join("etc/kapsel");
        let state_access_path = descriptor_directory_path(&state)?;
        let receipt_access_path = descriptor_directory_path(&receipts)?;
        let runtime_access_path = descriptor_directory_path(&runtime)?;
        Ok(Self {
            _configuration_root: configuration,
            _state_root: state,
            _receipt_root: receipts,
            runtime_root: runtime,
            configuration_path,
            document,
            grant,
            authorization_key,
            kubeconfig,
            receipt_seed,
            journal_path: installation_root.join("var/lib/kapsel/journal.sqlite3"),
            receipt_path: installation_root.join("var/lib/kapsel/receipts"),
            journal_access_path: state_access_path.join("journal.sqlite3"),
            receipt_access_path,
            socket_access_path: runtime_access_path.join("kapseld.sock"),
        })
    }

    pub(crate) fn bind_listener(&self) -> std::io::Result<UnixListener> {
        prepare_socket_path(&self.runtime_root, &self.socket_access_path)?;
        let listener = UnixListener::bind(&self.socket_access_path)?;
        let configured = chmodat(
            &self.runtime_root,
            "kapseld.sock",
            socket_mode(),
            AtFlags::empty(),
        )
        .map_err(std::io::Error::from)
        .and_then(|()| require_socket_identity(&self.runtime_root));
        if let Err(error) = configured {
            drop(listener);
            let _ = unlinkat(&self.runtime_root, "kapseld.sock", AtFlags::empty());
            return Err(error);
        }
        Ok(listener)
    }

    pub(crate) async fn open_application(&self) -> Result<Application, ApplicationError> {
        open_application_from_fixed_operator_document(
            &self.document,
            &self.journal_path,
            &self.receipt_path,
            &self.journal_access_path,
            &self.receipt_access_path,
            |path, maximum| {
                let bytes = if path == self.configuration_path.join("grant.bin") {
                    &self.grant
                } else if path == self.configuration_path.join("authorization.pub") {
                    &self.authorization_key
                } else if path == self.configuration_path.join("kubeconfig.yaml") {
                    &self.kubeconfig
                } else if path == self.configuration_path.join("receipt.seed") {
                    &self.receipt_seed
                } else {
                    return Err(ApplicationError::InvalidOperatorConfiguration);
                };
                if bytes.len() > maximum {
                    return Err(ApplicationError::InvalidOperatorConfiguration);
                }
                Ok(bytes.clone())
            },
        )
        .await
    }
}

fn descriptor_directory_path(directory: &File) -> std::io::Result<PathBuf> {
    let path = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
    let descriptor = directory.metadata()?;
    let named = path.metadata()?;
    if !named.is_dir()
        || descriptor.dev() != named.dev()
        || descriptor.ino() != named.ino()
        || descriptor.uid() != named.uid()
        || descriptor.gid() != named.gid()
        || descriptor.mode() != named.mode()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "validated directory descriptor is unavailable",
        ));
    }
    Ok(path)
}

fn prepare_socket_path(runtime: &File, socket_path: &Path) -> std::io::Result<()> {
    let stale = match statat(runtime, "kapseld.sock", AtFlags::SYMLINK_NOFOLLOW) {
        Ok(metadata) => metadata,
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    require_socket_metadata(&stale)?;
    match StdUnixStream::connect(socket_path) {
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                "service socket is active",
            ));
        },
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {},
        Err(error) => return Err(error),
    }
    let current = statat(runtime, "kapseld.sock", AtFlags::SYMLINK_NOFOLLOW)?;
    require_socket_metadata(&current)?;
    if stale.st_dev != current.st_dev || stale.st_ino != current.st_ino {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "service socket identity changed",
        ));
    }
    unlinkat(runtime, "kapseld.sock", AtFlags::empty())?;
    Ok(())
}

fn require_socket_identity(runtime: &File) -> std::io::Result<()> {
    let metadata = statat(runtime, "kapseld.sock", AtFlags::SYMLINK_NOFOLLOW)?;
    require_socket_metadata(&metadata)
}

fn require_socket_metadata(metadata: &Stat) -> std::io::Result<()> {
    if FileType::from_raw_mode(metadata.st_mode) == FileType::Socket
        && metadata.st_uid == rustix::process::geteuid().as_raw()
        && metadata.st_gid == rustix::process::getegid().as_raw()
        && metadata.st_nlink == 1
        && Mode::from_raw_mode(metadata.st_mode) == socket_mode()
    {
        return Ok(());
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "invalid service socket",
    ))
}

fn socket_mode() -> Mode {
    Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP
}

fn open_directory(parent: &File, name: &str) -> std::io::Result<File> {
    Ok(File::from(openat(
        parent,
        name,
        directory_flags(),
        Mode::empty(),
    )?))
}

fn require_owned_directory(directory: &File, mode: u32) -> std::io::Result<()> {
    let metadata = directory.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.gid() != rustix::process::getegid().as_raw()
        || metadata.mode() & 0o7777 != mode
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "invalid installation directory",
        ));
    }
    Ok(())
}

fn validate_optional_private_file(parent: &File, name: &str, maximum: u64) -> std::io::Result<()> {
    let file = match openat(parent, name, read_flags(), Mode::empty()) {
        Ok(file) => File::from(file),
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.gid() != rustix::process::getegid().as_raw()
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
        || metadata.len() > maximum
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "invalid installation state file",
        ));
    }
    Ok(())
}

fn read_private_file(parent: &File, name: &str, maximum: usize) -> std::io::Result<Vec<u8>> {
    let file = File::from(openat(parent, name, read_flags(), Mode::empty())?);
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.gid() != rustix::process::getegid().as_raw()
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
        || usize::try_from(metadata.len()).map_or(true, |length| length > maximum)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "invalid installation file",
        ));
    }
    let mut bytes = Vec::with_capacity(maximum.saturating_add(1));
    let limit = u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1);
    file.take(limit).read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "installation file exceeds bound",
        ));
    }
    Ok(bytes)
}

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

fn read_flags() -> OFlags {
    OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "controlled fixed-root fixtures must fail the startup test immediately"
)]
mod tests {
    use std::{
        fs,
        io::{Read as _, Write as _},
        net::{TcpListener, TcpStream},
        os::unix::{
            fs::PermissionsExt as _,
            net::{UnixListener, UnixStream as StdUnixStream},
        },
        path::{Path, PathBuf},
        thread,
        time::Duration,
    };

    use ed25519_dalek::SigningKey;
    use kapsel::{
        provision_exact_grant, AgentRequest, ExactAuthorization, GrantProvisioning, OperationResult,
    };

    use super::{InstallationInputs, GRANT_BYTES_MAX};

    fn directory(path: &Path, mode: u32) {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn private_file(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn root(name: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("kapseld-fixed-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        directory(&root, 0o700);
        directory(&root.join("etc"), 0o700);
        directory(&root.join("etc/kapsel"), 0o700);
        directory(&root.join("var"), 0o700);
        directory(&root.join("var/lib"), 0o700);
        directory(&root.join("var/lib/kapsel"), 0o700);
        directory(&root.join("var/lib/kapsel/receipts"), 0o700);
        directory(&root.join("run"), 0o700);
        directory(&root.join("run/kapsel"), 0o750);
        fs::canonicalize(root).unwrap()
    }

    fn valid_root(name: &str) -> PathBuf {
        valid_root_with_server(name, "http://127.0.0.1:1234")
    }

    fn valid_root_with_server(name: &str, server: &str) -> PathBuf {
        let root = root(name);
        let authorization_seed = [101_u8; 32];
        let authorization_key = SigningKey::from_bytes(&authorization_seed);
        let authorization = ExactAuthorization {
            approved_target: Some(kapsel::ApprovedTarget {
                uid: "uid-1".into(),
                resource_version: "1".into(),
            }),
            authorization_id: "service-auth".into(),
            operation_id: "service-op".into(),
            namespace: "demo".into(),
            deployment: "agent-api".into(),
            container: "api".into(),
            immutable_image_digest: concat!(
                "registry.example/agent-api@sha256:",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            )
            .into(),
        };
        let grant = provision_exact_grant(&GrantProvisioning {
            authorization: &authorization,
            signing_seed: &authorization_seed,
            signing_key_id: "service-owner-key",
        })
        .unwrap();
        private_file(&root.join("etc/kapsel/grant.bin"), &grant);
        private_file(
            &root.join("etc/kapsel/authorization.pub"),
            &authorization_key.verifying_key().to_bytes(),
        );
        private_file(
            &root.join("etc/kapsel/kubeconfig.yaml"),
            format!(
                concat!(
                    "apiVersion: v1\nkind: Config\ncurrent-context: fixture\n",
                    "clusters:\n- name: fixture\n  cluster:\n",
                    "    server: {server}\n",
                    "contexts:\n- name: fixture\n  context:\n",
                    "    cluster: fixture\n    user: fixture\n",
                    "users:\n- name: fixture\n  user: {{}}\n"
                ),
                server = server
            )
            .as_bytes(),
        );
        private_file(&root.join("etc/kapsel/receipt.seed"), &[102_u8; 32]);
        private_file(
            &root.join("etc/kapsel/operator.json"),
            &serde_json::to_vec(&serde_json::json!({
                "signed_authorization_grant": root.join("etc/kapsel/grant.bin"),
                "authorization_key_id": "service-owner-key",
                "authorization_public_key": root.join("etc/kapsel/authorization.pub"),
                "kubeconfig": root.join("etc/kapsel/kubeconfig.yaml"),
                "journal": root.join("var/lib/kapsel/journal.sqlite3"),
                "receipt_directory": root.join("var/lib/kapsel/receipts"),
                "receipt_signing_seed": root.join("etc/kapsel/receipt.seed"),
                "receipt_signing_key_id": "service-receipt-key"
            }))
            .unwrap(),
        );
        root
    }

    fn request() -> AgentRequest {
        AgentRequest {
            operation_id: "service-op".into(),
            namespace: "demo".into(),
            deployment: "agent-api".into(),
            container: "api".into(),
            immutable_image_digest: concat!(
                "registry.example/agent-api@sha256:",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            )
            .into(),
        }
    }

    fn deployment(resource_version: &str, generation: u64, updated: bool, ready: bool) -> String {
        let old_image = concat!(
            "registry.example/agent-api@sha256:",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
        let image = if updated {
            request().immutable_image_digest
        } else {
            old_image.into()
        };
        serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "agent-api",
                "namespace": "demo",
                "uid": "uid-1",
                "resourceVersion": resource_version,
                "generation": generation,
                "annotations": if updated {
                    serde_json::json!({"kapsel.dev/kap0038-operation-id": "service-op"})
                } else {
                    serde_json::json!({})
                }
            },
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": {"app": "agent-api"}},
                "template": {
                    "metadata": {"labels": {"app": "agent-api"}},
                    "spec": {"containers": [{"name": "api", "image": image}]}
                }
            },
            "status": if ready {
                serde_json::json!({
                    "observedGeneration": generation,
                    "updatedReplicas": 1,
                    "availableReplicas": 1,
                    "unavailableReplicas": 0,
                    "conditions": [{
                        "type": "Available",
                        "status": "True",
                        "reason": "MinimumReplicasAvailable"
                    }]
                })
            } else {
                serde_json::json!({"observedGeneration": generation})
            }
        })
        .to_string()
    }

    fn read_provider_request(stream: &mut TcpStream) -> String {
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut bytes = Vec::new();
        loop {
            let mut chunk = [0_u8; 4096];
            let read = stream.read(&mut chunk).unwrap();
            assert!(read > 0, "provider request ended before framing completed");
            bytes.extend_from_slice(&chunk[..read]);
            assert!(bytes.len() <= 16 * 1024, "provider request exceeded bound");
            let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
                continue;
            };
            let header_end = header_end + 4;
            let headers = std::str::from_utf8(&bytes[..header_end]).unwrap();
            let content_length = headers
                .lines()
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .map_or(0, |(_, value)| value.trim().parse::<usize>().unwrap());
            if bytes.len() >= header_end + content_length {
                return headers.lines().next().unwrap().to_owned();
            }
        }
    }

    fn write_provider_response(stream: &mut TcpStream, body: &str) {
        write!(
            stream,
            concat!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n",
                "content-length: {}\r\nconnection: close\r\n\r\n"
            ),
            body.len()
        )
        .unwrap();
        stream.write_all(body.as_bytes()).unwrap();
    }

    fn success_server() -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let thread = thread::spawn(move || {
            for (expected_method, response) in [
                ("GET", deployment("1", 1, false, false)),
                ("PATCH", deployment("2", 2, true, false)),
                ("GET", deployment("3", 2, true, true)),
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                let request_line = read_provider_request(&mut stream);
                assert!(request_line.starts_with(expected_method));
                write_provider_response(&mut stream, &response);
            }
        });
        (url, thread)
    }

    #[test]
    fn validated_authority_bytes_survive_name_replacement() {
        let root = valid_root("stable-inputs");
        let inputs = InstallationInputs::open_at(&root).unwrap();
        for (name, replacement) in [
            ("grant.bin", b"different".as_slice()),
            ("authorization.pub", &[99_u8; 32]),
            ("kubeconfig.yaml", b"different".as_slice()),
            ("receipt.seed", &[98_u8; 32]),
        ] {
            let path = root.join("etc/kapsel").join(name);
            fs::rename(&path, path.with_extension("replaced")).unwrap();
            private_file(&path, replacement);
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let application = runtime.block_on(inputs.open_application()).unwrap();
        assert!(application
            .read_set_deployment_image_status("service-op")
            .unwrap()
            .eq(&kapsel::SetDeploymentImageStatus::NotFound));
        drop(application);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn state_root_rename_and_replacement_keep_journal_on_validated_directory() {
        for replacement in [false, true] {
            let root = valid_root(if replacement {
                "state-replacement"
            } else {
                "state-rename"
            });
            let inputs = InstallationInputs::open_at(&root).unwrap();
            let state = root.join("var/lib/kapsel");
            let retained = root.join("var/lib/kapsel.retained");
            fs::rename(&state, &retained).unwrap();
            if replacement {
                directory(&state, 0o700);
                directory(&state.join("receipts"), 0o700);
            }
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            let application = runtime.block_on(inputs.open_application()).unwrap();

            assert!(retained.join("journal.sqlite3").is_file());
            assert!(retained
                .join("journal.sqlite3.kap0038-worker.lock")
                .is_file());
            for name in [
                "journal.sqlite3",
                "journal.sqlite3.kap0038-worker.lock",
                "journal.sqlite3-journal",
                "journal.sqlite3-wal",
                "journal.sqlite3-shm",
            ] {
                assert!(!state.join(name).exists());
            }
            if replacement {
                assert_eq!(fs::read_dir(&state).unwrap().count(), 1);
            }
            drop(application);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn receipt_root_rename_and_replacement_publish_only_on_validated_directory() {
        for replacement in [false, true] {
            let (server, provider) = success_server();
            let root = valid_root_with_server(
                if replacement {
                    "receipt-replacement"
                } else {
                    "receipt-rename"
                },
                &server,
            );
            let inputs = InstallationInputs::open_at(&root).unwrap();
            let receipts = root.join("var/lib/kapsel/receipts");
            let retained = root.join("var/lib/kapsel/receipts.retained");
            fs::rename(&receipts, &retained).unwrap();
            if replacement {
                directory(&receipts, 0o700);
            }
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            let mut application = runtime.block_on(inputs.open_application()).unwrap();
            let report = runtime.block_on(application.execute(&request())).unwrap();

            assert_eq!(report.result, Some(OperationResult::Succeeded));
            assert!(report.receipt.is_some());
            assert_eq!(fs::read_dir(&retained).unwrap().count(), 1);
            assert!(fs::read_dir(&retained)
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path()
                .is_file());
            if replacement {
                assert_eq!(fs::read_dir(&receipts).unwrap().count(), 0);
            } else {
                assert!(!receipts.exists());
            }
            provider.join().unwrap();
            drop(application);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn runtime_root_rename_and_replacement_bind_only_on_validated_directory() {
        for replacement in [false, true] {
            let root = valid_root(if replacement {
                "runtime-replacement"
            } else {
                "runtime-rename"
            });
            let inputs = InstallationInputs::open_at(&root).unwrap();
            let runtime_path = root.join("run/kapsel");
            let retained = root.join("run/kapsel.retained");
            fs::rename(&runtime_path, &retained).unwrap();
            if replacement {
                directory(&runtime_path, 0o750);
            }
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            let listener = runtime.block_on(async { inputs.bind_listener() }).unwrap();

            assert!(retained.join("kapseld.sock").exists());
            assert!(!runtime_path.join("kapseld.sock").exists());
            drop(listener);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn active_socket_is_preserved_and_rejected() {
        let root = valid_root("active-socket");
        let inputs = InstallationInputs::open_at(&root).unwrap();
        let socket = UnixListener::bind(&inputs.socket_access_path).unwrap();
        fs::set_permissions(
            &inputs.socket_access_path,
            fs::Permissions::from_mode(0o660),
        )
        .unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let error = runtime
            .block_on(async { inputs.bind_listener() })
            .unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
        assert!(inputs.socket_access_path.exists());
        drop(socket);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn stale_socket_is_removed_before_rebinding() {
        let root = valid_root("stale-socket");
        let inputs = InstallationInputs::open_at(&root).unwrap();
        let stale = UnixListener::bind(&inputs.socket_access_path).unwrap();
        fs::set_permissions(
            &inputs.socket_access_path,
            fs::Permissions::from_mode(0o660),
        )
        .unwrap();
        drop(stale);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let listener = runtime.block_on(async { inputs.bind_listener() }).unwrap();

        let replacement = fs::metadata(&inputs.socket_access_path).unwrap();
        assert_eq!(replacement.permissions().mode() & 0o7777, 0o660);
        let client = StdUnixStream::connect(&inputs.socket_access_path).unwrap();
        let (_connection, _) = runtime.block_on(listener.accept()).unwrap();
        drop(client);
        drop(listener);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn authority_file_and_component_substitutions_fail_closed() {
        for mutation in [
            "restrictive-mode",
            "permissive-mode",
            "hard-link",
            "symlink",
            "socket",
            "directory",
            "oversized",
        ] {
            let root = valid_root(mutation);
            let path = root.join("etc/kapsel/grant.bin");
            let mut socket = None;
            match mutation {
                "restrictive-mode" => {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
                },
                "permissive-mode" => {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
                },
                "hard-link" => {
                    fs::hard_link(&path, root.join("etc/kapsel/grant.link")).unwrap();
                },
                "symlink" => {
                    let target = root.join("etc/kapsel/grant.target");
                    fs::rename(&path, &target).unwrap();
                    std::os::unix::fs::symlink(target, &path).unwrap();
                },
                "socket" => {
                    fs::remove_file(&path).unwrap();
                    socket = Some(UnixListener::bind(&path).unwrap());
                },
                "directory" => {
                    fs::remove_file(&path).unwrap();
                    fs::create_dir(&path).unwrap();
                },
                "oversized" => private_file(&path, &vec![0_u8; GRANT_BYTES_MAX + 1]),
                _ => unreachable!(),
            }
            assert!(InstallationInputs::open_at(&root).is_err());
            drop(socket);
            fs::remove_dir_all(root).unwrap();
        }

        let root = valid_root("component-symlink");
        let configuration = root.join("etc/kapsel");
        let target = root.join("etc/configuration-target");
        fs::rename(&configuration, &target).unwrap();
        std::os::unix::fs::symlink(target, configuration).unwrap();
        assert!(InstallationInputs::open_at(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn wrong_mode_existing_worker_lock_is_rejected_before_application_open() {
        let root = valid_root("worker-lock-mode");
        fs::write(
            root.join("var/lib/kapsel/journal.sqlite3.kap0038-worker.lock"),
            b"",
        )
        .unwrap();
        fs::set_permissions(
            root.join("var/lib/kapsel/journal.sqlite3.kap0038-worker.lock"),
            fs::Permissions::from_mode(0o640),
        )
        .unwrap();

        assert!(InstallationInputs::open_at(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn wrong_mode_existing_journal_is_rejected_before_application_open() {
        let root = valid_root("journal-mode");
        fs::write(root.join("var/lib/kapsel/journal.sqlite3"), b"").unwrap();
        fs::set_permissions(
            root.join("var/lib/kapsel/journal.sqlite3"),
            fs::Permissions::from_mode(0o640),
        )
        .unwrap();

        assert!(InstallationInputs::open_at(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn wrong_mode_operator_document_is_rejected_before_other_inputs() {
        let root = root("mode");
        fs::write(root.join("etc/kapsel/operator.json"), b"{}").unwrap();
        fs::set_permissions(
            root.join("etc/kapsel/operator.json"),
            fs::Permissions::from_mode(0o640),
        )
        .unwrap();

        assert!(InstallationInputs::open_at(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
