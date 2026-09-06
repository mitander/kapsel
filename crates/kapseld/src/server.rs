//! Authenticated bounded socket, execution ownership, and fixed service startup.

use std::{
    future::Future,
    io,
    process::ExitCode,
    sync::{Arc, Mutex},
    time::Duration,
};

use kapsel::{
    AgentRequest, Application, ApplicationError, SetDeploymentImageReceipt,
    SetDeploymentImageStatus, TargetRejection,
};
use serde::Deserialize;
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
    net::{UnixListener, UnixStream},
    sync::{Mutex as AsyncMutex, Semaphore},
    task::spawn_blocking,
    time::timeout,
};

const REQUEST_BYTES_MAX: usize = 16 * 1024;
const ORDINARY_RESPONSE_BYTES_MAX: usize = 16 * 1024;
const RECEIPT_RESPONSE_BYTES_MAX: usize = 40 * 1024;
const CONNECTIONS_MAX: usize = 8;
const IO_DEADLINE: Duration = Duration::from_secs(2);

trait ApplicationReads: Send {
    fn status_with_targets(
        &self,
        operation_id: &str,
    ) -> Result<(SetDeploymentImageStatus, kapsel::OperationTargets), ApplicationError> {
        self.status(operation_id)
            .map(|status| (status, kapsel::OperationTargets::default()))
    }

    fn status(&self, operation_id: &str) -> Result<SetDeploymentImageStatus, ApplicationError>;

    fn receipt(&self, operation_id: &str) -> Result<SetDeploymentImageReceipt, ApplicationError>;
}

impl ApplicationReads for Application {
    fn status_with_targets(
        &self,
        operation_id: &str,
    ) -> Result<(SetDeploymentImageStatus, kapsel::OperationTargets), ApplicationError> {
        self.read_set_deployment_image_status_with_targets(operation_id)
    }

    fn status(&self, operation_id: &str) -> Result<SetDeploymentImageStatus, ApplicationError> {
        self.read_set_deployment_image_status(operation_id)
    }

    fn receipt(&self, operation_id: &str) -> Result<SetDeploymentImageReceipt, ApplicationError> {
        self.read_set_deployment_image_receipt(operation_id)
    }
}

trait ApplicationExecution: Send {
    fn matches(&self, request: &AgentRequest) -> bool;

    fn execute(
        &mut self,
        request: AgentRequest,
    ) -> impl Future<Output = Result<(), ApplicationError>> + Send;
}

impl ApplicationExecution for Application {
    fn matches(&self, request: &AgentRequest) -> bool {
        self.request_matches_authorized_grant(request)
    }

    async fn execute(&mut self, request: AgentRequest) -> Result<(), ApplicationError> {
        Self::execute(self, &request).await.map(|_| ())
    }
}

struct ServerState<R, E> {
    reads: Arc<Mutex<R>>,
    execution: Arc<AsyncMutex<E>>,
    submission: Arc<Semaphore>,
}

impl<R, E> ServerState<R, E> {
    fn new(reads: R, execution: E) -> Self {
        Self {
            reads: Arc::new(Mutex::new(reads)),
            execution: Arc::new(AsyncMutex::new(execution)),
            submission: Arc::new(Semaphore::new(1)),
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
impl<R> ServerState<R, UnavailableExecution> {
    fn read_only(reads: Arc<Mutex<R>>) -> Self {
        Self {
            reads,
            execution: Arc::new(AsyncMutex::new(UnavailableExecution)),
            submission: Arc::new(Semaphore::new(1)),
        }
    }
}

impl<R, E> Clone for ServerState<R, E> {
    fn clone(&self) -> Self {
        Self {
            reads: self.reads.clone(),
            execution: self.execution.clone(),
            submission: self.submission.clone(),
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
struct UnavailableExecution;

#[cfg(all(test, target_os = "linux"))]
impl ApplicationExecution for UnavailableExecution {
    fn matches(&self, _request: &AgentRequest) -> bool {
        false
    }

    fn execute(
        &mut self,
        _request: AgentRequest,
    ) -> impl Future<Output = Result<(), ApplicationError>> + Send {
        std::future::ready(Err(ApplicationError::OperationFailure))
    }
}

#[derive(Clone, Copy)]
enum SubmissionAdmission {
    Accepted,
    Busy,
    OperationFailure,
}

#[derive(Deserialize)]
#[serde(tag = "request", deny_unknown_fields)]
enum Request {
    #[serde(rename = "get_set_deployment_image_status")]
    Status { operation_id: String },
    #[serde(rename = "get_set_deployment_image_receipt")]
    Receipt { operation_id: String },
    #[serde(rename = "submit_set_deployment_image")]
    Submit {
        operation_id: String,
        namespace: String,
        deployment: String,
        container: String,
        immutable_image_digest: String,
    },
}

#[derive(Clone, Copy)]
enum ResponseClass {
    Ordinary,
    Receipt,
}

pub(crate) fn run() -> ExitCode {
    #[cfg(target_os = "linux")]
    {
        #[cfg(feature = "test-harness")]
        if std::env::var_os("KAPSELD_TEST_SOCKET").is_some() {
            return run_test_harness();
        }
        run_installed()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = serve_connections_with_state::<Application, Application>;
        let _ = ServerState::<Application, Application>::new;
        ExitCode::from(4)
    }
}

#[cfg(target_os = "linux")]
fn run_installed() -> ExitCode {
    use crate::startup::InstallationInputs;

    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--operator-config"))
        || arguments.next().as_deref() != Some(std::ffi::OsStr::new("/etc/kapsel/operator.json"))
        || arguments.next().as_deref() != Some(std::ffi::OsStr::new("--socket"))
        || arguments.next().as_deref() != Some(std::ffi::OsStr::new("/run/kapsel/kapseld.sock"))
        || arguments.next().is_some()
    {
        return ExitCode::from(4);
    }
    #[cfg(feature = "test-harness")]
    let installation_root = std::env::var_os("KAPSELD_TEST_INSTALLATION_ROOT")
        .map_or_else(|| std::path::PathBuf::from("/"), std::path::PathBuf::from);
    #[cfg(not(feature = "test-harness"))]
    let installation_root = std::path::PathBuf::from("/");
    #[cfg(feature = "test-harness")]
    let connections = match std::env::var("KAPSELD_TEST_CONNECTIONS") {
        Ok(value) => match value.parse::<usize>() {
            Ok(value) if value > 0 && value <= CONNECTIONS_MAX + 2 => Some(value),
            _ => return ExitCode::from(4),
        },
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => return ExitCode::from(4),
    };
    #[cfg(not(feature = "test-harness"))]
    let connections = None;
    let Ok(inputs) = InstallationInputs::open_at(&installation_root) else {
        return ExitCode::from(4);
    };
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return ExitCode::from(4);
    };
    let result = runtime.block_on(async {
        let mut execution = inputs
            .open_application()
            .await
            .map_err(|_| io::Error::other("application open failed"))?;
        execution
            .reconcile()
            .await
            .map_err(|_| io::Error::other("startup reconciliation failed"))?;
        let reads = inputs
            .open_application()
            .await
            .map_err(|_| io::Error::other("application open failed"))?;
        let listener = inputs.bind_listener()?;
        let state = ServerState::new(reads, execution);
        let expected_gid = rustix::process::getegid().as_raw();
        match connections {
            Some(connections) => {
                serve_connections_with_state(listener, expected_gid, state, connections).await
            },
            None => serve_connections_forever(listener, expected_gid, state).await,
        }
    });
    if result.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(4)
    }
}

#[cfg(all(target_os = "linux", feature = "test-harness"))]
fn run_test_harness() -> ExitCode {
    let Ok(path) = std::env::var("KAPSELD_TEST_SOCKET") else {
        return ExitCode::from(4);
    };
    let Ok(expected_gid) = std::env::var("KAPSELD_TEST_EXPECTED_GID") else {
        return ExitCode::from(4);
    };
    let Ok(expected_gid) = expected_gid.parse::<u32>() else {
        return ExitCode::from(4);
    };
    let Ok(connections) = std::env::var("KAPSELD_TEST_CONNECTIONS") else {
        return ExitCode::from(4);
    };
    let Ok(connections) = connections.parse::<usize>() else {
        return ExitCode::from(4);
    };
    if connections == 0 || connections > CONNECTIONS_MAX + 2 {
        return ExitCode::from(4);
    }
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return ExitCode::from(4);
    };
    let result = if let Some(root) = std::env::var_os("KAPSELD_TEST_APPLICATION_ROOT") {
        run_application_test_harness(
            &runtime,
            std::path::Path::new(&path),
            expected_gid,
            connections,
            std::path::Path::new(&root),
        )
    } else {
        let status = Arc::new(std::sync::atomic::AtomicU8::new(0));
        let release = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let state = ServerState::new(
            HarnessReads {
                status: status.clone(),
                release: release.clone(),
                status_reads: std::sync::atomic::AtomicU8::new(0),
            },
            HarnessExecution { status, release },
        );
        runtime.block_on(async {
            let listener = UnixListener::bind(&path)?;
            let result =
                serve_connections_with_state(listener, expected_gid, state, connections).await;
            let removal = std::fs::remove_file(path);
            result.and(removal)
        })
    };
    if result.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(4)
    }
}

#[cfg(all(target_os = "linux", feature = "test-harness"))]
fn run_application_test_harness(
    runtime: &tokio::runtime::Runtime,
    socket: &std::path::Path,
    expected_gid: u32,
    connections: usize,
    root: &std::path::Path,
) -> io::Result<()> {
    if !root.is_absolute() {
        return Err(io::Error::other("invalid application fixture"));
    }
    runtime.block_on(async {
        let mut execution = open_test_application(root)?;
        execution
            .reconcile()
            .await
            .map_err(|_| io::Error::other("startup reconciliation failed"))?;
        let reads = open_test_application(root)?;
        let listener = UnixListener::bind(socket)?;
        let result = serve_connections_with_state(
            listener,
            expected_gid,
            ServerState::new(reads, execution),
            connections,
        )
        .await;
        let removal = std::fs::remove_file(socket);
        result.and(removal)
    })
}

#[cfg(all(target_os = "linux", feature = "test-harness"))]
fn open_test_application(root: &std::path::Path) -> io::Result<Application> {
    use ed25519_dalek::SigningKey;
    use kapsel::{
        provision_exact_grant, AuthorizationTrust, ExactAuthorization, GrantProvisioning,
        OperatorConfiguration,
    };

    let url = std::env::var("KAPSELD_TEST_KUBERNETES_URL")
        .map_err(|_| io::Error::other("invalid application fixture"))?;
    let cluster_url = url
        .parse()
        .map_err(|_| io::Error::other("invalid application fixture"))?;
    let config = kube::Config::new(cluster_url);
    if config.cluster_url.scheme_str() != Some("http")
        || config.cluster_url.host() != Some("127.0.0.1")
        || config.cluster_url.port_u16().is_none()
    {
        return Err(io::Error::other("invalid application fixture"));
    }
    let kubernetes_client = kube::Client::try_from(config)
        .map_err(|_| io::Error::other("invalid application fixture"))?;
    let authorization_seed = [41_u8; 32];
    let authorization_key = SigningKey::from_bytes(&authorization_seed);
    let authorization = ExactAuthorization {
        approved_target: None,
        authorization_id: "process-auth".into(),
        operation_id: "process-op".into(),
        namespace: "demo".into(),
        deployment: "agent-api".into(),
        container: "api".into(),
        immutable_image_digest: concat!(
            "registry.example/agent-api@sha256:",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        .into(),
    };
    let signed_authorization_grant = provision_exact_grant(&GrantProvisioning {
        authorization: &authorization,
        signing_seed: &authorization_seed,
        signing_key_id: "process-authorization-key",
    })
    .map_err(|_| io::Error::other("invalid application fixture"))?;
    let (receipt_directory, receipt_signing_seed, receipt_signing_key_id) =
        match std::env::var("KAPSELD_TEST_RECEIPT_CONFIGURATION").as_deref() {
            Ok("A") => (
                root.join("receipts-a"),
                [42_u8; 32],
                "process-receipt-key-a",
            ),
            Ok("B") => (
                root.join("receipts-b"),
                [43_u8; 32],
                "process-receipt-key-b",
            ),
            _ => return Err(io::Error::other("invalid application fixture")),
        };
    Application::open(OperatorConfiguration {
        journal_path: root.join("journal.sqlite3"),
        receipt_output_directory: receipt_directory,
        authorization_trust: AuthorizationTrust {
            key_id: "process-authorization-key".into(),
            public_key: authorization_key.verifying_key().to_bytes(),
        },
        signed_authorization_grant,
        kubernetes_client,
        receipt_signing_seed,
        receipt_signing_key_id: receipt_signing_key_id.into(),
    })
    .map_err(|_| io::Error::other("application open failed"))
}

#[cfg(all(target_os = "linux", feature = "test-harness"))]
struct HarnessReads {
    status: Arc<std::sync::atomic::AtomicU8>,
    release: Arc<std::sync::atomic::AtomicBool>,
    status_reads: std::sync::atomic::AtomicU8,
}

#[cfg(all(target_os = "linux", feature = "test-harness"))]
impl ApplicationReads for HarnessReads {
    fn status(&self, operation_id: &str) -> Result<SetDeploymentImageStatus, ApplicationError> {
        use std::{sync::atomic::Ordering, time::Instant};

        if operation_id != "process-op" {
            return Ok(SetDeploymentImageStatus::NotFound);
        }
        let first_read = self.status_reads.fetch_add(1, Ordering::AcqRel) == 0;
        if !first_read {
            self.release.store(true, Ordering::Release);
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match (first_read, self.status.load(Ordering::Acquire)) {
                (true, 1) => return Ok(SetDeploymentImageStatus::InProgress),
                (false, 2) => {
                    return Ok(SetDeploymentImageStatus::NotAttempted(
                        TargetRejection::DeploymentNotFound,
                    ));
                },
                (_, _) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(1));
                },
                (_, _) => return Err(ApplicationError::OperationFailure),
            }
        }
    }

    fn receipt(&self, _operation_id: &str) -> Result<SetDeploymentImageReceipt, ApplicationError> {
        Ok(SetDeploymentImageReceipt::NotFound)
    }
}

#[cfg(all(target_os = "linux", feature = "test-harness"))]
struct HarnessExecution {
    status: Arc<std::sync::atomic::AtomicU8>,
    release: Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(all(target_os = "linux", feature = "test-harness"))]
impl ApplicationExecution for HarnessExecution {
    fn matches(&self, request: &AgentRequest) -> bool {
        request.operation_id == "process-op"
            && request.namespace == "demo"
            && request.deployment == "agent-api"
            && request.container == "api"
            && request.immutable_image_digest
                == concat!(
                    "registry.example/agent-api@sha256:",
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                )
    }

    async fn execute(&mut self, _request: AgentRequest) -> Result<(), ApplicationError> {
        use std::sync::atomic::Ordering;

        self.status.store(1, Ordering::Release);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !self.release.load(Ordering::Acquire) {
            if tokio::time::Instant::now() >= deadline {
                return Err(ApplicationError::OperationFailure);
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        self.status.store(2, Ordering::Release);
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux"))]
async fn serve_connections<R: ApplicationReads + 'static>(
    listener: UnixListener,
    expected_gid: u32,
    reads: Arc<Mutex<R>>,
    connections: usize,
) -> io::Result<()> {
    serve_connections_with_state(
        listener,
        expected_gid,
        ServerState::read_only(reads),
        connections,
    )
    .await
}

async fn serve_connections_with_state<
    R: ApplicationReads + 'static,
    E: ApplicationExecution + 'static,
>(
    listener: UnixListener,
    expected_gid: u32,
    state: ServerState<R, E>,
    connections: usize,
) -> io::Result<()> {
    let permits = Arc::new(Semaphore::new(CONNECTIONS_MAX));
    let mut handlers = Vec::with_capacity(connections.min(CONNECTIONS_MAX));
    for _ in 0..connections {
        let (stream, _) = listener.accept().await?;
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let state = state.clone();
        handlers.push(tokio::spawn(async move {
            serve_connection_with_state(stream, expected_gid, state).await;
            drop(permit);
        }));
    }
    for handler in handlers {
        handler
            .await
            .map_err(|_| io::Error::other("connection task failed"))?;
    }
    drop(state.execution.lock().await);
    Ok(())
}

#[cfg(target_os = "linux")]
async fn serve_connections_forever<
    R: ApplicationReads + 'static,
    E: ApplicationExecution + 'static,
>(
    listener: UnixListener,
    expected_gid: u32,
    state: ServerState<R, E>,
) -> io::Result<()> {
    let permits = Arc::new(Semaphore::new(CONNECTIONS_MAX));
    loop {
        let (stream, _) = listener.accept().await?;
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let state = state.clone();
        tokio::spawn(async move {
            serve_connection_with_state(stream, expected_gid, state).await;
            drop(permit);
        });
    }
}

#[cfg(all(test, target_os = "linux"))]
async fn serve_connection<R: ApplicationReads + 'static>(
    stream: UnixStream,
    expected_gid: u32,
    reads: Arc<Mutex<R>>,
) {
    serve_connection_with_state(stream, expected_gid, ServerState::read_only(reads)).await;
}

async fn serve_connection_with_state<
    R: ApplicationReads + 'static,
    E: ApplicationExecution + 'static,
>(
    mut stream: UnixStream,
    expected_gid: u32,
    state: ServerState<R, E>,
) {
    let Ok(credentials) = stream.peer_cred() else {
        return;
    };
    if credentials.gid() != expected_gid {
        return;
    }
    let Ok(body) = read_request_with_deadline(&mut stream).await else {
        return;
    };
    let (response, class) = dispatch_with_state(&body, &state).await;
    if !response_length_allowed(response.len(), class) {
        return;
    }
    let _ = write_response_with_deadline(&mut stream, &response).await;
}

fn response_length_allowed(length: usize, class: ResponseClass) -> bool {
    let maximum = match class {
        ResponseClass::Ordinary => ORDINARY_RESPONSE_BYTES_MAX,
        ResponseClass::Receipt => RECEIPT_RESPONSE_BYTES_MAX,
    };
    length > 0 && length <= maximum && u32::try_from(length).is_ok()
}

async fn read_request_with_deadline(input: &mut (impl AsyncRead + Unpin)) -> io::Result<Vec<u8>> {
    timeout(IO_DEADLINE, read_request_frame(input))
        .await
        .map_err(|_| io::Error::other("request deadline exceeded"))?
}

async fn read_request_frame(input: &mut (impl AsyncRead + Unpin)) -> io::Result<Vec<u8>> {
    let mut prefix = [0_u8; 4];
    input.read_exact(&mut prefix).await?;
    let length = usize::try_from(u32::from_be_bytes(prefix))
        .map_err(|_| io::Error::other("invalid frame length"))?;
    if length == 0 || length > REQUEST_BYTES_MAX {
        return Err(io::Error::other("invalid frame length"));
    }
    let mut body = vec![0_u8; length];
    input.read_exact(&mut body).await?;
    let mut trailing = [0_u8; 1];
    if input.read(&mut trailing).await? != 0 {
        return Err(io::Error::other("trailing input"));
    }
    Ok(body)
}

async fn write_response_with_deadline(
    output: &mut (impl AsyncWrite + Unpin),
    body: &[u8],
) -> io::Result<()> {
    timeout(IO_DEADLINE, write_response_frame(output, body))
        .await
        .map_err(|_| io::Error::other("response deadline exceeded"))?
}

async fn write_response_frame(
    output: &mut (impl AsyncWrite + Unpin),
    body: &[u8],
) -> io::Result<()> {
    let length = u32::try_from(body.len()).map_err(|_| io::Error::other("response too large"))?;
    output.write_all(&length.to_be_bytes()).await?;
    output.write_all(body).await?;
    output.shutdown().await
}

async fn dispatch_with_state<R: ApplicationReads + 'static, E: ApplicationExecution + 'static>(
    bytes: &[u8],
    state: &ServerState<R, E>,
) -> (Vec<u8>, ResponseClass) {
    let Ok(request) = serde_json::from_slice::<Request>(bytes) else {
        return (invalid_request(), ResponseClass::Ordinary);
    };
    match request {
        Request::Status { operation_id } if valid_identity(&operation_id) => {
            let reads = state.reads.clone();
            let result = spawn_blocking(move || {
                reads
                    .lock()
                    .map_err(|_| ApplicationError::OperationFailure)?
                    .status_with_targets(&operation_id)
            })
            .await
            .unwrap_or(Err(ApplicationError::OperationFailure));
            (render_status_with_targets(result), ResponseClass::Ordinary)
        },
        Request::Receipt { operation_id } if valid_identity(&operation_id) => {
            let reads = state.reads.clone();
            let result = spawn_blocking(move || {
                reads
                    .lock()
                    .map_err(|_| ApplicationError::OperationFailure)?
                    .receipt(&operation_id)
            })
            .await
            .unwrap_or(Err(ApplicationError::OperationFailure));
            (render_receipt(result), ResponseClass::Receipt)
        },
        Request::Submit {
            operation_id,
            namespace,
            deployment,
            container,
            immutable_image_digest,
        } if valid_identity(&operation_id)
            && valid_dns_label(&namespace)
            && valid_dns_subdomain(&deployment)
            && valid_dns_label(&container)
            && valid_image(&immutable_image_digest) =>
        {
            let request = AgentRequest {
                operation_id,
                namespace,
                deployment,
                container,
                immutable_image_digest,
            };
            (
                render_submission(admit_submission(state, request)),
                ResponseClass::Ordinary,
            )
        },
        Request::Status { .. } | Request::Receipt { .. } | Request::Submit { .. } => {
            (invalid_request(), ResponseClass::Ordinary)
        },
    }
}

fn admit_submission<R, E>(state: &ServerState<R, E>, request: AgentRequest) -> SubmissionAdmission
where
    E: ApplicationExecution + 'static,
{
    let Ok(permit) = state.submission.clone().try_acquire_owned() else {
        return SubmissionAdmission::Busy;
    };
    let Ok(mut execution) = state.execution.clone().try_lock_owned() else {
        return SubmissionAdmission::OperationFailure;
    };
    if !execution.matches(&request) {
        return SubmissionAdmission::OperationFailure;
    }
    let task = tokio::spawn(async move {
        let result = execution.execute(request).await;
        drop(result);
        drop(execution);
        drop(permit);
    });
    drop(task);
    SubmissionAdmission::Accepted
}

fn render_submission(admission: SubmissionAdmission) -> Vec<u8> {
    match admission {
        SubmissionAdmission::Accepted => br#"{"status":"ACCEPTED"}"#.to_vec(),
        SubmissionAdmission::Busy => br#"{"status":"BUSY"}"#.to_vec(),
        SubmissionAdmission::OperationFailure => operation_failure(),
    }
}

fn invalid_request() -> Vec<u8> {
    br#"{"status":"ERROR","error_class":"invalid_request"}"#.to_vec()
}

fn operation_failure() -> Vec<u8> {
    br#"{"status":"ERROR","error_class":"operation_failure"}"#.to_vec()
}

fn render_status(result: &Result<SetDeploymentImageStatus, ApplicationError>) -> Vec<u8> {
    match result {
        Ok(SetDeploymentImageStatus::NotFound) => br#"{"status":"NOT_FOUND"}"#.to_vec(),
        Ok(SetDeploymentImageStatus::InProgress) => br#"{"status":"IN_PROGRESS"}"#.to_vec(),
        Ok(SetDeploymentImageStatus::Succeeded) => br#"{"status":"SUCCEEDED"}"#.to_vec(),
        Ok(SetDeploymentImageStatus::Failed) => br#"{"status":"FAILED"}"#.to_vec(),
        Ok(SetDeploymentImageStatus::Unknown) => br#"{"status":"UNKNOWN"}"#.to_vec(),
        Ok(SetDeploymentImageStatus::NotAttempted(rejection)) => format!(
            "{{\"status\":\"NOT_ATTEMPTED\",\"target_rejection\":\"{}\"}}",
            target_rejection(*rejection)
        )
        .into_bytes(),
        Err(_) => operation_failure(),
    }
}

fn render_status_with_targets(
    result: Result<(SetDeploymentImageStatus, kapsel::OperationTargets), ApplicationError>,
) -> Vec<u8> {
    let Ok((status, targets)) = result else {
        return operation_failure();
    };
    let mut output = render_status(&Ok(status));
    if status == SetDeploymentImageStatus::NotFound
        || targets == kapsel::OperationTargets::default()
    {
        return output;
    }
    let exact = |target: Option<kapsel::ApprovedTarget>| {
        target.map(|target| {
        serde_json::json!({ "uid": target.uid, "resource_version": target.resource_version })
    })
    };
    let fields = serde_json::json!({
        "approved_target": exact(targets.approved_target),
        "attempt_target": exact(targets.attempt_target),
        "observed_target": targets.observed_target.map(|target| serde_json::json!({
            "uid": target.uid, "resource_version": target.resource_version,
        })),
    })
    .to_string();
    // Both objects are locally rendered JSON. Join fields without parsing or changing values.
    output.pop();
    output.push(b',');
    output.extend_from_slice(&fields.as_bytes()[1..]);
    output
}

fn render_receipt(result: Result<SetDeploymentImageReceipt, ApplicationError>) -> Vec<u8> {
    match result {
        Ok(SetDeploymentImageReceipt::NotFound) => br#"{"status":"NOT_FOUND"}"#.to_vec(),
        Ok(SetDeploymentImageReceipt::NotReady) => br#"{"status":"NOT_READY"}"#.to_vec(),
        Ok(SetDeploymentImageReceipt::Ready { bytes, sha256 }) => {
            if !valid_sha256(&sha256) {
                return operation_failure();
            }
            let receipt_hex = lowercase_hex(&bytes);
            format!(
                concat!(
                    "{{\"status\":\"READY\",\"receipt_hex\":\"{}\",",
                    "\"receipt_sha256\":\"{}\"}}"
                ),
                receipt_hex, sha256
            )
            .into_bytes()
        },
        Err(_) => operation_failure(),
    }
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

const fn target_rejection(rejection: TargetRejection) -> &'static str {
    match rejection {
        TargetRejection::DeploymentNotFound => "DEPLOYMENT_NOT_FOUND",
        TargetRejection::ContainerNotFound => "CONTAINER_NOT_FOUND",
        TargetRejection::InvalidTarget => "INVALID_TARGET",
        TargetRejection::StaleApproval => "STALE_APPROVAL",
    }
}

fn valid_identity(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn valid_dns_label(value: &str) -> bool {
    (1..=63).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn valid_dns_subdomain(value: &str) -> bool {
    (1..=253).contains(&value.len()) && value.split('.').all(valid_dns_label)
}

fn valid_image(value: &str) -> bool {
    if value.len() > 512 || !value.is_ascii() {
        return false;
    }
    let Some((name, digest)) = value.split_once("@sha256:") else {
        return false;
    };
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        && name.split('/').all(|component| {
            !component.is_empty()
                && component.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'_' | b'-')
                })
                && component
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && component
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}

#[cfg(test)]
mod parser_tests {
    use super::*;

    #[test]
    fn exact_request_grammars_parse_and_hostile_shapes_fail() {
        let image = concat!(
            "registry.example/agent-api@sha256:",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        for valid in [
            String::from(r#"{"request":"get_set_deployment_image_status","operation_id":"op-1"}"#),
            String::from(r#"{"request":"get_set_deployment_image_receipt","operation_id":"op-1"}"#),
            format!(
                concat!(
                    "{{\"request\":\"submit_set_deployment_image\",",
                    "\"operation_id\":\"op-1\",\"namespace\":\"demo\",",
                    "\"deployment\":\"agent-api\",\"container\":\"api\",",
                    "\"immutable_image_digest\":\"{image}\"}}"
                ),
                image = image
            ),
        ] {
            assert!(serde_json::from_str::<Request>(&valid).is_ok());
        }
        for invalid in [
            concat!(
                r#"{"request":"get_set_deployment_image_status","operation_id":"a","#,
                r#""operation_id":"b"}"#
            ),
            r#"{"request":"get_set_deployment_image_status","operation_id":"a","unknown":1}"#,
            r#"{"request":"get_set_deployment_image_status","operation_id":null}"#,
            r#"{"request":"get_set_deployment_image_status","operation_id":1}"#,
            r#"{"request":"get_set_deployment_image_status","namespace":"demo"}"#,
            r#"{"request":"get_set_deployment_image_status"}"#,
            r#"{"request":"unknown","operation_id":"a"}"#,
            r#"{"request":"get_set_deployment_image_status"}{}"#,
            r"[]",
        ] {
            assert!(serde_json::from_str::<Request>(invalid).is_err());
        }
        assert!(serde_json::from_slice::<Request>(&[0xff]).is_err());
    }

    #[test]
    fn operation_and_submit_field_grammars_are_exact() {
        assert!(valid_identity("A._:-z0"));
        assert!(!valid_identity(""));
        assert!(!valid_identity("space value"));
        assert!(valid_dns_label("agent-api"));
        assert!(!valid_dns_label("Agent-api"));
        assert!(valid_dns_subdomain("agent-api.demo"));
        assert!(!valid_dns_subdomain("agent_api"));
        assert!(valid_image(concat!(
            "registry.example/agent-api@sha256:",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )));
        assert!(!valid_image("registry.example/agent-api:latest"));
    }

    #[test]
    fn every_status_and_receipt_projection_uses_only_the_fixed_vocabulary() {
        for (status, expected) in [
            (
                SetDeploymentImageStatus::NotFound,
                r#"{"status":"NOT_FOUND"}"#,
            ),
            (
                SetDeploymentImageStatus::InProgress,
                r#"{"status":"IN_PROGRESS"}"#,
            ),
            (
                SetDeploymentImageStatus::Succeeded,
                r#"{"status":"SUCCEEDED"}"#,
            ),
            (SetDeploymentImageStatus::Failed, r#"{"status":"FAILED"}"#),
            (SetDeploymentImageStatus::Unknown, r#"{"status":"UNKNOWN"}"#),
            (
                SetDeploymentImageStatus::NotAttempted(TargetRejection::DeploymentNotFound),
                r#"{"status":"NOT_ATTEMPTED","target_rejection":"DEPLOYMENT_NOT_FOUND"}"#,
            ),
            (
                SetDeploymentImageStatus::NotAttempted(TargetRejection::ContainerNotFound),
                r#"{"status":"NOT_ATTEMPTED","target_rejection":"CONTAINER_NOT_FOUND"}"#,
            ),
            (
                SetDeploymentImageStatus::NotAttempted(TargetRejection::InvalidTarget),
                r#"{"status":"NOT_ATTEMPTED","target_rejection":"INVALID_TARGET"}"#,
            ),
        ] {
            assert_eq!(render_status(&Ok(status)), expected.as_bytes());
        }
        assert_eq!(
            render_receipt(Ok(SetDeploymentImageReceipt::NotFound)),
            br#"{"status":"NOT_FOUND"}"#
        );
        assert_eq!(
            render_receipt(Ok(SetDeploymentImageReceipt::NotReady)),
            br#"{"status":"NOT_READY"}"#
        );
        let ready = render_receipt(Ok(SetDeploymentImageReceipt::Ready {
            bytes: vec![0x00, 0xab, 0xff],
            sha256: concat!(
                "0123456789abcdef0123456789abcdef",
                "0123456789abcdef0123456789abcdef"
            )
            .into(),
        }));
        assert_eq!(
            ready,
            concat!(
                "{\"status\":\"READY\",\"receipt_hex\":\"00abff\",\"receipt_sha256\":\"",
                r#"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}"#
            )
            .as_bytes()
        );
        assert_eq!(lowercase_hex(&[0x00, 0xab, 0xff]), "00abff");
        assert_eq!(
            render_submission(SubmissionAdmission::Accepted),
            br#"{"status":"ACCEPTED"}"#
        );
        assert_eq!(
            render_submission(SubmissionAdmission::Busy),
            br#"{"status":"BUSY"}"#
        );
        assert_eq!(
            render_submission(SubmissionAdmission::OperationFailure),
            br#"{"status":"ERROR","error_class":"operation_failure"}"#
        );
    }

    #[test]
    fn frame_reader_enforces_length_body_eof_and_trailing_bounds() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            for (bytes, accepted) in [
                ([1_u32.to_be_bytes().as_slice(), b"x"].concat(), true),
                ([0_u32.to_be_bytes().as_slice(), b""].concat(), false),
                (
                    [
                        u32::try_from(REQUEST_BYTES_MAX + 1)
                            .unwrap()
                            .to_be_bytes()
                            .as_slice(),
                        b"",
                    ]
                    .concat(),
                    false,
                ),
                ([2_u32.to_be_bytes().as_slice(), b"x"].concat(), false),
                ([1_u32.to_be_bytes().as_slice(), b"xy"].concat(), false),
            ] {
                let (mut client, mut server) = tokio::io::duplex(REQUEST_BYTES_MAX + 8);
                client.write_all(&bytes).await.unwrap();
                client.shutdown().await.unwrap();
                assert_eq!(read_request_frame(&mut server).await.is_ok(), accepted);
            }
            let body = vec![b'x'; REQUEST_BYTES_MAX];
            let (mut client, mut server) = tokio::io::duplex(REQUEST_BYTES_MAX + 8);
            client
                .write_all(&u32::try_from(body.len()).unwrap().to_be_bytes())
                .await
                .unwrap();
            client.write_all(&body).await.unwrap();
            client.shutdown().await.unwrap();
            assert_eq!(read_request_frame(&mut server).await.unwrap(), body);
        });
    }

    #[test]
    fn aggregate_read_and_write_deadlines_abandon_stalled_io() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (_idle_writer, mut idle_reader) = tokio::io::duplex(1);
            assert!(read_request_with_deadline(&mut idle_reader).await.is_err());

            let (mut stalled_writer, mut stalled_reader) = tokio::io::duplex(1);
            assert!(
                write_response_with_deadline(&mut stalled_writer, b"bounded")
                    .await
                    .is_err()
            );
            drop(stalled_writer);
            let mut partial = Vec::new();
            stalled_reader.read_to_end(&mut partial).await.unwrap();
            let complete = [7_u32.to_be_bytes().as_slice(), b"bounded"].concat();
            assert!(!partial.is_empty());
            assert_ne!(partial, complete);
        });
    }

    #[test]
    fn response_class_bounds_accept_exact_and_reject_one_above() {
        assert!(response_length_allowed(
            ORDINARY_RESPONSE_BYTES_MAX,
            ResponseClass::Ordinary
        ));
        assert!(!response_length_allowed(
            ORDINARY_RESPONSE_BYTES_MAX + 1,
            ResponseClass::Ordinary
        ));
        assert!(response_length_allowed(
            RECEIPT_RESPONSE_BYTES_MAX,
            ResponseClass::Receipt
        ));
        assert!(!response_length_allowed(
            RECEIPT_RESPONSE_BYTES_MAX + 1,
            ResponseClass::Receipt
        ));
    }
}

#[cfg(all(test, target_os = "linux"))]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    reason = "controlled Linux fixtures must fail the socket contract tests immediately"
)]
mod linux_tests {
    use std::{
        fs,
        os::unix::{fs::PermissionsExt as _, net::UnixStream as StdUnixStream},
        path::Path,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Condvar, Mutex,
        },
    };

    use ed25519_dalek::SigningKey;
    use kapsel::{
        provision_exact_grant, AgentRequest, AuthorizationTrust, ExactAuthorization,
        GrantProvisioning, OperatorConfiguration,
    };
    use tokio::{net::UnixStream, runtime::Builder};
    use tower_test::mock;

    use super::*;

    #[derive(Default)]
    struct TestReads {
        status_calls: Arc<AtomicUsize>,
        receipt_calls: Arc<AtomicUsize>,
    }

    impl ApplicationReads for TestReads {
        fn status(&self, operation_id: &str) -> Result<SetDeploymentImageStatus, ApplicationError> {
            self.status_calls.fetch_add(1, Ordering::Relaxed);
            match operation_id {
                "in-progress" => Ok(SetDeploymentImageStatus::InProgress),
                "deployment-rejection" => Ok(SetDeploymentImageStatus::NotAttempted(
                    TargetRejection::DeploymentNotFound,
                )),
                "container-rejection" => Ok(SetDeploymentImageStatus::NotAttempted(
                    TargetRejection::ContainerNotFound,
                )),
                "invalid-rejection" => Ok(SetDeploymentImageStatus::NotAttempted(
                    TargetRejection::InvalidTarget,
                )),
                "succeeded" => Ok(SetDeploymentImageStatus::Succeeded),
                "failed" => Ok(SetDeploymentImageStatus::Failed),
                "unknown" => Ok(SetDeploymentImageStatus::Unknown),
                "operation-error" => Err(ApplicationError::OperationFailure),
                _ => Ok(SetDeploymentImageStatus::NotFound),
            }
        }

        fn receipt(
            &self,
            operation_id: &str,
        ) -> Result<SetDeploymentImageReceipt, ApplicationError> {
            self.receipt_calls.fetch_add(1, Ordering::Relaxed);
            match operation_id {
                "not-ready" => Ok(SetDeploymentImageReceipt::NotReady),
                "ready" => Ok(SetDeploymentImageReceipt::Ready {
                    bytes: vec![0x00, 0xab, 0xff],
                    sha256: String::from(
                        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    ),
                }),
                "operation-error" => Err(ApplicationError::OperationFailure),
                _ => Ok(SetDeploymentImageReceipt::NotFound),
            }
        }
    }

    struct ReadyReads {
        bytes: Vec<u8>,
        sha256: String,
    }

    impl ApplicationReads for ReadyReads {
        fn status(
            &self,
            _operation_id: &str,
        ) -> Result<SetDeploymentImageStatus, ApplicationError> {
            Ok(SetDeploymentImageStatus::NotFound)
        }

        fn receipt(
            &self,
            _operation_id: &str,
        ) -> Result<SetDeploymentImageReceipt, ApplicationError> {
            Ok(SetDeploymentImageReceipt::Ready {
                bytes: self.bytes.clone(),
                sha256: self.sha256.clone(),
            })
        }
    }

    #[derive(Default)]
    struct BlockingState {
        started: bool,
        release: bool,
    }

    struct BlockingReads {
        gate: Arc<(Mutex<BlockingState>, Condvar)>,
        status_calls: Arc<AtomicUsize>,
    }

    impl ApplicationReads for BlockingReads {
        fn status(
            &self,
            _operation_id: &str,
        ) -> Result<SetDeploymentImageStatus, ApplicationError> {
            self.status_calls.fetch_add(1, Ordering::Relaxed);
            let (lock, condition) = &*self.gate;
            let mut state = lock.lock().unwrap();
            state.started = true;
            condition.notify_all();
            while !state.release {
                state = condition.wait(state).unwrap();
            }
            drop(state);
            Ok(SetDeploymentImageStatus::NotFound)
        }

        fn receipt(
            &self,
            _operation_id: &str,
        ) -> Result<SetDeploymentImageReceipt, ApplicationError> {
            Ok(SetDeploymentImageReceipt::NotFound)
        }
    }

    struct BlockingExecution {
        started: Arc<Semaphore>,
        release: Arc<Semaphore>,
    }

    impl ApplicationExecution for BlockingExecution {
        fn matches(&self, _request: &AgentRequest) -> bool {
            true
        }

        async fn execute(&mut self, _request: AgentRequest) -> Result<(), ApplicationError> {
            self.started.add_permits(1);
            self.release
                .acquire()
                .await
                .map_err(|_| ApplicationError::OperationFailure)?
                .forget();
            Ok(())
        }
    }

    struct CountingExecution<E> {
        inner: E,
        matches_calls: Arc<AtomicUsize>,
        execute_calls: Arc<AtomicUsize>,
    }

    impl<E: ApplicationExecution> ApplicationExecution for CountingExecution<E> {
        fn matches(&self, request: &AgentRequest) -> bool {
            self.matches_calls.fetch_add(1, Ordering::SeqCst);
            self.inner.matches(request)
        }

        async fn execute(&mut self, request: AgentRequest) -> Result<(), ApplicationError> {
            self.execute_calls.fetch_add(1, Ordering::SeqCst);
            self.inner.execute(request).await
        }
    }

    #[test]
    fn finite_server_waits_for_the_final_accepted_execution() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let root = std::env::temp_dir()
                .join(format!("kapseld-final-execution-{}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            private_directory(&root);
            let socket = root.join("kapseld.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            let started = Arc::new(Semaphore::new(0));
            let release = Arc::new(Semaphore::new(0));
            let state = ServerState::new(
                TestReads::default(),
                BlockingExecution {
                    started: started.clone(),
                    release: release.clone(),
                },
            );
            let mut client = UnixStream::connect(&socket).await.unwrap();
            let expected_gid = client.peer_cred().unwrap().gid();
            let mut server = tokio::spawn(serve_connections_with_state(
                listener,
                expected_gid,
                state,
                1,
            ));

            write_frame_and_close(&mut client, submit_request().as_bytes()).await;
            assert_eq!(read_frame(&mut client).await, br#"{"status":"ACCEPTED"}"#);
            started.acquire().await.unwrap().forget();
            assert!(timeout(Duration::from_millis(20), &mut server)
                .await
                .is_err());

            release.add_permits(1);
            server.await.unwrap().unwrap();
            fs::remove_dir_all(root).unwrap();
        });
    }

    #[test]
    fn authenticated_status_not_found_crosses_one_complete_frame() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let (client, server) = StdUnixStream::pair().unwrap();
            client.set_nonblocking(true).unwrap();
            server.set_nonblocking(true).unwrap();
            let mut client = UnixStream::from_std(client).unwrap();
            let server = UnixStream::from_std(server).unwrap();
            let calls = Arc::new(AtomicUsize::new(0));
            let reads = Arc::new(Mutex::new(TestReads {
                status_calls: calls.clone(),
                receipt_calls: Arc::new(AtomicUsize::new(0)),
            }));
            let expected_gid = server.peer_cred().unwrap().gid();
            let handler = tokio::spawn(serve_connection(server, expected_gid, reads));
            let request =
                br#"{"request":"get_set_deployment_image_status","operation_id":"missing"}"#;
            write_frame_and_close(&mut client, request).await;
            assert_eq!(read_frame(&mut client).await, br#"{"status":"NOT_FOUND"}"#);
            handler.await.unwrap();
            assert_eq!(calls.load(Ordering::Relaxed), 1);
        });
    }

    #[test]
    fn authenticated_status_and_receipt_projection_matrix_crosses_exact_frames() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let status_calls = Arc::new(AtomicUsize::new(0));
            let receipt_calls = Arc::new(AtomicUsize::new(0));
            let reads = Arc::new(Mutex::new(TestReads {
                status_calls: status_calls.clone(),
                receipt_calls: receipt_calls.clone(),
            }));
            for (operation_id, expected) in [
                ("not-found", r#"{"status":"NOT_FOUND"}"#),
                ("in-progress", r#"{"status":"IN_PROGRESS"}"#),
                (
                    "deployment-rejection",
                    r#"{"status":"NOT_ATTEMPTED","target_rejection":"DEPLOYMENT_NOT_FOUND"}"#,
                ),
                (
                    "container-rejection",
                    r#"{"status":"NOT_ATTEMPTED","target_rejection":"CONTAINER_NOT_FOUND"}"#,
                ),
                (
                    "invalid-rejection",
                    r#"{"status":"NOT_ATTEMPTED","target_rejection":"INVALID_TARGET"}"#,
                ),
                ("succeeded", r#"{"status":"SUCCEEDED"}"#),
                ("failed", r#"{"status":"FAILED"}"#),
                ("unknown", r#"{"status":"UNKNOWN"}"#),
                (
                    "operation-error",
                    r#"{"status":"ERROR","error_class":"operation_failure"}"#,
                ),
            ] {
                let request = format!(
                    concat!(
                        "{{\"request\":\"get_set_deployment_image_status\",",
                        "\"operation_id\":\"{operation_id}\"}}"
                    ),
                    operation_id = operation_id
                );
                assert_socket_response(reads.clone(), request.as_bytes(), expected.as_bytes())
                    .await;
            }
            for (operation_id, expected) in [
                ("not-found", r#"{"status":"NOT_FOUND"}"#),
                ("not-ready", r#"{"status":"NOT_READY"}"#),
                (
                    "ready",
                    concat!(
                        "{\"status\":\"READY\",\"receipt_hex\":\"00abff\",",
                        "\"receipt_sha256\":\"",
                        r#"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}"#
                    ),
                ),
                (
                    "operation-error",
                    r#"{"status":"ERROR","error_class":"operation_failure"}"#,
                ),
            ] {
                let request = format!(
                    concat!(
                        "{{\"request\":\"get_set_deployment_image_receipt\",",
                        "\"operation_id\":\"{operation_id}\"}}"
                    ),
                    operation_id = operation_id
                );
                assert_socket_response(reads.clone(), request.as_bytes(), expected.as_bytes())
                    .await;
            }
            assert_eq!(status_calls.load(Ordering::Relaxed), 9);
            assert_eq!(receipt_calls.load(Ordering::Relaxed), 4);
        });
    }

    #[test]
    fn over_limit_receipt_projection_closes_without_disclosure() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let (mut client, server) = socket_pair();
            let gid = server.peer_cred().unwrap().gid();
            let reads = Arc::new(Mutex::new(ReadyReads {
                bytes: vec![0x55; 20 * 1024],
                sha256: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into(),
            }));
            let handler = tokio::spawn(serve_connection(server, gid, reads));
            write_frame_and_close(
                &mut client,
                br#"{"request":"get_set_deployment_image_receipt","operation_id":"receipt-op"}"#,
            )
            .await;
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            assert!(response.is_empty());
            handler.await.unwrap();
        });
    }

    #[test]
    fn socket_status_and_receipt_compose_real_application_reads_without_kubernetes() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let root =
                std::env::temp_dir().join(format!("kapseld-application-{}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            private_directory(&root);
            private_directory(&root.join("receipts"));
            let (application, mut kubernetes) = application(&root);
            let reads = Arc::new(Mutex::new(application));
            for (request, expected) in [
                (
                    concat!(
                        r#"{"request":"get_set_deployment_image_status","#,
                        r#""operation_id":"socket-op-1"}"#
                    )
                    .as_bytes(),
                    br#"{"status":"NOT_FOUND"}"#.as_slice(),
                ),
                (
                    concat!(
                        r#"{"request":"get_set_deployment_image_receipt","#,
                        r#""operation_id":"socket-op-1"}"#
                    )
                    .as_bytes(),
                    br#"{"status":"NOT_FOUND"}"#.as_slice(),
                ),
            ] {
                let (mut client, server) = socket_pair();
                let gid = server.peer_cred().unwrap().gid();
                let handler = tokio::spawn(serve_connection(server, gid, reads.clone()));
                write_frame_and_close(&mut client, request).await;
                assert_eq!(read_frame(&mut client).await, expected);
                handler.await.unwrap();
            }
            assert!(
                timeout(Duration::from_millis(10), kubernetes.next_request())
                    .await
                    .is_err()
            );
            drop(reads);
            fs::remove_dir_all(root).unwrap();
        });
    }

    #[test]
    fn authenticated_submit_accepts_one_real_application_execution() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let root = std::env::temp_dir()
                .join(format!("kapseld-accepted-execution-{}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            private_directory(&root);
            private_directory(&root.join("receipts"));
            let (projection, execution, mut kubernetes) = applications(&root);
            let state = ServerState::new(projection, execution);

            let (mut client, server) = socket_pair();
            let gid = server.peer_cred().unwrap().gid();
            let handler = tokio::spawn(serve_connection_with_state(server, gid, state.clone()));
            write_frame_and_close(&mut client, submit_request().as_bytes()).await;
            assert_eq!(read_frame(&mut client).await, br#"{"status":"ACCEPTED"}"#);
            handler.await.unwrap();

            let (_, response) = timeout(Duration::from_secs(1), kubernetes.next_request())
                .await
                .unwrap()
                .unwrap();
            response.send_response(
                http::Response::builder()
                    .status(http::StatusCode::NOT_FOUND)
                    .body(kube::client::Body::from(Vec::<u8>::new()))
                    .unwrap(),
            );

            wait_for_not_attempted(&state, gid).await;

            drop(state);
            fs::remove_dir_all(root).unwrap();
        });
    }

    #[test]
    fn overlapping_submit_is_busy_without_a_second_application_attempt() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let root = std::env::temp_dir().join(format!("kapseld-busy-{}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            private_directory(&root);
            private_directory(&root.join("receipts"));
            let (projection, execution, mut kubernetes) = applications(&root);
            let matches_calls = Arc::new(AtomicUsize::new(0));
            let execute_calls = Arc::new(AtomicUsize::new(0));
            let state = ServerState::new(
                projection,
                CountingExecution {
                    inner: execution,
                    matches_calls: matches_calls.clone(),
                    execute_calls: execute_calls.clone(),
                },
            );

            let (mut first_client, first_server) = socket_pair();
            let gid = first_server.peer_cred().unwrap().gid();
            let first_handler = tokio::spawn(serve_connection_with_state(
                first_server,
                gid,
                state.clone(),
            ));
            write_frame_and_close(&mut first_client, submit_request().as_bytes()).await;
            assert_eq!(
                read_frame(&mut first_client).await,
                br#"{"status":"ACCEPTED"}"#
            );
            first_handler.await.unwrap();
            let (_, provider_response) = timeout(Duration::from_secs(1), kubernetes.next_request())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(matches_calls.load(Ordering::SeqCst), 1);
            assert_eq!(execute_calls.load(Ordering::SeqCst), 1);

            let (mut second_client, second_server) = socket_pair();
            let second_handler = tokio::spawn(serve_connection_with_state(
                second_server,
                gid,
                state.clone(),
            ));
            write_frame_and_close(&mut second_client, submit_request().as_bytes()).await;
            assert_eq!(
                read_frame(&mut second_client).await,
                br#"{"status":"BUSY"}"#
            );
            second_handler.await.unwrap();
            assert_eq!(matches_calls.load(Ordering::SeqCst), 1);
            assert_eq!(execute_calls.load(Ordering::SeqCst), 1);
            assert!(
                timeout(Duration::from_millis(10), kubernetes.next_request())
                    .await
                    .is_err()
            );

            send_not_found(provider_response);
            wait_for_not_attempted(&state, gid).await;
            drop(state);
            fs::remove_dir_all(root).unwrap();
        });
    }

    #[test]
    fn reconnect_status_remains_available_while_execution_waits_on_provider() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let root = std::env::temp_dir()
                .join(format!("kapseld-concurrent-status-{}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            private_directory(&root);
            private_directory(&root.join("receipts"));
            let (projection, execution, mut kubernetes) = applications(&root);
            let state = ServerState::new(projection, execution);

            let (mut submit_client, submit_server) = socket_pair();
            let gid = submit_server.peer_cred().unwrap().gid();
            let submit_handler = tokio::spawn(serve_connection_with_state(
                submit_server,
                gid,
                state.clone(),
            ));
            write_frame_and_close(&mut submit_client, submit_request().as_bytes()).await;
            assert_eq!(
                read_frame(&mut submit_client).await,
                br#"{"status":"ACCEPTED"}"#
            );
            submit_handler.await.unwrap();
            let (_, provider_response) = timeout(Duration::from_secs(1), kubernetes.next_request())
                .await
                .unwrap()
                .unwrap();

            let (mut status_client, status_server) = socket_pair();
            let status_handler = tokio::spawn(serve_connection_with_state(
                status_server,
                gid,
                state.clone(),
            ));
            write_frame_and_close(
                &mut status_client,
                br#"{"request":"get_set_deployment_image_status","operation_id":"socket-op-1"}"#,
            )
            .await;
            assert_eq!(
                timeout(Duration::from_secs(1), read_frame(&mut status_client))
                    .await
                    .unwrap(),
                br#"{"status":"IN_PROGRESS"}"#
            );
            status_handler.await.unwrap();

            send_not_found(provider_response);
            wait_for_not_attempted(&state, gid).await;
            drop(state);
            fs::remove_dir_all(root).unwrap();
        });
    }

    #[test]
    fn client_disconnect_before_response_does_not_cancel_execution() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let root =
                std::env::temp_dir().join(format!("kapseld-disconnect-{}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            private_directory(&root);
            private_directory(&root.join("receipts"));
            let (projection, execution, mut kubernetes) = applications(&root);
            let state = ServerState::new(projection, execution);

            let (mut submit_client, submit_server) = socket_pair();
            let gid = submit_server.peer_cred().unwrap().gid();
            let submit_handler = tokio::spawn(serve_connection_with_state(
                submit_server,
                gid,
                state.clone(),
            ));
            write_frame_and_close(&mut submit_client, submit_request().as_bytes()).await;
            drop(submit_client);
            submit_handler.await.unwrap();

            let (_, provider_response) = timeout(Duration::from_secs(1), kubernetes.next_request())
                .await
                .unwrap()
                .unwrap();
            send_not_found(provider_response);
            wait_for_not_attempted(&state, gid).await;

            drop(state);
            fs::remove_dir_all(root).unwrap();
        });
    }

    #[test]
    fn retry_race_after_apply_started_keeps_one_provider_mutation() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let root = std::env::temp_dir().join(format!("kapseld-replay-{}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            private_directory(&root);
            private_directory(&root.join("receipts"));
            let (projection, execution, mut kubernetes) = applications(&root);
            let state = ServerState::new(projection, execution);
            let gid = submit_and_read(&state).await.0;

            let (target_request, target_response) =
                timeout(Duration::from_secs(1), kubernetes.next_request())
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(target_request.method(), http::Method::GET);
            send_deployment(target_response, &deployment("1", 1, false));

            let (apply_request, apply_response) =
                timeout(Duration::from_secs(1), kubernetes.next_request())
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(apply_request.method(), http::Method::PATCH);
            send_deployment(apply_response, &deployment("2", 2, false));

            let (observation_request, observation_response) =
                timeout(Duration::from_secs(1), kubernetes.next_request())
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(observation_request.method(), http::Method::GET);
            let (_, competing_response) = submit_and_read(&state).await;
            assert_eq!(competing_response, br#"{"status":"BUSY"}"#);
            assert!(
                timeout(Duration::from_millis(10), kubernetes.next_request())
                    .await
                    .is_err()
            );
            send_deployment(observation_response, &deployment("3", 2, true));
            wait_for_status(&state, gid, br#"{"status":"SUCCEEDED"}"#).await;

            let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
            loop {
                let (_, replay_response) = submit_and_read(&state).await;
                if replay_response == br#"{"status":"ACCEPTED"}"# {
                    break;
                }
                assert_eq!(replay_response, br#"{"status":"BUSY"}"#);
                assert!(tokio::time::Instant::now() < deadline);
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            while state.submission.available_permits() == 0 {
                assert!(tokio::time::Instant::now() < deadline);
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(
                timeout(Duration::from_millis(20), kubernetes.next_request())
                    .await
                    .is_err()
            );

            drop(state);
            fs::remove_dir_all(root).unwrap();
        });
    }

    #[test]
    fn grant_mismatched_submit_is_bounded_without_execution() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let root =
                std::env::temp_dir().join(format!("kapseld-mismatch-{}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            private_directory(&root);
            private_directory(&root.join("receipts"));
            let (projection, execution, mut kubernetes) = applications(&root);
            let state = ServerState::new(projection, execution);

            let (mut client, server) = socket_pair();
            let gid = server.peer_cred().unwrap().gid();
            let handler = tokio::spawn(serve_connection_with_state(server, gid, state.clone()));
            let mismatched =
                submit_request().replace("\"container\":\"api\"", "\"container\":\"other\"");
            write_frame_and_close(&mut client, mismatched.as_bytes()).await;
            assert_eq!(
                read_frame(&mut client).await,
                br#"{"status":"ERROR","error_class":"operation_failure"}"#
            );
            handler.await.unwrap();
            assert!(
                timeout(Duration::from_millis(10), kubernetes.next_request())
                    .await
                    .is_err()
            );

            drop(state);
            fs::remove_dir_all(root).unwrap();
        });
    }

    #[test]
    fn peer_denial_happens_before_body_read_or_application_access() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let (mut client, server) = socket_pair();
            let calls = Arc::new(AtomicUsize::new(0));
            let reads = Arc::new(Mutex::new(TestReads {
                status_calls: calls.clone(),
                receipt_calls: Arc::new(AtomicUsize::new(0)),
            }));
            let denied_gid = server.peer_cred().unwrap().gid().wrapping_add(1);
            let handler = tokio::spawn(serve_connection(server, denied_gid, reads));
            let _ = client.write_all(b"SECRET_UNPARSED_BODY").await;
            let mut response = Vec::new();
            match client.read_to_end(&mut response).await {
                Ok(_) => {},
                Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {},
                Err(error) => panic!("unexpected denied-peer read failure: {error}"),
            }
            handler.await.unwrap();
            assert!(response.is_empty());
            assert_eq!(calls.load(Ordering::Relaxed), 0);
        });
    }

    #[test]
    fn incomplete_zero_oversized_and_trailing_frames_close_without_application_access() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let calls = Arc::new(AtomicUsize::new(0));
            let reads = Arc::new(Mutex::new(TestReads {
                status_calls: calls.clone(),
                receipt_calls: Arc::new(AtomicUsize::new(0)),
            }));
            for bytes in [
                vec![0_u8, 0, 0],
                0_u32.to_be_bytes().to_vec(),
                u32::try_from(REQUEST_BYTES_MAX + 1)
                    .unwrap()
                    .to_be_bytes()
                    .to_vec(),
                [1_u32.to_be_bytes().as_slice(), b""].concat(),
                [1_u32.to_be_bytes().as_slice(), b"xy"].concat(),
            ] {
                let (mut client, server) = socket_pair();
                let gid = server.peer_cred().unwrap().gid();
                let handler = tokio::spawn(serve_connection(server, gid, reads.clone()));
                client.write_all(&bytes).await.unwrap();
                client.shutdown().await.unwrap();
                let mut response = Vec::new();
                client.read_to_end(&mut response).await.unwrap();
                handler.await.unwrap();
                assert!(response.is_empty());
            }
            assert_eq!(calls.load(Ordering::Relaxed), 0);
        });
    }

    #[test]
    fn missing_write_half_close_expires_under_the_complete_frame_deadline() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let (mut client, server) = socket_pair();
            let gid = server.peer_cred().unwrap().gid();
            let calls = Arc::new(AtomicUsize::new(0));
            let reads = Arc::new(Mutex::new(TestReads {
                status_calls: calls.clone(),
                receipt_calls: Arc::new(AtomicUsize::new(0)),
            }));
            let handler = tokio::spawn(serve_connection(server, gid, reads));
            let request = br#"{"request":"get_set_deployment_image_status","operation_id":"slow"}"#;
            client
                .write_all(&u32::try_from(request.len()).unwrap().to_be_bytes())
                .await
                .unwrap();
            client.write_all(request).await.unwrap();
            tokio::time::sleep(IO_DEADLINE + Duration::from_millis(50)).await;
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            handler.await.unwrap();
            assert!(response.is_empty());
            assert_eq!(calls.load(Ordering::Relaxed), 0);
        });
    }

    #[test]
    fn staged_prefix_body_and_eof_progress_share_one_aggregate_deadline() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let (mut client, server) = socket_pair();
            let gid = server.peer_cred().unwrap().gid();
            let calls = Arc::new(AtomicUsize::new(0));
            let reads = Arc::new(Mutex::new(TestReads {
                status_calls: calls.clone(),
                receipt_calls: Arc::new(AtomicUsize::new(0)),
            }));
            let handler = tokio::spawn(serve_connection(server, gid, reads));
            let request = br#"{"request":"get_set_deployment_image_status","operation_id":"slow"}"#;
            let prefix = u32::try_from(request.len()).unwrap().to_be_bytes();
            client.write_all(&prefix[..2]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(500)).await;
            client.write_all(&prefix[2..]).await.unwrap();
            client
                .write_all(&request[..request.len() / 2])
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(750)).await;
            client
                .write_all(&request[request.len() / 2..])
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
            let _ = client.shutdown().await;
            let mut response = Vec::new();
            match client.read_to_end(&mut response).await {
                Ok(_) => {},
                Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {},
                Err(error) => panic!("unexpected staged-frame read failure: {error}"),
            }
            handler.await.unwrap();
            assert!(response.is_empty());
            assert_eq!(calls.load(Ordering::Relaxed), 0);
        });
    }

    #[test]
    fn blocked_application_read_does_not_prevent_another_frame_deadline() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let gate = Arc::new((Mutex::new(BlockingState::default()), Condvar::new()));
            let calls = Arc::new(AtomicUsize::new(0));
            let reads = Arc::new(Mutex::new(BlockingReads {
                gate: gate.clone(),
                status_calls: calls.clone(),
            }));

            let (mut blocked_client, blocked_server) = socket_pair();
            let gid = blocked_server.peer_cred().unwrap().gid();
            let blocked_handler =
                tokio::spawn(serve_connection(blocked_server, gid, reads.clone()));
            write_frame_and_close(
                &mut blocked_client,
                br#"{"request":"get_set_deployment_image_status","operation_id":"blocked"}"#,
            )
            .await;
            let started_deadline = tokio::time::Instant::now() + Duration::from_secs(1);
            loop {
                if gate.0.lock().unwrap().started {
                    break;
                }
                assert!(tokio::time::Instant::now() < started_deadline);
                tokio::time::sleep(Duration::from_millis(10)).await;
            }

            let (mut idle_client, idle_server) = socket_pair();
            let idle_handler = tokio::spawn(serve_connection(idle_server, gid, reads));
            idle_client.write_all(&[0_u8]).await.unwrap();
            let mut idle_response = Vec::new();
            let idle_result = timeout(
                IO_DEADLINE + Duration::from_millis(500),
                idle_client.read_to_end(&mut idle_response),
            )
            .await
            .unwrap();
            assert!(
                idle_result.is_ok()
                    || idle_result.unwrap_err().kind() == io::ErrorKind::ConnectionReset
            );
            idle_handler.await.unwrap();
            assert!(idle_response.is_empty());
            assert_eq!(calls.load(Ordering::Relaxed), 1);

            {
                let mut state = gate.0.lock().unwrap();
                state.release = true;
                drop(state);
                gate.1.notify_all();
            }
            assert_eq!(
                read_frame(&mut blocked_client).await,
                br#"{"status":"NOT_FOUND"}"#
            );
            blocked_handler.await.unwrap();
        });
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one table keeps the authenticated hostile-request matrix explicit"
    )]
    fn authenticated_hostile_json_and_submit_matrix_has_no_application_effect() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let status_calls = Arc::new(AtomicUsize::new(0));
            let receipt_calls = Arc::new(AtomicUsize::new(0));
            let reads = Arc::new(Mutex::new(TestReads {
                status_calls: status_calls.clone(),
                receipt_calls: receipt_calls.clone(),
            }));
            let invalid = br#"{"status":"ERROR","error_class":"invalid_request"}"#;
            let immutable_image = concat!(
                "registry.example/agent-api@sha256:",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            );
            for request in [
                vec![0xff],
                b"{".to_vec(),
                concat!(
                    r#"{"request":"get_set_deployment_image_status","#,
                    r#""operation_id":"a"}{}"#
                )
                .as_bytes()
                .to_vec(),
                concat!(
                    r#"{"request":"get_set_deployment_image_status","operation_id":"a","#,
                    r#""operation_id":"SECRET_DUPLICATE"}"#
                )
                .as_bytes()
                .to_vec(),
                concat!(
                    r#"{"request":"get_set_deployment_image_status","#,
                    r#""operation_id":"a","unknown":1}"#
                )
                .as_bytes()
                .to_vec(),
                br#"{"request":"get_set_deployment_image_status"}"#.to_vec(),
                concat!(
                    r#"{"request":"get_set_deployment_image_status","#,
                    r#""operation_id":null}"#
                )
                .as_bytes()
                .to_vec(),
                concat!(
                    r#"{"request":"get_set_deployment_image_status","#,
                    r#""operation_id":1}"#
                )
                .as_bytes()
                .to_vec(),
                concat!(
                    r#"{"request":"get_set_deployment_image_status","operation_id":"a","#,
                    r#""namespace":"demo"}"#
                )
                .as_bytes()
                .to_vec(),
                concat!(
                    r#"{"request":"get_set_deployment_image_receipt","operation_id":"a","#,
                    r#""container":"api"}"#
                )
                .as_bytes()
                .to_vec(),
                br#"{"request":"unknown","operation_id":"a"}"#.to_vec(),
                format!(
                    concat!(
                        r#"{{"request":"submit_set_deployment_image","operation_id":"op-1","#,
                        r#""deployment":"agent-api","container":"api","#,
                        r#""immutable_image_digest":"{immutable_image}"}}"#
                    ),
                    immutable_image = immutable_image
                )
                .into_bytes(),
                format!(
                    concat!(
                        r#"{{"request":"submit_set_deployment_image","operation_id":"op-1","#,
                        r#""namespace":null,"deployment":"agent-api","container":"api","#,
                        r#""immutable_image_digest":"{immutable_image}"}}"#
                    ),
                    immutable_image = immutable_image
                )
                .into_bytes(),
                concat!(
                    r#"{"request":"submit_set_deployment_image","operation_id":"op-1","#,
                    r#""namespace":"demo","deployment":"agent-api","container":"api","#,
                    r#""immutable_image_digest":"registry.example/agent-api:latest"}"#
                )
                .as_bytes()
                .to_vec(),
                format!(
                    concat!(
                        r#"{{"request":"submit_set_deployment_image","operation_id":"op-1","#,
                        r#""namespace":"demo","deployment":"agent-api","container":"api","#,
                        r#""immutable_image_digest":"{immutable_image}","retry":true}}"#
                    ),
                    immutable_image = immutable_image
                )
                .into_bytes(),
            ] {
                assert_socket_response(reads.clone(), &request, invalid).await;
            }
            let submit = format!(
                concat!(
                    r#"{{"request":"submit_set_deployment_image","operation_id":"op-1","#,
                    r#""namespace":"demo","deployment":"agent-api","container":"api","#,
                    r#""immutable_image_digest":"{immutable_image}"}}"#
                ),
                immutable_image = immutable_image
            );
            assert_socket_response(
                reads,
                submit.as_bytes(),
                br#"{"status":"ERROR","error_class":"operation_failure"}"#,
            )
            .await;
            assert_eq!(status_calls.load(Ordering::Relaxed), 0);
            assert_eq!(receipt_calls.load(Ordering::Relaxed), 0);
        });
    }

    #[test]
    fn saturation_closes_ninth_and_new_connection_succeeds_after_permit_recovery() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let root = std::env::temp_dir().join(format!("kapseld-cap-{}", std::process::id()));
            let _ = std::fs::remove_file(&root);
            let listener = UnixListener::bind(&root).unwrap();
            let gid = socket_pair().1.peer_cred().unwrap().gid();
            let calls = Arc::new(AtomicUsize::new(0));
            let reads = Arc::new(Mutex::new(TestReads {
                status_calls: calls.clone(),
                receipt_calls: Arc::new(AtomicUsize::new(0)),
            }));
            let server = tokio::spawn(serve_connections(listener, gid, reads, 10));
            let mut admitted = Vec::new();
            for _ in 0..CONNECTIONS_MAX {
                admitted.push(UnixStream::connect(&root).await.unwrap());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;

            let mut ninth = UnixStream::connect(&root).await.unwrap();
            let mut denied = Vec::new();
            let denied_result = timeout(Duration::from_millis(500), ninth.read_to_end(&mut denied))
                .await
                .unwrap();
            assert!(
                denied_result.is_ok()
                    || denied_result.unwrap_err().kind() == io::ErrorKind::ConnectionReset
            );
            assert!(denied.is_empty());
            assert_eq!(calls.load(Ordering::Relaxed), 0);

            drop(admitted.remove(0));
            let mut tenth = UnixStream::connect(&root).await.unwrap();
            write_frame_and_close(
                &mut tenth,
                br#"{"request":"get_set_deployment_image_status","operation_id":"cap-op"}"#,
            )
            .await;
            assert_eq!(read_frame(&mut tenth).await, br#"{"status":"NOT_FOUND"}"#);
            assert_eq!(calls.load(Ordering::Relaxed), 1);
            drop(admitted);
            server.await.unwrap().unwrap();
            std::fs::remove_file(root).unwrap();
        });
    }

    async fn assert_socket_response(reads: Arc<Mutex<TestReads>>, request: &[u8], expected: &[u8]) {
        let (mut client, server) = socket_pair();
        let gid = server.peer_cred().unwrap().gid();
        let handler = tokio::spawn(serve_connection(server, gid, reads));
        write_frame_and_close(&mut client, request).await;
        assert_eq!(read_frame(&mut client).await, expected);
        handler.await.unwrap();
    }

    fn application(
        root: &Path,
    ) -> (
        Application,
        mock::Handle<http::Request<kube::client::Body>, http::Response<kube::client::Body>>,
    ) {
        let (projection, _execution, handle) = applications(root);
        (projection, handle)
    }

    fn applications(
        root: &Path,
    ) -> (
        Application,
        Application,
        mock::Handle<http::Request<kube::client::Body>, http::Response<kube::client::Body>>,
    ) {
        let seed = [41_u8; 32];
        let key = SigningKey::from_bytes(&seed);
        let authorization = ExactAuthorization {
            approved_target: None,
            authorization_id: "socket-auth-1".into(),
            operation_id: "socket-op-1".into(),
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
            signing_seed: &seed,
            signing_key_id: "socket-authorization-key",
        })
        .unwrap();
        let (service, handle) =
            mock::pair::<http::Request<kube::client::Body>, http::Response<kube::client::Body>>();
        let client = kube::Client::new(service, "demo");
        let configuration = |client| OperatorConfiguration {
            journal_path: fs::canonicalize(root).unwrap().join("journal.sqlite3"),
            receipt_output_directory: fs::canonicalize(root.join("receipts")).unwrap(),
            authorization_trust: AuthorizationTrust {
                key_id: "socket-authorization-key".into(),
                public_key: key.verifying_key().to_bytes(),
            },
            signed_authorization_grant: grant.clone(),
            kubernetes_client: client,
            receipt_signing_seed: [42_u8; 32],
            receipt_signing_key_id: "socket-receipt-key".into(),
        };
        (
            Application::open(configuration(client.clone())).unwrap(),
            Application::open(configuration(client)).unwrap(),
            handle,
        )
    }

    async fn wait_for_not_attempted<E: ApplicationExecution + 'static>(
        state: &ServerState<Application, E>,
        gid: u32,
    ) {
        wait_for_status(
            state,
            gid,
            br#"{"status":"NOT_ATTEMPTED","target_rejection":"DEPLOYMENT_NOT_FOUND"}"#,
        )
        .await;
    }

    fn every_expected_field_matches(observed: &serde_json::Value, expected: &[u8]) -> bool {
        let Ok(expected) = serde_json::from_slice::<serde_json::Value>(expected) else {
            return false;
        };
        let (Some(observed), Some(expected)) = (observed.as_object(), expected.as_object()) else {
            return false;
        };
        expected
            .iter()
            .all(|(field, value)| observed.get(field) == Some(value))
    }

    async fn wait_for_status<E: ApplicationExecution + 'static>(
        state: &ServerState<Application, E>,
        gid: u32,
        expected: &[u8],
    ) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        loop {
            let (mut client, server) = socket_pair();
            let handler = tokio::spawn(serve_connection_with_state(server, gid, state.clone()));
            write_frame_and_close(
                &mut client,
                br#"{"request":"get_set_deployment_image_status","operation_id":"socket-op-1"}"#,
            )
            .await;
            let response = read_frame(&mut client).await;
            handler.await.unwrap();
            let observed: serde_json::Value = serde_json::from_slice(&response).unwrap();
            if every_expected_field_matches(&observed, expected) {
                break;
            }
            assert_eq!(
                observed.get("status"),
                Some(&serde_json::json!("IN_PROGRESS"))
            );
            assert!(tokio::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn submit_and_read<E: ApplicationExecution + 'static>(
        state: &ServerState<Application, E>,
    ) -> (u32, Vec<u8>) {
        let (mut client, server) = socket_pair();
        let gid = server.peer_cred().unwrap().gid();
        let handler = tokio::spawn(serve_connection_with_state(server, gid, state.clone()));
        write_frame_and_close(&mut client, submit_request().as_bytes()).await;
        let response = read_frame(&mut client).await;
        handler.await.unwrap();
        (gid, response)
    }

    fn send_not_found(
        response: tower_test::mock::SendResponse<http::Response<kube::client::Body>>,
    ) {
        response.send_response(
            http::Response::builder()
                .status(http::StatusCode::NOT_FOUND)
                .body(kube::client::Body::from(Vec::<u8>::new()))
                .unwrap(),
        );
    }

    fn send_deployment(
        response: tower_test::mock::SendResponse<http::Response<kube::client::Body>>,
        body: &serde_json::Value,
    ) {
        response.send_response(
            http::Response::builder()
                .status(http::StatusCode::OK)
                .body(kube::client::Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        );
    }

    fn deployment(resource_version: &str, generation: i64, observed: bool) -> serde_json::Value {
        let old_image = concat!(
            "registry.example/agent-api@sha256:",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
        let image = concat!(
            "registry.example/agent-api@sha256:",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        let mut deployment = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "agent-api",
                "namespace": "demo",
                "uid": "uid-1",
                "resourceVersion": resource_version,
                "generation": generation
            },
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": {"app": "agent-api"}},
                "template": {
                    "metadata": {"labels": {"app": "agent-api"}},
                    "spec": {"containers": [{
                        "name": "api",
                        "image": if generation == 1 { old_image } else { image }
                    }]}
                }
            },
            "status": {"observedGeneration": generation}
        });
        if observed {
            deployment["metadata"]["annotations"] = serde_json::json!({
                "kapsel.dev/kap0038-operation-id": "socket-op-1"
            });
            deployment["status"] = serde_json::json!({
                "observedGeneration": 2,
                "updatedReplicas": 1,
                "availableReplicas": 1,
                "unavailableReplicas": 0,
                "conditions": [{
                    "type": "Available",
                    "status": "True",
                    "reason": "MinimumReplicasAvailable"
                }]
            });
        }
        deployment
    }

    fn submit_request() -> String {
        let request = submit_agent_request();
        format!(
            concat!(
                "{{\"request\":\"submit_set_deployment_image\",",
                "\"operation_id\":\"{}\",\"namespace\":\"{}\",",
                "\"deployment\":\"{}\",\"container\":\"{}\",",
                "\"immutable_image_digest\":\"{}\"}}"
            ),
            request.operation_id,
            request.namespace,
            request.deployment,
            request.container,
            request.immutable_image_digest
        )
    }

    fn submit_agent_request() -> AgentRequest {
        AgentRequest {
            operation_id: "socket-op-1".into(),
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

    fn private_directory(path: &Path) {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn socket_pair() -> (UnixStream, UnixStream) {
        let (client, server) = StdUnixStream::pair().unwrap();
        client.set_nonblocking(true).unwrap();
        server.set_nonblocking(true).unwrap();
        (
            UnixStream::from_std(client).unwrap(),
            UnixStream::from_std(server).unwrap(),
        )
    }

    async fn write_frame_and_close(stream: &mut UnixStream, body: &[u8]) {
        stream
            .write_all(&u32::try_from(body.len()).unwrap().to_be_bytes())
            .await
            .unwrap();
        stream.write_all(body).await.unwrap();
        stream.shutdown().await.unwrap();
    }

    async fn read_frame(stream: &mut UnixStream) -> Vec<u8> {
        let mut prefix = [0_u8; 4];
        stream.read_exact(&mut prefix).await.unwrap();
        let mut body = vec![0_u8; u32::from_be_bytes(prefix) as usize];
        stream.read_exact(&mut body).await.unwrap();
        body
    }
}
