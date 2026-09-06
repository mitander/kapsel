//! Fixed parser and composition for the evaluator command evaluator commands.

use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
};

use kapsel::{
    inspect_receipt, provision_exact_grant, provision_snapshot_grant, AgentRequest,
    ExactAuthorization, GrantProvisioning, InspectionLimits, InspectionReport, InspectionStatus,
    OperationReport, OperationResult, ReceiptStatement,
};
use rustix::fs::{openat, Mode, OFlags, CWD};
use serde::Deserialize;

use crate::transport_support::{self, FailureClass};

const JSON_BYTES_MAX: usize = 16 * 1024;
const MACHINE_OUTPUT_BYTES_MAX: usize = 64 * 1024;
const NON_CLAIMS: &str = concat!(
    "no-exactly-once;no-causation;no-kubernetes-truth;",
    "no-complete-capture;no-witnessing;not-production"
);

type CommandResult = Result<String, CommandError>;

pub(crate) fn run(arguments: impl Iterator<Item = OsString>) -> CommandResult {
    let mut arguments = arguments;
    let Some(subcommand) = arguments.next() else {
        return Err(CommandError::input("kapsel"));
    };
    let subcommand = subcommand
        .into_string()
        .map_err(|_| CommandError::input("kapsel"))?;
    match subcommand.as_str() {
        "--version" => version(arguments),
        "provision-grant" => provision(parse_options("provision-grant", arguments)?, false),
        "provision-snapshot-grant" => {
            provision(parse_options("provision-snapshot-grant", arguments)?, true)
        },
        "operate" => operate(parse_options("operate", arguments)?),
        "inspect" => inspect(parse_options("inspect", arguments)?),
        _ => Err(CommandError::input("kapsel")),
    }
}

fn version(mut arguments: impl Iterator<Item = OsString>) -> CommandResult {
    if arguments.next().is_some() {
        return Err(CommandError::input("kapsel"));
    }
    Ok(format!("kapsel {}", env!("CARGO_PKG_VERSION")))
}

fn parse_options(
    command: &'static str,
    mut arguments: impl Iterator<Item = OsString>,
) -> Result<BTreeMap<String, OsString>, CommandError> {
    let mut options = BTreeMap::new();
    while let Some(option) = arguments.next() {
        let option = option
            .into_string()
            .map_err(|_| CommandError::input(command))?;
        if !option.starts_with("--") || option.len() == 2 || options.contains_key(&option) {
            return Err(CommandError::input(command));
        }
        let value = arguments
            .next()
            .ok_or_else(|| CommandError::input(command))?;
        if value.to_string_lossy().starts_with("--") {
            return Err(CommandError::input(command));
        }
        options.insert(option, value);
    }
    Ok(options)
}

fn take_path(
    options: &mut BTreeMap<String, OsString>,
    name: &str,
    command: &'static str,
) -> Result<PathBuf, CommandError> {
    options
        .remove(name)
        .map(PathBuf::from)
        .ok_or_else(|| CommandError::input(command))
}

fn take_text(
    options: &mut BTreeMap<String, OsString>,
    name: &str,
    command: &'static str,
) -> Result<String, CommandError> {
    options
        .remove(name)
        .ok_or_else(|| CommandError::input(command))?
        .into_string()
        .map_err(|_| CommandError::input(command))
}

fn finish_options(
    options: &BTreeMap<String, OsString>,
    command: &'static str,
) -> Result<(), CommandError> {
    if options.is_empty() {
        Ok(())
    } else {
        Err(CommandError::input(command))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationDocument {
    authorization_id: String,
    operation_id: String,
    namespace: String,
    deployment: String,
    container: String,
    immutable_image_digest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestDocument {
    operation_id: String,
    namespace: String,
    deployment: String,
    container: String,
    immutable_image_digest: String,
}

fn provision(mut options: BTreeMap<String, OsString>, snapshot: bool) -> CommandResult {
    let command = if snapshot {
        "provision-snapshot-grant"
    } else {
        "provision-grant"
    };
    let kubeconfig = if snapshot {
        Some(take_path(&mut options, "--kubeconfig", command)?)
    } else {
        None
    };
    let authorization_path = take_path(&mut options, "--authorization", command)?;
    let seed_path = take_path(&mut options, "--signing-seed", command)?;
    let key_id = take_text(&mut options, "--signing-key-id", command)?;
    let output_path = take_path(&mut options, "--output", command)?;
    finish_options(&options, command)?;

    let document: AuthorizationDocument = read_json(&authorization_path, command)?;
    let seed = read_exact_32(&seed_path, command, ErrorClass::OperatorConfiguration)?;
    let authorization = ExactAuthorization {
        approved_target: None,
        authorization_id: document.authorization_id,
        operation_id: document.operation_id,
        namespace: document.namespace,
        deployment: document.deployment,
        container: document.container,
        immutable_image_digest: document.immutable_image_digest,
    };
    let provisioning = GrantProvisioning {
        authorization: &authorization,
        signing_seed: &seed,
        signing_key_id: &key_id,
    };
    let grant = if let Some(path) = kubeconfig {
        let bytes = read_bounded(
            &path,
            JSON_BYTES_MAX,
            command,
            ErrorClass::OperatorConfiguration,
        )?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| CommandError::configuration(command))?;
        runtime.block_on(provision_snapshot_grant(&provisioning, &bytes))
    } else {
        provision_exact_grant(&provisioning)
    }
    .map_err(|_| CommandError::input(command))?;
    write_new_private(&output_path, &grant)
        .map_err(|_| CommandError::configuration("provision-grant"))?;
    Ok(format!(
        "{{\"command\":\"{command}\",\"status\":\"PROVISIONED\"}}"
    ))
}

fn operate(mut options: BTreeMap<String, OsString>) -> CommandResult {
    let request_path = take_path(&mut options, "--request", "operate")?;
    let operator_path = take_path(&mut options, "--operator-config", "operate")?;
    finish_options(&options, "operate")?;

    let request: RequestDocument = read_json(&request_path, "operate")?;
    let request = AgentRequest {
        operation_id: request.operation_id,
        namespace: request.namespace,
        deployment: request.deployment,
        container: request.container,
        immutable_image_digest: request.immutable_image_digest,
    };

    let runtime = transport_support::runtime().map_err(|class| map_failure("operate", class))?;
    let report = runtime.block_on(async {
        let mut application = transport_support::open_application(&operator_path)
            .await
            .map_err(|class| map_failure("operate", class))?;
        application.execute(&request).await.map_err(|error| {
            map_failure(
                "operate",
                transport_support::classify_application_operation(&error),
            )
        })
    })?;
    render_operation(&report)
}

fn inspect(mut options: BTreeMap<String, OsString>) -> CommandResult {
    let receipt_path = take_path(&mut options, "--receipt", "inspect")?;
    let trust_path = take_path(&mut options, "--trust", "inspect")?;
    let evaluation_time_unix_s = take_text(&mut options, "--evaluation-time-unix-s", "inspect")?
        .parse::<i64>()
        .map_err(|_| CommandError::input("inspect"))?;
    let defaults = InspectionLimits::default();
    let limits = InspectionLimits {
        receipt_bytes_max: take_limit(
            &mut options,
            "--receipt-bytes-max",
            defaults.receipt_bytes_max,
        )?,
        statement_bytes_max: take_limit(
            &mut options,
            "--statement-bytes-max",
            defaults.statement_bytes_max,
        )?,
        trust_bytes_max: take_limit(&mut options, "--trust-bytes-max", defaults.trust_bytes_max)?,
        text_bytes_max: take_limit(&mut options, "--text-bytes-max", defaults.text_bytes_max)?,
    };
    finish_options(&options, "inspect")?;
    if !inspection_limits_are_valid(limits, defaults) {
        return Err(CommandError::input("inspect"));
    }
    let receipt_file = open_within_limit(
        &receipt_path,
        limits.receipt_bytes_max,
        "inspect",
        ErrorClass::CommandInput,
    )?;
    let trust_file = open_within_limit(
        &trust_path,
        limits.trust_bytes_max,
        "inspect",
        ErrorClass::CommandInput,
    )?;
    let (Some(receipt_file), Some(trust_file)) = (receipt_file, trust_file) else {
        return Ok(structure_rejected_output());
    };
    let receipt = read_opened_bounded(
        receipt_file,
        limits.receipt_bytes_max,
        "inspect",
        ErrorClass::CommandInput,
    )?;
    let trust = read_opened_bounded(
        trust_file,
        limits.trust_bytes_max,
        "inspect",
        ErrorClass::CommandInput,
    )?;
    let output = render_inspection(&inspect_receipt(
        &receipt,
        &trust,
        evaluation_time_unix_s,
        limits,
    ));
    if output
        .len()
        .checked_add(1)
        .is_none_or(|length| length > MACHINE_OUTPUT_BYTES_MAX)
    {
        return Err(CommandError::operation("inspect"));
    }
    Ok(output)
}

fn inspection_limits_are_valid(limits: InspectionLimits, maximum: InspectionLimits) -> bool {
    limits.receipt_bytes_max > 0
        && limits.receipt_bytes_max <= maximum.receipt_bytes_max
        && limits.statement_bytes_max > 0
        && limits.statement_bytes_max <= maximum.statement_bytes_max
        && limits.trust_bytes_max > 0
        && limits.trust_bytes_max <= maximum.trust_bytes_max
        && limits.text_bytes_max > 0
        && limits.text_bytes_max <= maximum.text_bytes_max
}

fn take_limit(
    options: &mut BTreeMap<String, OsString>,
    name: &str,
    default: usize,
) -> Result<usize, CommandError> {
    options.remove(name).map_or(Ok(default), |value| {
        value
            .into_string()
            .map_err(|_| CommandError::input("inspect"))?
            .parse::<usize>()
            .map_err(|_| CommandError::input("inspect"))
    })
}

fn read_json<T: for<'de> Deserialize<'de>>(
    path: &Path,
    command: &'static str,
) -> Result<T, CommandError> {
    read_json_classified(path, command, ErrorClass::CommandInput)
}

fn read_json_classified<T: for<'de> Deserialize<'de>>(
    path: &Path,
    command: &'static str,
    class: ErrorClass,
) -> Result<T, CommandError> {
    let bytes = read_bounded(path, JSON_BYTES_MAX, command, class)?;
    serde_json::from_slice(&bytes).map_err(|_| CommandError { command, class })
}

fn read_exact_32(
    path: &Path,
    command: &'static str,
    class: ErrorClass,
) -> Result<[u8; 32], CommandError> {
    read_bounded(path, 32, command, class)?
        .try_into()
        .map_err(|_| CommandError { command, class })
}

fn open_regular(
    path: &Path,
    command: &'static str,
    class: ErrorClass,
) -> Result<File, CommandError> {
    let descriptor = openat(
        CWD,
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| CommandError { command, class })?;
    let file = File::from(descriptor);
    if !file
        .metadata()
        .map_err(|_| CommandError { command, class })?
        .is_file()
    {
        return Err(CommandError { command, class });
    }
    Ok(file)
}

fn open_within_limit(
    path: &Path,
    maximum: usize,
    command: &'static str,
    class: ErrorClass,
) -> Result<Option<File>, CommandError> {
    if maximum == 0 {
        return Err(CommandError { command, class });
    }
    let file = open_regular(path, command, class)?;
    let length = file
        .metadata()
        .map_err(|_| CommandError { command, class })?
        .len();
    if usize::try_from(length).map_or(true, |length| length > maximum) {
        Ok(None)
    } else {
        Ok(Some(file))
    }
}

fn read_bounded(
    path: &Path,
    maximum: usize,
    command: &'static str,
    class: ErrorClass,
) -> Result<Vec<u8>, CommandError> {
    let file =
        open_within_limit(path, maximum, command, class)?.ok_or(CommandError { command, class })?;
    read_opened_bounded(file, maximum, command, class)
}

fn read_opened_bounded(
    file: File,
    maximum: usize,
    command: &'static str,
    class: ErrorClass,
) -> Result<Vec<u8>, CommandError> {
    let capacity = maximum
        .checked_add(1)
        .ok_or(CommandError { command, class })?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(u64::try_from(capacity).map_err(|_| CommandError { command, class })?)
        .read_to_end(&mut bytes)
        .map_err(|_| CommandError { command, class })?;
    if bytes.len() > maximum {
        return Err(CommandError { command, class });
    }
    Ok(bytes)
}

fn write_new_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    let descriptor = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    if descriptor.dev() != named.dev() || descriptor.ino() != named.ino() {
        return Err(std::io::Error::other("output path identity changed"));
    }
    Ok(())
}

fn render_operation(report: &OperationReport) -> CommandResult {
    let projection = transport_support::project_operation(report)
        .map_err(|class| map_failure("operate", class))?;
    let operation_id_json = json_string(projection.operation_id);
    let result_json = optional_json(projection.result);
    let target_rejection_json = optional_json(projection.target_rejection);
    let receipt_file_json = optional_json(projection.receipt_file);
    let receipt_digest_json = optional_json(projection.receipt_sha256);
    let fields = transport_support::target_fields(&report.targets);
    let target_fields = &fields[1..fields.len() - 1];
    Ok(format!(
        concat!(
            "{{\"command\":\"operate\",\"operation_id\":{operation_id_json},",
            "\"state\":\"{state}\",\"result\":{result_json},",
            "\"target_rejection\":{target_rejection_json},",
            "\"receipt_file\":{receipt_file_json},",
            "\"receipt_sha256\":{receipt_digest_json},{target_fields}}}"
        ),
        operation_id_json = operation_id_json,
        state = projection.state,
        result_json = result_json,
        target_rejection_json = target_rejection_json,
        receipt_file_json = receipt_file_json,
        target_fields = target_fields,
        receipt_digest_json = receipt_digest_json
    ))
}

fn structure_rejected_output() -> String {
    render_inspection_fields("STRUCTURE_REJECTED", None)
}

fn render_inspection(report: &InspectionReport) -> String {
    render_inspection_fields(inspection_status(report.status()), report.statement())
}

#[allow(
    clippy::too_many_lines,
    reason = "the fixed classifier-complete machine record keeps field order explicit"
)]
fn render_inspection_fields(status: &str, statement: Option<&ReceiptStatement>) -> String {
    let mut output = format!("{{\"command\":\"inspect\",\"status\":\"{status}\"");
    let Some(statement) = statement else {
        for name in [
            "operation_id",
            "authorization_id",
            "authorization_signer_key_id",
            "authorization_grant_digest",
            "namespace",
            "deployment",
            "container",
            "immutable_image_digest",
            "write_strategy",
            "target_uid",
            "target_resource_version",
            "receiver_uid",
            "observed_image",
            "observed_operation_marker",
            "current_generation",
            "requested_generation",
            "observed_generation",
            "observed_resource_version",
            "desired_replicas",
            "updated_replicas",
            "available_replicas",
            "unavailable_replicas",
            "rollout_condition_type",
            "rollout_condition_status",
            "rollout_condition_reason",
            "result",
            "non_claims",
        ] {
            append_json_field(&mut output, name, "null");
        }
        output.push('}');
        return output;
    };

    let text_fields = [
        ("operation_id", Some(statement.operation_id())),
        ("authorization_id", Some(statement.authorization_id())),
        (
            "authorization_signer_key_id",
            Some(statement.authorization_signer_key_id()),
        ),
        (
            "authorization_grant_digest",
            Some(statement.authorization_grant_digest()),
        ),
        ("namespace", Some(statement.namespace())),
        ("deployment", Some(statement.deployment())),
        ("container", Some(statement.container())),
        (
            "immutable_image_digest",
            Some(statement.immutable_image_digest()),
        ),
        ("write_strategy", Some(statement.write_strategy())),
        ("target_uid", Some(statement.target_uid())),
        (
            "target_resource_version",
            Some(statement.target_resource_version()),
        ),
        ("receiver_uid", statement.receiver_uid()),
        ("observed_image", statement.observed_image()),
        (
            "observed_operation_marker",
            statement.observed_operation_marker(),
        ),
    ];
    for (name, value) in text_fields {
        append_json_field(&mut output, name, &optional_json(value));
    }

    for (name, value) in [
        ("current_generation", statement.current_generation()),
        ("requested_generation", statement.requested_generation()),
        ("observed_generation", statement.observed_generation()),
    ] {
        append_json_field(&mut output, name, &optional_number(value));
    }
    append_json_field(
        &mut output,
        "observed_resource_version",
        &optional_json(statement.observed_resource_version()),
    );

    for (name, value) in [
        ("desired_replicas", statement.desired_replicas()),
        ("updated_replicas", statement.updated_replicas()),
        ("available_replicas", statement.available_replicas()),
        ("unavailable_replicas", statement.unavailable_replicas()),
    ] {
        append_json_field(&mut output, name, &optional_number(value));
    }

    for (name, value) in [
        ("rollout_condition_type", statement.rollout_condition_type()),
        (
            "rollout_condition_status",
            statement.rollout_condition_status(),
        ),
        (
            "rollout_condition_reason",
            statement.rollout_condition_reason(),
        ),
    ] {
        append_json_field(&mut output, name, &optional_json(value));
    }

    append_json_field(
        &mut output,
        "result",
        &json_string(operation_result(statement.result())),
    );
    let targets = kapsel::OperationTargets {
        approved_target: statement.approved_target().cloned(),
        attempt_target: Some(kapsel::ApprovedTarget {
            uid: statement.target_uid().into(),
            resource_version: statement.target_resource_version().into(),
        }),
        observed_target: Some(kapsel::ObservedTarget {
            uid: statement.receiver_uid().map(str::to_owned),
            resource_version: statement.observed_resource_version().map(str::to_owned),
        }),
    };
    let fields = transport_support::target_fields(&targets);
    output.push(',');
    output.push_str(&fields[1..fields.len() - 1]);
    append_json_field(&mut output, "non_claims", &json_string(NON_CLAIMS));
    output.push('}');
    output
}

fn append_json_field(output: &mut String, name: &str, value: &str) {
    use std::fmt::Write as _;

    write!(output, ",\"{name}\":{value}")
        .unwrap_or_else(|_| unreachable!("writing into String cannot fail"));
}

fn optional_number<T: std::fmt::Display>(value: Option<T>) -> String {
    value.map_or_else(|| String::from("null"), |value| value.to_string())
}

fn json_string(value: &str) -> String {
    serde_json::to_string(value)
        .unwrap_or_else(|_| unreachable!("serializing a string as JSON cannot fail"))
}

fn optional_json(value: Option<&str>) -> String {
    value.map_or_else(|| "null".into(), json_string)
}

const fn operation_result(value: OperationResult) -> &'static str {
    match value {
        OperationResult::Succeeded => "SUCCEEDED",
        OperationResult::Failed => "FAILED",
        OperationResult::Unknown => "UNKNOWN",
    }
}

const fn inspection_status(value: InspectionStatus) -> &'static str {
    match value {
        InspectionStatus::StructureRejected => "STRUCTURE_REJECTED",
        InspectionStatus::SignatureRejected => "SIGNATURE_REJECTED",
        InspectionStatus::UntrustedSigner => "UNTRUSTED_SIGNER",
        InspectionStatus::Inspected => "INSPECTED",
    }
}

fn map_failure(command: &'static str, class: FailureClass) -> CommandError {
    match class {
        FailureClass::OperatorConfiguration => CommandError::configuration(command),
        FailureClass::RequestRejected => CommandError::input(command),
        FailureClass::OperationFailure => CommandError::operation(command),
    }
}

#[derive(Clone, Copy)]
enum ErrorClass {
    CommandInput,
    OperatorConfiguration,
    OperationFailure,
}

pub(crate) struct CommandError {
    command: &'static str,
    class: ErrorClass,
}

impl CommandError {
    const fn input(command: &'static str) -> Self {
        Self {
            command,
            class: ErrorClass::CommandInput,
        }
    }

    const fn configuration(command: &'static str) -> Self {
        Self {
            command,
            class: ErrorClass::OperatorConfiguration,
        }
    }

    const fn operation(command: &'static str) -> Self {
        Self {
            command,
            class: ErrorClass::OperationFailure,
        }
    }

    const fn class_name(&self) -> &'static str {
        match self.class {
            ErrorClass::CommandInput => "command_input",
            ErrorClass::OperatorConfiguration => "operator_configuration",
            ErrorClass::OperationFailure => "operation_failure",
        }
    }

    pub(crate) fn exit_code(&self) -> u8 {
        match self.class {
            ErrorClass::CommandInput => 2,
            ErrorClass::OperatorConfiguration => 3,
            ErrorClass::OperationFailure => 4,
        }
    }

    pub(crate) fn machine_output(&self) -> String {
        format!(
            "{{\"command\":\"{}\",\"status\":\"ERROR\",\"error_class\":\"{}\"}}",
            self.command,
            self.class_name()
        )
    }

    pub(crate) fn diagnostic(&self) -> String {
        format!("Kapsel command failure: {}", self.class_name())
    }
}
