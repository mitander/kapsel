//! Linux installer execution, preflight, and crash-safe filesystem operations.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read as _, Seek as _, SeekFrom},
    mem::MaybeUninit,
    os::fd::OwnedFd,
    path::{Component, Path},
};

use http_body_util::Limited;
use k8s_openapi::api::{
    core::v1::{Namespace, ServiceAccount},
    rbac::v1::{Role, RoleBinding},
};
use kube::{api::Api, config::KubeConfigOptions, Config};
use rustix::fs::{
    self as rfs, AtFlags, FileType, FlockOperation, Mode, OFlags, RawDir, RenameFlags, Stat,
    XattrFlags, CWD,
};
use tokio::io::AsyncReadExt as _;
use tower_http::map_response_body::MapResponseBodyLayer;

use super::{
    identity::{
        classify_group_observation, classify_user_observation, owned_group_gid,
        parse_identity_gids, pending_user, select_group_gid, select_user_uid, user_from_pending,
        user_resource_from_pending, BoundedCommandOutput, GroupObservation, UserObservation,
        UserSpec, CALLER_USER, SERVICE_USER,
    },
    transaction::{
        classify_install_phase, decode_transaction, encode_transaction,
        legal_transaction_successor, matches_stable_identity, validate_initial_transaction,
        InstallPhase, TRANSACTION_BYTES_MAX,
    },
    *,
};

struct OperatorInput {
    _directory: OwnedFd,
    directory_metadata: Stat,
    files: BTreeMap<&'static str, Vec<u8>>,
    identity: kapsel_authority::ValidatedServiceOperatorInputs,
    path: String,
    bootstrap: BootstrapAuthority,
}

struct OpenTransaction {
    directory: OwnedFd,
    record: InstallerTransaction,
}

#[allow(
    dead_code,
    reason = "host-file installation order is intentionally not wired in this milestone"
)]
struct HostFileSpec<'a> {
    bytes: &'a [u8],
    destination: &'a str,
    gid: u32,
    mode: u32,
    staging: &'a str,
    uid: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostFilePublication {
    Complete,
    NotStarted,
}

const OPERATOR_FILES: &[(&str, usize)] = &[
    ("authorization.pub", 32),
    ("bootstrap-kubeconfig.yaml", 64 * 1024),
    ("grant.bin", 4 * 1024),
    ("receipt.seed", 32),
    ("receipt.trust", 1024),
];

pub(super) fn run(arguments: impl IntoIterator<Item = OsString>) -> Result<(), InstallerError> {
    let invocation = parse_arguments(arguments)?;
    validate_embedded_bundle()?;
    let operator_input =
        validate_operator_input(&invocation.operator_input, &invocation.kube_context)?;
    validate_fixed_authority(&operator_input.identity)?;
    let lock = acquire_installer_lock()?;
    let mut transaction = open_transaction(&invocation, &operator_input)?;

    if invocation.action != Action::Install {
        return Err(InstallerError::ImplementationIncomplete);
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| InstallerError::HostPreflightFailure)?;
    match classify_install_phase(transaction.record.phase)? {
        InstallPhase::Blocked => return Err(InstallerError::HostMutationFailure),
        InstallPhase::Prepared => {
            enter_installing(&runtime, &operator_input, &mut transaction)?;
        },
        InstallPhase::Installing => {},
        InstallPhase::RollingBack => {
            runtime.block_on(rollback_groups(&lock, &mut transaction))?;
            return Err(InstallerError::ImplementationIncomplete);
        },
        InstallPhase::RolledBack => {
            let old = transaction.record.clone();
            transaction.record.phase = TransactionPhase::Prepared;
            publish_transaction_successor(&transaction.directory, &old, &transaction.record)?;
            enter_installing(&runtime, &operator_input, &mut transaction)?;
        },
    }
    runtime.block_on(ensure_group(&lock, &mut transaction, "kapsel"))?;
    if fail_at_test_seam("first-group-complete") {
        runtime.block_on(rollback_groups(&lock, &mut transaction))?;
        return Err(InstallerError::ImplementationIncomplete);
    }
    runtime.block_on(ensure_group(
        &lock,
        &mut transaction,
        "kapsel-service-callers",
    ))?;
    if fail_at_test_seam("second-group-complete") {
        runtime.block_on(rollback_groups(&lock, &mut transaction))?;
        return Err(InstallerError::ImplementationIncomplete);
    }
    runtime.block_on(ensure_user(&lock, &mut transaction, &SERVICE_USER))?;
    runtime.block_on(ensure_user(&lock, &mut transaction, &CALLER_USER))?;
    Err(InstallerError::ImplementationIncomplete)
}

fn enter_installing(
    runtime: &tokio::runtime::Runtime,
    operator_input: &OperatorInput,
    transaction: &mut OpenTransaction,
) -> Result<(), InstallerError> {
    runtime.block_on(run_preflight(operator_input))?;
    let old = transaction.record.clone();
    transaction.record.phase = TransactionPhase::Installing;
    publish_transaction_successor(&transaction.directory, &old, &transaction.record)
}

const INSTALLER_BYTES_MAX: usize = 64 * 1024 * 1024;

fn initial_transaction(
    invocation: &Invocation,
    input: &OperatorInput,
    transaction_id: String,
) -> Result<InstallerTransaction, InstallerError> {
    let bootstrap_digest = digest_named_input(input, "bootstrap-kubeconfig.yaml")?;
    let transaction = InstallerTransaction {
        action: Action::Install,
        bootstrap_kubeconfig_initial_sha256: bootstrap_digest.clone(),
        bootstrap_kubeconfig_sha256: bootstrap_digest,
        cluster: TransactionCluster {
            ca_sha256: hex_digest(&input.bootstrap.certificate_authority),
            server: input.bootstrap.server.clone(),
        },
        credential_expiration: None,
        host_resources: Vec::new(),
        input_directory: TransactionInputDirectory {
            device: input.directory_metadata.st_dev,
            inode: input.directory_metadata.st_ino,
            mode: input.directory_metadata.st_mode & 0o7777,
            path: input.path.clone(),
            uid: input.directory_metadata.st_uid,
        },
        installer_sha256: digest_running_installer()?,
        kube_context: invocation.kube_context.clone(),
        kubernetes_resources: Vec::new(),
        operator_inputs: TransactionOperatorInputs {
            authorization_pub: digest_named_input(input, "authorization.pub")?,
            grant_bin: digest_named_input(input, "grant.bin")?,
            receipt_seed: digest_named_input(input, "receipt.seed")?,
            receipt_trust: digest_named_input(input, "receipt.trust")?,
        },
        pending: None,
        phase: TransactionPhase::Prepared,
        schema: 1,
        transaction_id,
    };
    validate_initial_transaction(&transaction)?;
    Ok(transaction)
}

fn digest_named_input(input: &OperatorInput, name: &str) -> Result<String, InstallerError> {
    input
        .files
        .get(name)
        .map(|bytes| hex_digest(bytes))
        .ok_or(InstallerError::TransactionFailure)
}

fn open_transaction(
    invocation: &Invocation,
    input: &OperatorInput,
) -> Result<OpenTransaction, InstallerError> {
    let root = rfs::openat(
        CWD,
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| InstallerError::TransactionFailure)?;
    let var = open_directory(&root, "var", InstallerError::TransactionFailure)?;
    validate_transaction_parent(&var, false)?;
    let lib = open_directory(&var, "lib", InstallerError::TransactionFailure)?;
    validate_transaction_parent(&lib, true)?;

    let created = if invocation.action == Action::Install {
        match with_exact_creation_mode(|| rfs::mkdirat(&lib, "kapsel-installer", Mode::RWXU)) {
            Ok(()) => {
                stop_at_test_seam("transaction-directory");
                true
            },
            Err(rustix::io::Errno::EXIST) => false,
            Err(_) => return Err(InstallerError::TransactionFailure),
        }
    } else {
        false
    };
    let directory = open_directory(&lib, "kapsel-installer", InstallerError::TransactionFailure)?;
    if created {
        rfs::fchmod(&directory, Mode::RWXU).map_err(|_| InstallerError::TransactionFailure)?;
    }
    let before = rfs::fstat(&directory).map_err(|_| InstallerError::TransactionFailure)?;
    if !valid_transaction_directory(&before) {
        return Err(InstallerError::TransactionFailure);
    }
    let names = directory_names(&directory, InstallerError::TransactionFailure)?;
    if names.is_empty() {
        rfs::fsync(&lib).map_err(|_| InstallerError::TransactionFailure)?;
        stop_at_test_seam("transaction-parent-synced");
        let transaction = initial_transaction(invocation, input, new_transaction_id()?)?;
        let bytes = encode_transaction(&transaction)?;
        publish_initial_transaction(&directory, &bytes)?;
        return Ok(OpenTransaction {
            directory,
            record: transaction,
        });
    }
    let (transaction, recovered_successor) =
        if names.len() == 1 && names.contains("transaction.json") {
            (
                read_transaction_leaf(&directory, "transaction.json", false)?,
                false,
            )
        } else if names.len() == 2
            && names.contains("transaction.json")
            && names.contains(".transaction.next")
        {
            let old = read_transaction_leaf(&directory, "transaction.json", false)?;
            let expected = initial_transaction(invocation, input, old.transaction_id.clone())?;
            if !matches_stable_identity(&old, &expected) {
                return Err(InstallerError::TransactionFailure);
            }
            (
                recover_transaction_successor(
                    &directory,
                    &old,
                    &digest_named_input(input, "bootstrap-kubeconfig.yaml")?,
                )?,
                true,
            )
        } else {
            return Err(InstallerError::TransactionFailure);
        };
    let expected = initial_transaction(invocation, input, transaction.transaction_id.clone())?;
    if !matches_stable_identity(&transaction, &expected) {
        return Err(InstallerError::TransactionFailure);
    }
    let current_digest = digest_named_input(input, "bootstrap-kubeconfig.yaml")?;
    let (transaction, published_digest_successor) = if invocation.action != Action::Install
        || transaction.bootstrap_kubeconfig_sha256 == current_digest
    {
        (transaction, false)
    } else {
        let mut renewed = transaction.clone();
        renewed.bootstrap_kubeconfig_sha256 = current_digest;
        publish_transaction_successor(&directory, &transaction, &renewed)?;
        (renewed, true)
    };
    let after = rfs::fstat(&directory).map_err(|_| InstallerError::TransactionFailure)?;
    if !valid_transaction_directory(&after)
        || !recovered_successor && !published_digest_successor && !stable_directory(&before, &after)
    {
        return Err(InstallerError::TransactionFailure);
    }
    Ok(OpenTransaction {
        directory,
        record: transaction,
    })
}

fn validate_transaction_parent(
    directory: &OwnedFd,
    reject_inherited_setgid: bool,
) -> Result<(), InstallerError> {
    let metadata = rfs::fstat(directory).map_err(|_| InstallerError::TransactionFailure)?;
    if !root_owned_directory(&metadata)
        || metadata.st_mode & 0o022 != 0
        || (reject_inherited_setgid && metadata.st_mode & 0o2000 != 0)
    {
        return Err(InstallerError::TransactionFailure);
    }
    Ok(())
}

fn valid_transaction_directory(metadata: &Stat) -> bool {
    root_owned_directory(metadata) && metadata.st_mode & 0o7777 == 0o700
}

fn publish_initial_transaction(directory: &OwnedFd, bytes: &[u8]) -> Result<(), InstallerError> {
    let file = write_transaction_inode(directory, bytes, None)?;
    link_transaction_inode(directory, &file, "transaction.json")?;
    rfs::fsync(directory).map_err(|_| InstallerError::TransactionFailure)
}

fn write_transaction_inode(
    directory: &OwnedFd,
    bytes: &[u8],
    marker: Option<&str>,
) -> Result<std::fs::File, InstallerError> {
    let descriptor = rfs::openat(
        directory,
        ".",
        OFlags::RDWR | OFlags::TMPFILE | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| InstallerError::TransactionFailure)?;
    rfs::fchmod(&descriptor, Mode::RUSR | Mode::WUSR)
        .map_err(|_| InstallerError::TransactionFailure)?;
    let mut file = std::fs::File::from(descriptor);
    file.write_all(bytes)
        .map_err(|_| InstallerError::TransactionFailure)?;
    if let Some(transaction_id) = marker {
        rfs::fsetxattr(
            &file,
            "user.kapsel.transaction-id",
            transaction_id.as_bytes(),
            XattrFlags::CREATE,
        )
        .map_err(|_| InstallerError::TransactionFailure)?;
        validate_transaction_marker(&file, transaction_id, true)?;
    }
    rfs::fsync(&file).map_err(|_| InstallerError::TransactionFailure)?;
    let metadata = rfs::fstat(&file).map_err(|_| InstallerError::TransactionFailure)?;
    if !FileType::from_raw_mode(metadata.st_mode).is_file()
        || metadata.st_uid != 0
        || metadata.st_mode & 0o7777 != 0o600
        || metadata.st_nlink != 0
        || usize::try_from(metadata.st_size) != Ok(bytes.len())
    {
        return Err(InstallerError::TransactionFailure);
    }
    Ok(file)
}

fn link_transaction_inode(
    directory: &OwnedFd,
    file: &std::fs::File,
    name: &str,
) -> Result<(), InstallerError> {
    rfs::linkat(file, "", directory, name, AtFlags::EMPTY_PATH)
        .map_err(|_| InstallerError::TransactionFailure)
}

#[allow(
    dead_code,
    reason = "successor writes begin with the next installer phase"
)]
fn publish_transaction_successor(
    directory: &OwnedFd,
    old: &InstallerTransaction,
    next: &InstallerTransaction,
) -> Result<(), InstallerError> {
    if !legal_transaction_successor(old, next) {
        return Err(InstallerError::TransactionFailure);
    }
    let bytes = encode_transaction(next)?;
    let file = write_transaction_inode(directory, &bytes, Some(&next.transaction_id))?;
    stop_at_test_seam("successor-inode-synced");
    link_transaction_inode(directory, &file, ".transaction.next")?;
    rfs::fsync(directory).map_err(|_| InstallerError::TransactionFailure)?;
    stop_at_test_seam("successor-linked");
    install_transaction_successor(directory)
}

fn install_transaction_successor(directory: &OwnedFd) -> Result<(), InstallerError> {
    rfs::renameat(
        directory,
        ".transaction.next",
        directory,
        "transaction.json",
    )
    .map_err(|_| InstallerError::TransactionFailure)?;
    stop_at_test_seam("successor-renamed");
    rfs::fsync(directory).map_err(|_| InstallerError::TransactionFailure)
}

fn read_transaction_leaf(
    directory: &OwnedFd,
    name: &str,
    marker_required: bool,
) -> Result<InstallerTransaction, InstallerError> {
    let descriptor = rfs::openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| InstallerError::TransactionFailure)?;
    let before = rfs::fstat(&descriptor).map_err(|_| InstallerError::TransactionFailure)?;
    if !FileType::from_raw_mode(before.st_mode).is_file()
        || before.st_uid != 0
        || before.st_mode & 0o7777 != 0o600
        || before.st_nlink != 1
        || before.st_size <= 0
        || usize::try_from(before.st_size).map_or(true, |length| length > TRANSACTION_BYTES_MAX)
    {
        return Err(InstallerError::TransactionFailure);
    }
    let capacity =
        usize::try_from(before.st_size).map_err(|_| InstallerError::TransactionFailure)?;
    let mut file = std::fs::File::from(descriptor);
    let mut bytes = Vec::with_capacity(capacity);
    (&mut file)
        .take(u64::try_from(TRANSACTION_BYTES_MAX).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| InstallerError::TransactionFailure)?;
    let after = rfs::fstat(&file).map_err(|_| InstallerError::TransactionFailure)?;
    if bytes.len() > TRANSACTION_BYTES_MAX || !stable_file(&before, &after, bytes.len()) {
        return Err(InstallerError::TransactionFailure);
    }
    let transaction = decode_transaction(&bytes)?;
    validate_transaction_marker(&file, &transaction.transaction_id, marker_required)?;
    Ok(transaction)
}

fn validate_transaction_marker(
    file: &std::fs::File,
    transaction_id: &str,
    required: bool,
) -> Result<(), InstallerError> {
    let mut marker = [0_u8; 65];
    match rfs::fgetxattr(file, "user.kapsel.transaction-id", &mut marker[..]) {
        Ok(length) if length == 64 && marker[..length] == *transaction_id.as_bytes() => Ok(()),
        Err(rustix::io::Errno::NODATA) if !required => Ok(()),
        _ => Err(InstallerError::TransactionFailure),
    }
}

fn recover_transaction_successor(
    directory: &OwnedFd,
    old: &InstallerTransaction,
    validated_bootstrap_digest: &str,
) -> Result<InstallerTransaction, InstallerError> {
    let next = read_transaction_leaf(directory, ".transaction.next", true)?;
    if !legal_transaction_successor(old, &next)
        || old.bootstrap_kubeconfig_sha256 != next.bootstrap_kubeconfig_sha256
            && next.bootstrap_kubeconfig_sha256 != validated_bootstrap_digest
    {
        return Err(InstallerError::TransactionFailure);
    }
    install_transaction_successor(directory)?;
    Ok(next)
}

#[allow(
    dead_code,
    reason = "host-file installation order is intentionally not wired in this milestone"
)]
#[allow(
    clippy::too_many_lines,
    reason = "keeping the crash-safe state transitions together makes their ordering reviewable"
)]
fn ensure_host_file(
    transaction: &mut OpenTransaction,
    spec: &HostFileSpec<'_>,
) -> Result<(), InstallerError> {
    let parent = open_destination_parent(spec.destination)?;
    let expected_digest = hex_digest(spec.bytes);
    let expected_length =
        u64::try_from(spec.bytes.len()).map_err(|_| InstallerError::HostMutationFailure)?;
    if let Some(resource) = transaction.record.host_resources.iter().find(
        |resource| matches!(resource, HostResource::File(file) if file.path == spec.destination),
    ) {
        let HostResource::File(file) = resource else {
            return Err(InstallerError::HostMutationFailure);
        };
        if transaction.record.pending.is_none()
            && file_matches_spec(file, spec, &expected_digest)
            && validate_named_host_file(
                &parent,
                destination_leaf(spec.destination)?,
                spec,
                &transaction.record.transaction_id,
                file.device,
                file.inode,
            )
            .is_ok()
        {
            return Ok(());
        }
        return Err(InstallerError::HostMutationFailure);
    }

    if transaction.record.pending.is_none() {
        let old = transaction.record.clone();
        transaction.record.pending = Some(PendingAction::StageHost {
            destination: String::from(spec.destination),
            device: None,
            file_type: HostFileType::Regular,
            gid: spec.gid,
            inode: None,
            length: expected_length,
            mode: spec.mode,
            sha256: expected_digest.clone(),
            staging: String::from(spec.staging),
            transaction_id: transaction.record.transaction_id.clone(),
            uid: spec.uid,
        });
        publish_transaction_successor(&transaction.directory, &old, &transaction.record)?;
    }

    let pending = transaction
        .record
        .pending
        .clone()
        .ok_or(InstallerError::HostMutationFailure)?;
    match pending {
        PendingAction::StageHost {
            destination,
            device,
            file_type,
            gid,
            inode,
            length,
            mode,
            sha256,
            staging,
            transaction_id,
            uid,
        } => {
            if destination != spec.destination
                || file_type != HostFileType::Regular
                || gid != spec.gid
                || length != expected_length
                || mode != spec.mode
                || sha256 != expected_digest
                || staging != spec.staging
                || transaction_id != transaction.record.transaction_id
                || uid != spec.uid
            {
                return Err(InstallerError::HostMutationFailure);
            }
            let (device, inode) = match (device, inode) {
                (None, None) => {
                    let metadata = stage_or_recover_host_file(
                        &parent,
                        spec,
                        &transaction.record.transaction_id,
                    )?;
                    let old = transaction.record.clone();
                    let Some(PendingAction::StageHost { device, inode, .. }) =
                        transaction.record.pending.as_mut()
                    else {
                        return Err(InstallerError::HostMutationFailure);
                    };
                    *device = Some(metadata.st_dev);
                    *inode = Some(metadata.st_ino);
                    publish_transaction_successor(
                        &transaction.directory,
                        &old,
                        &transaction.record,
                    )?;
                    (metadata.st_dev, metadata.st_ino)
                },
                (Some(device), Some(inode)) => {
                    require_destination_absent(&parent, destination_leaf(spec.destination)?)?;
                    validate_named_host_file(
                        &parent,
                        OsStr::new(spec.staging),
                        spec,
                        &transaction.record.transaction_id,
                        device,
                        inode,
                    )?;
                    (device, inode)
                },
                _ => return Err(InstallerError::HostMutationFailure),
            };
            let old = transaction.record.clone();
            transaction.record.pending = Some(PendingAction::PublishHost {
                destination: String::from(spec.destination),
                device,
                file_type,
                gid,
                inode,
                length,
                mode,
                sha256,
                staging,
                transaction_id,
                uid,
            });
            publish_transaction_successor(&transaction.directory, &old, &transaction.record)?;
        },
        PendingAction::PublishHost { .. } => {},
        _ => return Err(InstallerError::HostMutationFailure),
    }

    let PendingAction::PublishHost {
        destination,
        device,
        file_type,
        gid,
        inode,
        length,
        mode,
        sha256,
        staging,
        transaction_id,
        uid,
    } = transaction
        .record
        .pending
        .clone()
        .ok_or(InstallerError::HostMutationFailure)?
    else {
        return Err(InstallerError::HostMutationFailure);
    };
    if destination != spec.destination
        || file_type != HostFileType::Regular
        || gid != spec.gid
        || length != expected_length
        || mode != spec.mode
        || sha256 != expected_digest
        || staging != spec.staging
        || transaction_id != transaction.record.transaction_id
        || uid != spec.uid
    {
        return Err(InstallerError::HostMutationFailure);
    }
    publish_or_recover_host_file(
        &parent,
        spec,
        &transaction.record.transaction_id,
        device,
        inode,
    )?;
    let old = transaction.record.clone();
    transaction.record.pending = None;
    transaction
        .record
        .host_resources
        .push(HostResource::File(FileResource {
            device,
            file_type: HostFileType::Regular,
            gid: spec.gid,
            inode,
            kind: FileResourceKind::File,
            length: expected_length,
            mode: spec.mode,
            path: String::from(spec.destination),
            sha256: expected_digest,
            uid: spec.uid,
        }));
    publish_transaction_successor(&transaction.directory, &old, &transaction.record)
}

fn file_matches_spec(file: &FileResource, spec: &HostFileSpec<'_>, digest: &str) -> bool {
    file.file_type == HostFileType::Regular
        && file.gid == spec.gid
        && file.kind == FileResourceKind::File
        && file.length == u64::try_from(spec.bytes.len()).unwrap_or(u64::MAX)
        && file.mode == spec.mode
        && file.path == spec.destination
        && file.sha256 == digest
        && file.uid == spec.uid
}

fn open_destination_parent(destination: &str) -> Result<OwnedFd, InstallerError> {
    let destination = Path::new(destination);
    if !destination.is_absolute()
        || destination
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(InstallerError::HostMutationFailure);
    }
    let parent = destination
        .parent()
        .ok_or(InstallerError::HostMutationFailure)?;
    open_host_directory(&host_path(
        parent.to_str().ok_or(InstallerError::HostMutationFailure)?,
    ))
    .map_err(|_| InstallerError::HostMutationFailure)
}

fn destination_leaf(destination: &str) -> Result<&OsStr, InstallerError> {
    Path::new(destination)
        .file_name()
        .ok_or(InstallerError::HostMutationFailure)
}

fn stage_or_recover_host_file(
    parent: &OwnedFd,
    spec: &HostFileSpec<'_>,
    transaction_id: &str,
) -> Result<Stat, InstallerError> {
    require_destination_absent(parent, destination_leaf(spec.destination)?)?;
    match rfs::statat(parent, spec.staging, AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => create_staged_host_file(parent, spec, transaction_id),
        Ok(_) => {
            validate_named_host_file(parent, OsStr::new(spec.staging), spec, transaction_id, 0, 0)
        },
        Err(_) => Err(InstallerError::HostMutationFailure),
    }
}

fn create_staged_host_file(
    parent: &OwnedFd,
    spec: &HostFileSpec<'_>,
    transaction_id: &str,
) -> Result<Stat, InstallerError> {
    let descriptor = rfs::openat(
        parent,
        ".",
        OFlags::RDWR | OFlags::TMPFILE | OFlags::CLOEXEC,
        Mode::from_raw_mode(spec.mode),
    )
    .map_err(|_| InstallerError::HostMutationFailure)?;
    rfs::fchown(
        &descriptor,
        Some(rustix::process::Uid::from_raw(spec.uid)),
        Some(rustix::process::Gid::from_raw(spec.gid)),
    )
    .map_err(|_| InstallerError::HostMutationFailure)?;
    rfs::fchmod(&descriptor, Mode::from_raw_mode(spec.mode))
        .map_err(|_| InstallerError::HostMutationFailure)?;
    let mut file = std::fs::File::from(descriptor);
    file.write_all(spec.bytes)
        .map_err(|_| InstallerError::HostMutationFailure)?;
    rfs::fdatasync(&file).map_err(|_| InstallerError::HostMutationFailure)?;
    rfs::fsetxattr(
        &file,
        "user.kapsel.transaction-id",
        transaction_id.as_bytes(),
        XattrFlags::CREATE,
    )
    .map_err(|_| InstallerError::HostMutationFailure)?;
    validate_host_file_marker(&file, transaction_id)?;
    rfs::fsync(&file).map_err(|_| InstallerError::HostMutationFailure)?;
    validate_open_host_file(&mut file, spec, transaction_id, 0, 0, 0)?;
    rfs::linkat(&file, "", parent, spec.staging, AtFlags::EMPTY_PATH)
        .map_err(|_| InstallerError::HostMutationFailure)?;
    rfs::fsync(parent).map_err(|_| InstallerError::HostMutationFailure)?;
    validate_named_host_file(parent, OsStr::new(spec.staging), spec, transaction_id, 0, 0)
}

fn validate_named_host_file(
    parent: &OwnedFd,
    name: &OsStr,
    spec: &HostFileSpec<'_>,
    transaction_id: &str,
    expected_device: u64,
    expected_inode: u64,
) -> Result<Stat, InstallerError> {
    let descriptor = rfs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| InstallerError::HostMutationFailure)?;
    let mut file = std::fs::File::from(descriptor);
    validate_open_host_file(
        &mut file,
        spec,
        transaction_id,
        expected_device,
        expected_inode,
        1,
    )
}

fn validate_open_host_file(
    file: &mut std::fs::File,
    spec: &HostFileSpec<'_>,
    transaction_id: &str,
    expected_device: u64,
    expected_inode: u64,
    expected_links: u64,
) -> Result<Stat, InstallerError> {
    let before = rfs::fstat(&*file).map_err(|_| InstallerError::HostMutationFailure)?;
    let expected_length =
        i64::try_from(spec.bytes.len()).map_err(|_| InstallerError::HostMutationFailure)?;
    if !FileType::from_raw_mode(before.st_mode).is_file()
        || before.st_uid != spec.uid
        || before.st_gid != spec.gid
        || before.st_mode & 0o7777 != spec.mode
        || before.st_nlink != expected_links
        || before.st_size != expected_length
        || expected_device != 0 && before.st_dev != expected_device
        || expected_inode != 0 && before.st_ino != expected_inode
    {
        return Err(InstallerError::HostMutationFailure);
    }
    validate_host_file_marker(file, transaction_id)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| InstallerError::HostMutationFailure)?;
    let maximum = u64::try_from(spec.bytes.len())
        .map_err(|_| InstallerError::HostMutationFailure)?
        .checked_add(1)
        .ok_or(InstallerError::HostMutationFailure)?;
    let mut bytes = Vec::with_capacity(spec.bytes.len());
    (&mut *file)
        .take(maximum)
        .read_to_end(&mut bytes)
        .map_err(|_| InstallerError::HostMutationFailure)?;
    let after = rfs::fstat(&*file).map_err(|_| InstallerError::HostMutationFailure)?;
    if bytes != spec.bytes || !stable_file(&before, &after, bytes.len()) {
        return Err(InstallerError::HostMutationFailure);
    }
    Ok(after)
}

fn validate_host_file_marker(
    file: &std::fs::File,
    transaction_id: &str,
) -> Result<(), InstallerError> {
    let mut marker = [0_u8; 65];
    match rfs::fgetxattr(file, "user.kapsel.transaction-id", &mut marker) {
        Ok(length) if length == 64 && marker[..length] == *transaction_id.as_bytes() => Ok(()),
        _ => Err(InstallerError::HostMutationFailure),
    }
}

fn require_destination_absent(parent: &OwnedFd, name: &OsStr) -> Result<(), InstallerError> {
    match rfs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => Ok(()),
        _ => Err(InstallerError::HostMutationFailure),
    }
}

fn publish_or_recover_host_file(
    parent: &OwnedFd,
    spec: &HostFileSpec<'_>,
    transaction_id: &str,
    expected_device: u64,
    expected_inode: u64,
) -> Result<(), InstallerError> {
    match classify_host_file_publication(
        parent,
        spec,
        transaction_id,
        expected_device,
        expected_inode,
    )? {
        HostFilePublication::Complete => Ok(()),
        HostFilePublication::NotStarted => {
            rfs::renameat_with(
                parent,
                spec.staging,
                parent,
                destination_leaf(spec.destination)?,
                RenameFlags::NOREPLACE,
            )
            .map_err(|_| InstallerError::HostMutationFailure)?;
            rfs::fsync(parent).map_err(|_| InstallerError::HostMutationFailure)?;
            validate_named_host_file(
                parent,
                destination_leaf(spec.destination)?,
                spec,
                transaction_id,
                expected_device,
                expected_inode,
            )?;
            Ok(())
        },
    }
}

fn classify_host_file_publication(
    parent: &OwnedFd,
    spec: &HostFileSpec<'_>,
    transaction_id: &str,
    expected_device: u64,
    expected_inode: u64,
) -> Result<HostFilePublication, InstallerError> {
    let destination = destination_leaf(spec.destination)?;
    let destination_exists = match rfs::statat(parent, destination, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => true,
        Err(rustix::io::Errno::NOENT) => false,
        Err(_) => return Err(InstallerError::HostMutationFailure),
    };
    let staging_exists = match rfs::statat(parent, spec.staging, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => true,
        Err(rustix::io::Errno::NOENT) => false,
        Err(_) => return Err(InstallerError::HostMutationFailure),
    };
    match (destination_exists, staging_exists) {
        (true, false) => {
            validate_named_host_file(
                parent,
                destination,
                spec,
                transaction_id,
                expected_device,
                expected_inode,
            )?;
            Ok(HostFilePublication::Complete)
        },
        (false, true) => {
            validate_named_host_file(
                parent,
                OsStr::new(spec.staging),
                spec,
                transaction_id,
                expected_device,
                expected_inode,
            )?;
            Ok(HostFilePublication::NotStarted)
        },
        _ => Err(InstallerError::HostMutationFailure),
    }
}

fn new_transaction_id() -> Result<String, InstallerError> {
    let mut bytes = [0_u8; 32];
    let mut offset = 0;
    while offset < bytes.len() {
        match rustix::rand::getrandom(&mut bytes[offset..], rustix::rand::GetRandomFlags::empty()) {
            Ok(0) => return Err(InstallerError::TransactionFailure),
            Ok(read) => offset += read,
            Err(rustix::io::Errno::INTR) => {},
            Err(_) => return Err(InstallerError::TransactionFailure),
        }
    }
    Ok(hex_bytes(&bytes))
}

async fn run_preflight(input: &OperatorInput) -> Result<(), InstallerError> {
    run_host_preflight().await?;
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        run_kubernetes_preflight(input),
    )
    .await
    .map_err(|_| InstallerError::KubernetesPreflightFailure)??;
    Ok(())
}

const HOST_TOOLS: &[&str] = &[
    "/usr/sbin/groupadd",
    "/usr/sbin/groupdel",
    "/usr/sbin/useradd",
    "/usr/sbin/nologin",
    "/usr/bin/getent",
    "/usr/bin/systemctl",
    "/usr/bin/timeout",
];

const ABSENT_HOST_PATHS: &[&str] = &[
    "/etc/kapsel",
    "/var/lib/kapsel",
    "/run/kapsel",
    "/usr/libexec/kapsel",
    "/usr/share/kapsel",
    "/usr/share/doc/kapsel",
    "/usr/bin/kapsel",
    "/usr/bin/kapsel-service-client",
    "/usr/lib/systemd/system/kapseld.service",
    "/usr/lib/sysusers.d/kapseld.conf",
    "/etc/systemd/system/multi-user.target.wants/kapseld.service",
];

fn host_path(path: &str) -> PathBuf {
    #[cfg(kapsel_installer_test_crash_seams)]
    if let Some(root) = env::var_os("KAPSEL_INSTALLER_TEST_HOST_ROOT") {
        return PathBuf::from(root).join(path.trim_start_matches('/'));
    }
    PathBuf::from(path)
}

fn open_host_directory(path: &Path) -> Result<OwnedFd, InstallerError> {
    let mut directory = rfs::openat(
        CWD,
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| InstallerError::HostPreflightFailure)?;
    for component in path.components() {
        match component {
            Component::RootDir => {},
            Component::Normal(name) => {
                directory = rfs::openat(
                    &directory,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| InstallerError::HostPreflightFailure)?;
                let metadata =
                    rfs::fstat(&directory).map_err(|_| InstallerError::HostPreflightFailure)?;
                if !root_owned_directory(&metadata) || metadata.st_mode & 0o022 != 0 {
                    return Err(InstallerError::HostPreflightFailure);
                }
            },
            _ => return Err(InstallerError::HostPreflightFailure),
        }
    }
    Ok(directory)
}

fn open_host_file(path: &Path) -> Result<OwnedFd, InstallerError> {
    let parent = path.parent().ok_or(InstallerError::HostPreflightFailure)?;
    let name = path
        .file_name()
        .ok_or(InstallerError::HostPreflightFailure)?;
    let directory = open_host_directory(parent)?;
    rfs::openat(
        &directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| InstallerError::HostPreflightFailure)
}

fn require_host_leaf_absent(path: &Path) -> Result<(), InstallerError> {
    let parent = path.parent().ok_or(InstallerError::HostPreflightFailure)?;
    let name = path
        .file_name()
        .ok_or(InstallerError::HostPreflightFailure)?;
    let directory = open_host_directory(parent)?;
    match rfs::statat(&directory, name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => Ok(()),
        _ => Err(InstallerError::HostPreflightFailure),
    }
}

async fn ensure_group(
    lock: &OwnedFd,
    transaction: &mut OpenTransaction,
    name: &'static str,
) -> Result<(), InstallerError> {
    let index = usize::from(name == "kapsel-service-callers");
    if let Some(resource) = transaction.record.host_resources.get(index) {
        if let HostResource::Group(group) = resource {
            if group.name == name
                && observe_group(name, group.gid).await? == GroupObservation::Exact
            {
                return Ok(());
            }
        }
        return Err(InstallerError::HostMutationFailure);
    }
    if transaction.record.host_resources.len() != index {
        return Err(InstallerError::HostMutationFailure);
    }

    if transaction.record.pending.is_none() {
        let getent = host_path("/usr/bin/getent");
        let groups = run_bounded_query(&getent, &["group"], 64 * 1024).await?;
        let passwd = run_bounded_query(&getent, &["passwd"], 64 * 1024).await?;
        if groups.status != 0 || passwd.status != 0 {
            return Err(InstallerError::HostMutationFailure);
        }
        let gid = select_group_gid(&groups.stdout, &passwd.stdout)
            .map_err(|_| InstallerError::HostMutationFailure)?;
        if observe_group(name, gid).await? != GroupObservation::Absent {
            return Err(InstallerError::HostMutationFailure);
        }
        let old = transaction.record.clone();
        transaction.record.pending = Some(PendingAction::CreateGroup {
            gid,
            name: String::from(name),
            transaction_id: transaction.record.transaction_id.clone(),
        });
        publish_transaction_successor(&transaction.directory, &old, &transaction.record)?;
        stop_at_group_seam(name, "group-pending", "second-group-pending");
    }

    let gid = match transaction.record.pending.as_ref() {
        Some(PendingAction::CreateGroup {
            gid,
            name: pending_name,
            transaction_id,
        }) if pending_name == name && transaction_id == &transaction.record.transaction_id => *gid,
        _ => return Err(InstallerError::HostMutationFailure),
    };
    match observe_group(name, gid).await? {
        GroupObservation::Absent => {
            run_identity_mutation(
                lock,
                &host_path("/usr/sbin/groupadd"),
                &[
                    OsString::from("--system"),
                    OsString::from("--gid"),
                    gid.to_string().into(),
                    OsString::from(name),
                ],
            )
            .await?;
            stop_at_group_seam(
                name,
                "group-command-complete",
                "second-group-command-complete",
            );
        },
        GroupObservation::Exact => {},
    }
    if observe_group(name, gid).await? != GroupObservation::Exact {
        return Err(InstallerError::HostMutationFailure);
    }

    let old = transaction.record.clone();
    transaction.record.pending = None;
    transaction
        .record
        .host_resources
        .push(HostResource::Group(GroupResource {
            gid,
            kind: GroupResourceKind::Group,
            name: String::from(name),
        }));
    publish_transaction_successor(&transaction.directory, &old, &transaction.record)
}

async fn ensure_user(
    lock: &OwnedFd,
    transaction: &mut OpenTransaction,
    spec: &UserSpec,
) -> Result<(), InstallerError> {
    let index = if spec.name == "kapsel" { 2 } else { 3 };
    let primary_gid = owned_group_gid(&transaction.record, spec.group_name)?;
    if let Some(resource) = transaction.record.host_resources.get(index) {
        if let HostResource::User(user) = resource {
            if user.name == spec.name && user.primary_gid == primary_gid {
                if observe_user(user).await? == UserObservation::Exact {
                    return Ok(());
                }
                block_identity(transaction)?;
            }
        }
        return Err(InstallerError::HostMutationFailure);
    }
    if transaction.record.host_resources.len() != index {
        return Err(InstallerError::HostMutationFailure);
    }

    if transaction.record.pending.is_none() {
        let passwd =
            run_bounded_query(&host_path("/usr/bin/getent"), &["passwd"], 64 * 1024).await?;
        if passwd.status != 0 {
            return Err(InstallerError::HostMutationFailure);
        }
        let uid =
            select_user_uid(&passwd.stdout).map_err(|_| InstallerError::HostMutationFailure)?;
        let expected = pending_user(spec, uid, primary_gid, &transaction.record.transaction_id);
        if observe_pending_user(&expected).await? != UserObservation::Absent {
            block_identity(transaction)?;
            return Err(InstallerError::HostMutationFailure);
        }
        let old = transaction.record.clone();
        transaction.record.pending = Some(expected);
        publish_transaction_successor(&transaction.directory, &old, &transaction.record)?;
        stop_at_user_seam(spec.name, "service-user-pending", "caller-user-pending");
    }

    let user = user_from_pending(&transaction.record, spec)?;
    match observe_user(&user).await? {
        UserObservation::Absent => {
            run_identity_mutation(
                lock,
                &host_path("/usr/sbin/useradd"),
                &[
                    OsString::from("--system"),
                    OsString::from("--uid"),
                    user.uid.to_string().into(),
                    OsString::from("--gid"),
                    user.primary_gid.to_string().into(),
                    OsString::from("--no-create-home"),
                    OsString::from("--home-dir"),
                    OsString::from(&user.home),
                    OsString::from("--shell"),
                    OsString::from(&user.shell),
                    OsString::from("--comment"),
                    OsString::from(&user.gecos_transaction_id),
                    OsString::from("--no-user-group"),
                    OsString::from("--no-log-init"),
                    OsString::from("--password"),
                    OsString::from("!"),
                    OsString::from(&user.name),
                ],
            )
            .await?;
            stop_at_user_seam(
                spec.name,
                "service-user-command-complete",
                "caller-user-command-complete",
            );
        },
        UserObservation::Exact => {},
        UserObservation::Conflict | UserObservation::Ambiguous => {
            block_identity(transaction)?;
            return Err(InstallerError::HostMutationFailure);
        },
    }
    match observe_user(&user).await? {
        UserObservation::Exact => {},
        UserObservation::Absent => return Err(InstallerError::HostMutationFailure),
        UserObservation::Conflict | UserObservation::Ambiguous => {
            block_identity(transaction)?;
            return Err(InstallerError::HostMutationFailure);
        },
    }
    let old = transaction.record.clone();
    transaction.record.pending = None;
    transaction
        .record
        .host_resources
        .push(HostResource::User(user));
    publish_transaction_successor(&transaction.directory, &old, &transaction.record)
}

fn block_identity(transaction: &mut OpenTransaction) -> Result<(), InstallerError> {
    let old = transaction.record.clone();
    transaction.record.phase = TransactionPhase::IdentityBlocked;
    publish_transaction_successor(&transaction.directory, &old, &transaction.record)
}

fn stop_at_user_seam(name: &str, service: &str, caller: &str) {
    stop_at_test_seam(if name == "kapsel" { service } else { caller });
}

async fn observe_pending_user(pending: &PendingAction) -> Result<UserObservation, InstallerError> {
    observe_user(&user_resource_from_pending(pending)?).await
}

async fn observe_user(user: &UserResource) -> Result<UserObservation, InstallerError> {
    let uid = user.uid.to_string();
    let Ok(by_name) = run_user_query("passwd", &user.name).await else {
        return Ok(UserObservation::Ambiguous);
    };
    let Ok(by_uid) = run_user_query("passwd", &uid).await else {
        return Ok(UserObservation::Ambiguous);
    };
    let Ok(shadow) = run_user_query("shadow", &user.name).await else {
        return Ok(UserObservation::Ambiguous);
    };
    Ok(classify_user_observation(&by_name, &by_uid, &shadow, user))
}

async fn run_user_query(database: &str, key: &str) -> Result<BoundedCommandOutput, InstallerError> {
    let timeout = host_path("/usr/bin/timeout");
    let getent = host_path("/usr/bin/getent");
    let getent = getent.to_str().ok_or(InstallerError::HostMutationFailure)?;
    run_bounded_query(
        &timeout,
        &["--signal=KILL", "10s", getent, database, key],
        4 * 1024,
    )
    .await
}

async fn rollback_groups(
    lock: &OwnedFd,
    transaction: &mut OpenTransaction,
) -> Result<(), InstallerError> {
    if transaction.record.phase == TransactionPhase::Installing {
        let old = transaction.record.clone();
        transaction.record.phase = TransactionPhase::RollingBack;
        publish_transaction_successor(&transaction.directory, &old, &transaction.record)?;
    }
    while let Some(resource) = transaction.record.host_resources.last().cloned() {
        let HostResource::Group(group) = resource else {
            return Err(InstallerError::HostMutationFailure);
        };
        stop_at_group_seam(
            &group.name,
            "group-rollback-before-pending",
            "second-group-rollback-before-pending",
        );
        if transaction.record.pending.is_none() {
            if observe_group(&group.name, group.gid).await? != GroupObservation::Exact {
                return Err(InstallerError::HostMutationFailure);
            }
            require_gid_without_primary_user(group.gid).await?;
            let old = transaction.record.clone();
            transaction.record.pending = Some(PendingAction::RemoveGroup {
                group: group.clone(),
            });
            publish_transaction_successor(&transaction.directory, &old, &transaction.record)?;
            stop_at_group_seam(
                &group.name,
                "group-remove-pending",
                "second-group-remove-pending",
            );
        } else if transaction.record.pending
            != Some(PendingAction::RemoveGroup {
                group: group.clone(),
            })
        {
            return Err(InstallerError::HostMutationFailure);
        }

        match observe_group(&group.name, group.gid).await? {
            GroupObservation::Exact => {
                require_gid_without_primary_user(group.gid).await?;
                run_identity_mutation(
                    lock,
                    &host_path("/usr/sbin/groupdel"),
                    &[OsString::from(&group.name)],
                )
                .await?;
                stop_at_group_seam(
                    &group.name,
                    "group-remove-command-complete",
                    "second-group-remove-command-complete",
                );
            },
            GroupObservation::Absent => {},
        }
        if observe_group(&group.name, group.gid).await? != GroupObservation::Absent {
            return Err(InstallerError::HostMutationFailure);
        }
        let old = transaction.record.clone();
        transaction.record.pending = None;
        transaction.record.host_resources.pop();
        publish_transaction_successor(&transaction.directory, &old, &transaction.record)?;
    }
    if transaction.record.pending.is_some() {
        return Err(InstallerError::HostMutationFailure);
    }
    let old = transaction.record.clone();
    transaction.record.phase = TransactionPhase::RolledBack;
    publish_transaction_successor(&transaction.directory, &old, &transaction.record)
}

fn stop_at_group_seam(name: &str, first: &str, second: &str) {
    stop_at_test_seam(if name == "kapsel" { first } else { second });
}

async fn require_gid_without_primary_user(gid: u32) -> Result<(), InstallerError> {
    let passwd = run_bounded_query(&host_path("/usr/bin/getent"), &["passwd"], 64 * 1024).await?;
    if passwd.status != 0
        || parse_identity_gids(&passwd.stdout, 3, 7)
            .map_err(|_| InstallerError::HostMutationFailure)?
            .contains(&gid)
    {
        return Err(InstallerError::HostMutationFailure);
    }
    Ok(())
}

async fn observe_group(name: &str, gid: u32) -> Result<GroupObservation, InstallerError> {
    let getent = host_path("/usr/bin/getent");
    let by_name = run_bounded_query(&getent, &["group", name], 4 * 1024).await?;
    let gid_string = gid.to_string();
    let by_gid = run_bounded_query(&getent, &["group", &gid_string], 4 * 1024).await?;
    classify_group_observation(
        by_name.status,
        &by_name.stdout,
        by_gid.status,
        &by_gid.stdout,
        name,
        gid,
    )
    .map_err(|_| InstallerError::HostMutationFailure)
}

async fn run_bounded_query(
    path: &Path,
    arguments: &[&str],
    maximum: usize,
) -> Result<BoundedCommandOutput, InstallerError> {
    let mut command = tokio::process::Command::new(path);
    command
        .args(arguments)
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .map_err(|_| InstallerError::HostMutationFailure)?;
    let stdout = child
        .stdout
        .take()
        .ok_or(InstallerError::HostMutationFailure)?;
    tokio::time::timeout(std::time::Duration::from_secs(10), async move {
        let mut bytes = Vec::with_capacity(maximum.saturating_add(1));
        stdout
            .take(u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1))
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| InstallerError::HostMutationFailure)?;
        let status = child
            .wait()
            .await
            .map_err(|_| InstallerError::HostMutationFailure)?;
        if bytes.len() > maximum {
            return Err(InstallerError::HostMutationFailure);
        }
        Ok(BoundedCommandOutput {
            status: status.code().ok_or(InstallerError::HostMutationFailure)?,
            stdout: bytes,
        })
    })
    .await
    .map_err(|_| InstallerError::HostMutationFailure)?
}

async fn run_identity_mutation(
    lock: &OwnedFd,
    program: &Path,
    arguments: &[OsString],
) -> Result<(), InstallerError> {
    let inherited = rustix::io::fcntl_dupfd_cloexec(lock, 3)
        .map_err(|_| InstallerError::HostMutationFailure)?;
    rustix::io::fcntl_setfd(&inherited, rustix::io::FdFlags::empty())
        .map_err(|_| InstallerError::HostMutationFailure)?;
    let mut command = tokio::process::Command::new(host_path("/usr/bin/timeout"));
    command
        .arg("--signal=KILL")
        .arg("10s")
        .arg(program)
        .args(arguments)
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .map_err(|_| InstallerError::HostMutationFailure)?;
    drop(inherited);
    let _status = tokio::time::timeout(std::time::Duration::from_secs(11), child.wait())
        .await
        .map_err(|_| InstallerError::HostMutationFailure)?
        .map_err(|_| InstallerError::HostMutationFailure)?;
    Ok(())
}

async fn run_host_preflight() -> Result<(), InstallerError> {
    if !rustix::process::geteuid().is_root()
        || !cfg!(all(target_arch = "x86_64", target_env = "gnu"))
    {
        return Err(InstallerError::HostPreflightFailure);
    }
    for tool in HOST_TOOLS {
        let path = host_path(tool);
        let descriptor = open_host_file(&path)?;
        let metadata = rfs::fstat(&descriptor).map_err(|_| InstallerError::HostPreflightFailure)?;
        if !FileType::from_raw_mode(metadata.st_mode).is_file()
            || metadata.st_uid != 0
            || metadata.st_nlink != 1
            || metadata.st_mode & 0o111 == 0
            || metadata.st_mode & 0o022 != 0
        {
            return Err(InstallerError::HostPreflightFailure);
        }
    }
    let systemd = open_host_directory(&host_path("/run/systemd/system"))?;
    let systemd = rfs::fstat(&systemd).map_err(|_| InstallerError::HostPreflightFailure)?;
    if !root_owned_directory(&systemd) || systemd.st_mode & 0o022 != 0 {
        return Err(InstallerError::HostPreflightFailure);
    }
    let systemctl = host_path("/usr/bin/systemctl");
    if run_bounded_command(&systemctl, &["show-environment"]).await? != 0
        || run_bounded_command(&systemctl, &["cat", "--no-pager", "kapseld.service"]).await? != 1
        || run_bounded_command(&systemctl, &["is-active", "--quiet", "kapseld.service"]).await? != 3
        || run_bounded_command(&systemctl, &["is-enabled", "--quiet", "kapseld.service"]).await?
            != 1
    {
        return Err(InstallerError::HostPreflightFailure);
    }
    let getent = host_path("/usr/bin/getent");
    for arguments in [
        ["passwd", "kapsel"],
        ["passwd", "kapsel-service-caller"],
        ["group", "kapsel"],
        ["group", "kapsel-service-callers"],
    ] {
        if run_bounded_command(&getent, &arguments).await? != 2 {
            return Err(InstallerError::HostPreflightFailure);
        }
    }
    for path in ABSENT_HOST_PATHS {
        require_host_leaf_absent(&host_path(path))?;
    }
    probe_destination_filesystems()?;
    Ok(())
}

async fn run_bounded_command(path: &Path, arguments: &[&str]) -> Result<i32, InstallerError> {
    let mut command = tokio::process::Command::new(path);
    command
        .args(arguments)
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    let status = tokio::time::timeout(std::time::Duration::from_secs(10), command.status())
        .await
        .map_err(|_| InstallerError::HostPreflightFailure)?
        .map_err(|_| InstallerError::HostPreflightFailure)?;
    status.code().ok_or(InstallerError::HostPreflightFailure)
}

fn probe_destination_filesystems() -> Result<(), InstallerError> {
    for parent in [
        "/etc",
        "/var/lib",
        "/run",
        "/usr/bin",
        "/usr/libexec",
        "/usr/lib/systemd/system",
        "/usr/lib/sysusers.d",
        "/usr/share",
        "/usr/share/doc",
    ] {
        let directory = open_host_directory(&host_path(parent))?;
        let metadata = rfs::fstat(&directory).map_err(|_| InstallerError::HostPreflightFailure)?;
        if !root_owned_directory(&metadata) {
            return Err(InstallerError::HostPreflightFailure);
        }
        probe_destination_filesystem(&directory)?;
    }
    Ok(())
}

fn probe_destination_filesystem(directory: &OwnedFd) -> Result<(), InstallerError> {
    const STAGING: &str = ".kapsel-installer-filesystem-probe.stage";
    const DESTINATION: &str = ".kapsel-installer-filesystem-probe";
    const MARKER: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const BYTES: &[u8] = b"kapsel installer filesystem probe";

    require_probe_leaf_absent(directory, STAGING)?;
    require_probe_leaf_absent(directory, DESTINATION)?;
    let probe = (|| {
        let descriptor = rfs::openat(
            directory,
            ".",
            OFlags::RDWR | OFlags::TMPFILE | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| InstallerError::HostPreflightFailure)?;
        rfs::fchmod(&descriptor, Mode::RUSR | Mode::WUSR)
            .map_err(|_| InstallerError::HostPreflightFailure)?;
        let mut file = std::fs::File::from(descriptor);
        file.write_all(BYTES)
            .map_err(|_| InstallerError::HostPreflightFailure)?;
        rfs::fdatasync(&file).map_err(|_| InstallerError::HostPreflightFailure)?;
        rfs::fsetxattr(
            &file,
            "user.kapsel.transaction-id",
            MARKER.as_bytes(),
            XattrFlags::CREATE,
        )
        .map_err(|_| InstallerError::HostPreflightFailure)?;
        validate_probe_file(&mut file, MARKER, 0)?;
        rfs::fsync(&file).map_err(|_| InstallerError::HostPreflightFailure)?;
        rfs::linkat(&file, "", directory, STAGING, AtFlags::EMPTY_PATH)
            .map_err(|_| InstallerError::HostPreflightFailure)?;
        rfs::fsync(directory).map_err(|_| InstallerError::HostPreflightFailure)?;
        validate_named_probe_file(directory, STAGING, MARKER)?;
        rfs::renameat_with(
            directory,
            STAGING,
            directory,
            DESTINATION,
            RenameFlags::NOREPLACE,
        )
        .map_err(|_| InstallerError::HostPreflightFailure)?;
        rfs::fsync(directory).map_err(|_| InstallerError::HostPreflightFailure)?;
        validate_named_probe_file(directory, DESTINATION, MARKER)?;
        Ok(())
    })();
    let cleanup = cleanup_probe_file(directory, STAGING, MARKER)
        .and_then(|()| cleanup_probe_file(directory, DESTINATION, MARKER))
        .and_then(|()| rfs::fsync(directory).map_err(|_| InstallerError::HostPreflightFailure));
    probe.and(cleanup)
}

fn require_probe_leaf_absent(directory: &OwnedFd, name: &str) -> Result<(), InstallerError> {
    match rfs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => Ok(()),
        _ => Err(InstallerError::HostPreflightFailure),
    }
}

fn validate_named_probe_file(
    directory: &OwnedFd,
    name: &str,
    marker: &str,
) -> Result<(), InstallerError> {
    let descriptor = rfs::openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| InstallerError::HostPreflightFailure)?;
    let mut file = std::fs::File::from(descriptor);
    validate_probe_file(&mut file, marker, 1)
}

fn validate_probe_file(
    file: &mut std::fs::File,
    marker: &str,
    expected_links: u64,
) -> Result<(), InstallerError> {
    const BYTES: &[u8] = b"kapsel installer filesystem probe";
    let before = rfs::fstat(&*file).map_err(|_| InstallerError::HostPreflightFailure)?;
    if !FileType::from_raw_mode(before.st_mode).is_file()
        || before.st_uid != 0
        || before.st_gid != 0
        || before.st_mode & 0o7777 != 0o600
        || before.st_nlink != expected_links
        || usize::try_from(before.st_size) != Ok(BYTES.len())
    {
        return Err(InstallerError::HostPreflightFailure);
    }
    let mut observed_marker = [0_u8; 65];
    if !matches!(
        rfs::fgetxattr(&*file, "user.kapsel.transaction-id", &mut observed_marker),
        Ok(64) if observed_marker[..64] == *marker.as_bytes()
    ) {
        return Err(InstallerError::HostPreflightFailure);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| InstallerError::HostPreflightFailure)?;
    let mut bytes = Vec::with_capacity(BYTES.len());
    (&mut *file)
        .take(u64::try_from(BYTES.len()).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| InstallerError::HostPreflightFailure)?;
    let after = rfs::fstat(&*file).map_err(|_| InstallerError::HostPreflightFailure)?;
    if bytes != BYTES || !stable_file(&before, &after, bytes.len()) {
        return Err(InstallerError::HostPreflightFailure);
    }
    Ok(())
}

fn cleanup_probe_file(directory: &OwnedFd, name: &str, marker: &str) -> Result<(), InstallerError> {
    match rfs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => Ok(()),
        Ok(_) => {
            validate_named_probe_file(directory, name, marker)?;
            rfs::unlinkat(directory, name, AtFlags::empty())
                .map_err(|_| InstallerError::HostPreflightFailure)
        },
        Err(_) => Err(InstallerError::HostPreflightFailure),
    }
}

async fn run_kubernetes_preflight(input: &OperatorInput) -> Result<(), InstallerError> {
    let client = load_bootstrap_client(input).await?;
    let namespaces: Api<Namespace> = Api::all(client.clone());
    let namespace = namespaces
        .get("demo")
        .await
        .map_err(|_| InstallerError::KubernetesPreflightFailure)?;
    if namespace.metadata.name.as_deref() != Some("demo") {
        return Err(InstallerError::KubernetesPreflightFailure);
    }
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), "demo");
    let deployment = deployments
        .get("agent-api")
        .await
        .map_err(|_| InstallerError::KubernetesPreflightFailure)?;
    validate_deployment_target(&deployment)?;
    if Api::<ServiceAccount>::namespaced(client.clone(), "demo")
        .get_opt("kapsel-service")
        .await
        .map_err(|_| InstallerError::KubernetesPreflightFailure)?
        .is_some()
        || Api::<Role>::namespaced(client.clone(), "demo")
            .get_opt("kapsel-service-agent-api")
            .await
            .map_err(|_| InstallerError::KubernetesPreflightFailure)?
            .is_some()
        || Api::<RoleBinding>::namespaced(client, "demo")
            .get_opt("kapsel-service-agent-api")
            .await
            .map_err(|_| InstallerError::KubernetesPreflightFailure)?
            .is_some()
    {
        return Err(InstallerError::KubernetesPreflightFailure);
    }
    Ok(())
}

async fn load_bootstrap_client(input: &OperatorInput) -> Result<kube::Client, InstallerError> {
    const RESPONSE_BYTES_MAX: usize = 2 * 1024 * 1024;
    let text = std::str::from_utf8(
        input
            .files
            .get("bootstrap-kubeconfig.yaml")
            .ok_or(InstallerError::KubernetesPreflightFailure)?,
    )
    .map_err(|_| InstallerError::KubernetesPreflightFailure)?;
    let mut kubeconfig = kube::config::Kubeconfig::from_yaml(text)
        .map_err(|_| InstallerError::KubernetesPreflightFailure)?;
    kubeconfig.current_context = Some(input.bootstrap.selected_context.clone());
    let proxy_placeholder = configure_explicit_kubeconfig(&mut kubeconfig)?;
    let options = KubeConfigOptions {
        context: Some(input.bootstrap.selected_context.clone()),
        ..KubeConfigOptions::default()
    };
    let mut config = Config::from_custom_kubeconfig(kubeconfig, &options)
        .await
        .map_err(|_| InstallerError::KubernetesPreflightFailure)?;
    if proxy_placeholder {
        config.proxy_url = None;
    }
    config.connect_timeout = Some(std::time::Duration::from_secs(10));
    config.read_timeout = Some(std::time::Duration::from_secs(10));
    config.write_timeout = Some(std::time::Duration::from_secs(10));
    let limit = MapResponseBodyLayer::new(|body| Limited::new(body, RESPONSE_BYTES_MAX));
    Ok(kube::client::ClientBuilder::try_from(config)
        .map_err(|_| InstallerError::KubernetesPreflightFailure)?
        .with_layer(&limit)
        .build())
}

fn configure_explicit_kubeconfig(
    kubeconfig: &mut kube::config::Kubeconfig,
) -> Result<bool, InstallerError> {
    let current = kubeconfig
        .current_context
        .as_deref()
        .ok_or(InstallerError::KubernetesPreflightFailure)?;
    let context = kubeconfig
        .contexts
        .iter()
        .find(|value| value.name == current)
        .and_then(|value| value.context.as_ref())
        .ok_or(InstallerError::KubernetesPreflightFailure)?;
    let cluster_name = context.cluster.clone();
    let cluster = kubeconfig
        .clusters
        .iter_mut()
        .find(|value| value.name == cluster_name)
        .and_then(|value| value.cluster.as_mut())
        .ok_or(InstallerError::KubernetesPreflightFailure)?;
    if cluster.certificate_authority.is_some() {
        return Err(InstallerError::KubernetesPreflightFailure);
    }
    if cluster.proxy_url.as_deref().is_none_or(str::is_empty) {
        cluster.proxy_url = Some(String::from("http://127.0.0.1"));
        Ok(true)
    } else {
        Ok(false)
    }
}

fn digest_running_installer() -> Result<String, InstallerError> {
    let descriptor = rfs::openat(
        CWD,
        "/proc/self/exe",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| InstallerError::TransactionFailure)?;
    let before = rfs::fstat(&descriptor).map_err(|_| InstallerError::TransactionFailure)?;
    if !FileType::from_raw_mode(before.st_mode).is_file()
        || before.st_size <= 0
        || usize::try_from(before.st_size).map_or(true, |length| length > INSTALLER_BYTES_MAX)
    {
        return Err(InstallerError::TransactionFailure);
    }
    let capacity =
        usize::try_from(before.st_size).map_err(|_| InstallerError::TransactionFailure)?;
    let mut file = std::fs::File::from(descriptor);
    let mut bytes = Vec::with_capacity(capacity);
    (&mut file)
        .take(u64::try_from(INSTALLER_BYTES_MAX).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| InstallerError::TransactionFailure)?;
    let after = rfs::fstat(&file).map_err(|_| InstallerError::TransactionFailure)?;
    if bytes.is_empty()
        || bytes.len() > INSTALLER_BYTES_MAX
        || !stable_file(&before, &after, bytes.len())
    {
        return Err(InstallerError::TransactionFailure);
    }
    Ok(hex_digest(&bytes))
}

fn with_exact_creation_mode<T>(create: impl FnOnce() -> T) -> T {
    let previous_umask = rustix::process::umask(Mode::empty());
    let result = create();
    rustix::process::umask(previous_umask);
    result
}

#[cfg(kapsel_installer_test_crash_seams)]
fn stop_at_test_seam(seam: &str) {
    if std::env::var("KAPSEL_INSTALLER_TEST_STOP_AT_SEAM").as_deref() == Ok(seam) {
        rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::STOP)
            .expect("test crash seam must stop the installer");
    }
}

#[cfg(not(kapsel_installer_test_crash_seams))]
fn stop_at_test_seam(_: &str) {}

#[cfg(kapsel_installer_test_crash_seams)]
fn fail_at_test_seam(seam: &str) -> bool {
    std::env::var("KAPSEL_INSTALLER_TEST_FAIL_AT_SEAM").as_deref() == Ok(seam)
}

#[cfg(not(kapsel_installer_test_crash_seams))]
fn fail_at_test_seam(_: &str) -> bool {
    false
}

fn acquire_installer_lock() -> Result<OwnedFd, InstallerError> {
    let root = rfs::openat(
        CWD,
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| InstallerError::InstallerLockFailure)?;
    let run = open_directory(&root, "run", InstallerError::InstallerLockFailure)?;
    let run_metadata = rfs::fstat(&run).map_err(|_| InstallerError::InstallerLockFailure)?;
    if !root_owned_directory(&run_metadata) || run_metadata.st_mode & 0o022 != 0 {
        return Err(InstallerError::InstallerLockFailure);
    }
    let lock_directory = open_directory(&run, "lock", InstallerError::InstallerLockFailure)?;
    let lock_directory_metadata =
        rfs::fstat(&lock_directory).map_err(|_| InstallerError::InstallerLockFailure)?;
    if !root_owned_directory(&lock_directory_metadata)
        || lock_directory_metadata.st_mode & 0o022 != 0
            && lock_directory_metadata.st_mode & 0o1000 == 0
    {
        return Err(InstallerError::InstallerLockFailure);
    }

    let create_flags = OFlags::RDWR
        | OFlags::CREATE
        | OFlags::EXCL
        | OFlags::NOFOLLOW
        | OFlags::NONBLOCK
        | OFlags::CLOEXEC;
    let descriptor = match with_exact_creation_mode(|| {
        rfs::openat(
            &lock_directory,
            "kapsel-installer.lock",
            create_flags,
            Mode::RUSR | Mode::WUSR,
        )
    }) {
        Ok(descriptor) => {
            stop_at_test_seam("installer-lock");
            rfs::fchmod(&descriptor, Mode::RUSR | Mode::WUSR)
                .map_err(|_| InstallerError::InstallerLockFailure)?;
            descriptor
        },
        Err(rustix::io::Errno::EXIST) => rfs::openat(
            &lock_directory,
            "kapsel-installer.lock",
            OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| InstallerError::InstallerLockFailure)?,
        Err(_) => return Err(InstallerError::InstallerLockFailure),
    };
    let before = rfs::fstat(&descriptor).map_err(|_| InstallerError::InstallerLockFailure)?;
    if !valid_installer_lock(&before) {
        return Err(InstallerError::InstallerLockFailure);
    }
    rfs::flock(&descriptor, FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| InstallerError::InstallerLockFailure)?;
    let after = rfs::fstat(&descriptor).map_err(|_| InstallerError::InstallerLockFailure)?;
    if !valid_installer_lock(&after) || !stable_lock(&before, &after) {
        return Err(InstallerError::InstallerLockFailure);
    }
    Ok(descriptor)
}

fn open_directory(
    parent: &OwnedFd,
    name: &str,
    error: InstallerError,
) -> Result<OwnedFd, InstallerError> {
    rfs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| error)
}

fn root_owned_directory(metadata: &Stat) -> bool {
    FileType::from_raw_mode(metadata.st_mode).is_dir() && metadata.st_uid == 0
}

fn valid_installer_lock(metadata: &Stat) -> bool {
    FileType::from_raw_mode(metadata.st_mode).is_file()
        && metadata.st_uid == 0
        && metadata.st_mode & 0o7777 == 0o600
        && metadata.st_nlink == 1
}

fn stable_lock(before: &Stat, after: &Stat) -> bool {
    before.st_dev == after.st_dev
        && before.st_ino == after.st_ino
        && before.st_mode == after.st_mode
        && before.st_uid == after.st_uid
        && before.st_gid == after.st_gid
        && before.st_nlink == after.st_nlink
}

fn validate_operator_input(
    path: &Path,
    kube_context: &str,
) -> Result<OperatorInput, InstallerError> {
    let directory = open_absolute_directory_without_symlinks(path)?;
    let before = rfs::fstat(&directory).map_err(|_| InstallerError::InvalidOperatorInput)?;
    if !valid_operator_directory(&before) {
        return Err(InstallerError::InvalidOperatorInput);
    }
    let expected = OPERATOR_FILES
        .iter()
        .map(|(name, _)| (*name).to_owned())
        .collect::<BTreeSet<_>>();
    if directory_names(&directory, InstallerError::InvalidOperatorInput)? != expected {
        return Err(InstallerError::InvalidOperatorInput);
    }

    let mut inputs = BTreeMap::new();
    for (name, maximum) in OPERATOR_FILES {
        inputs.insert(*name, read_operator_file(&directory, name, *maximum)?);
    }
    let after = rfs::fstat(&directory).map_err(|_| InstallerError::InvalidOperatorInput)?;
    if !stable_directory(&before, &after) {
        return Err(InstallerError::InvalidOperatorInput);
    }

    let authorization_public_key = exact_32(&inputs, "authorization.pub")?;
    let receipt_signing_seed = exact_32(&inputs, "receipt.seed")?;
    let identity = kapsel_authority::validate_service_operator_inputs(
        inputs
            .get("grant.bin")
            .ok_or(InstallerError::InvalidOperatorInput)?,
        &authorization_public_key,
        &receipt_signing_seed,
        inputs
            .get("receipt.trust")
            .ok_or(InstallerError::InvalidOperatorInput)?,
    )
    .map_err(|_| InstallerError::InvalidOperatorInput)?;
    let bootstrap = parse_bootstrap_kubeconfig(
        inputs
            .get("bootstrap-kubeconfig.yaml")
            .ok_or(InstallerError::InvalidOperatorInput)?,
        kube_context,
    )?;
    Ok(OperatorInput {
        _directory: directory,
        directory_metadata: after,
        files: inputs,
        identity,
        path: path
            .to_str()
            .ok_or(InstallerError::InvalidOperatorInput)?
            .to_owned(),
        bootstrap,
    })
}

fn open_absolute_directory_without_symlinks(path: &Path) -> Result<OwnedFd, InstallerError> {
    let mut directory = rfs::openat(
        CWD,
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| InstallerError::InvalidOperatorInput)?;
    let mut saw_component = false;
    for component in path.components() {
        match component {
            Component::RootDir => {},
            Component::Normal(name) => {
                directory = rfs::openat(
                    &directory,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| InstallerError::InvalidOperatorInput)?;
                saw_component = true;
            },
            _ => return Err(InstallerError::InvalidOperatorInput),
        }
    }
    if !saw_component {
        return Err(InstallerError::InvalidOperatorInput);
    }
    Ok(directory)
}

fn valid_operator_directory(metadata: &Stat) -> bool {
    FileType::from_raw_mode(metadata.st_mode).is_dir()
        && metadata.st_uid == 0
        && metadata.st_mode & 0o7777 == 0o700
}

fn directory_names(
    directory: &OwnedFd,
    error: InstallerError,
) -> Result<BTreeSet<String>, InstallerError> {
    let mut buffer = [MaybeUninit::uninit(); 4096];
    let mut entries = RawDir::new(directory, &mut buffer);
    let mut names = BTreeSet::new();
    while let Some(entry) = entries.next() {
        let entry = entry.map_err(|_| error)?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        let name = std::str::from_utf8(bytes).map_err(|_| error)?;
        if !names.insert(name.to_owned()) {
            return Err(error);
        }
    }
    Ok(names)
}

fn read_operator_file(
    directory: &OwnedFd,
    name: &str,
    maximum: usize,
) -> Result<Vec<u8>, InstallerError> {
    let descriptor = rfs::openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| InstallerError::InvalidOperatorInput)?;
    let before = rfs::fstat(&descriptor).map_err(|_| InstallerError::InvalidOperatorInput)?;
    if !FileType::from_raw_mode(before.st_mode).is_file()
        || before.st_uid != 0
        || before.st_mode & 0o7777 != 0o600
        || before.st_nlink != 1
        || before.st_size < 0
        || usize::try_from(before.st_size).map_or(true, |length| length > maximum)
    {
        return Err(InstallerError::InvalidOperatorInput);
    }
    let capacity =
        usize::try_from(before.st_size).map_err(|_| InstallerError::InvalidOperatorInput)?;
    let mut file = std::fs::File::from(descriptor);
    let mut bytes = Vec::with_capacity(capacity);
    (&mut file)
        .take(u64::try_from(maximum).map_err(|_| InstallerError::InvalidOperatorInput)? + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| InstallerError::InvalidOperatorInput)?;
    let after = rfs::fstat(&file).map_err(|_| InstallerError::InvalidOperatorInput)?;
    if bytes.len() > maximum || !stable_file(&before, &after, bytes.len()) {
        return Err(InstallerError::InvalidOperatorInput);
    }
    Ok(bytes)
}

fn exact_32(inputs: &BTreeMap<&str, Vec<u8>>, name: &str) -> Result<[u8; 32], InstallerError> {
    inputs
        .get(name)
        .ok_or(InstallerError::InvalidOperatorInput)?
        .as_slice()
        .try_into()
        .map_err(|_| InstallerError::InvalidOperatorInput)
}

fn stable_directory(before: &Stat, after: &Stat) -> bool {
    before.st_dev == after.st_dev
        && before.st_ino == after.st_ino
        && before.st_mode == after.st_mode
        && before.st_uid == after.st_uid
        && before.st_gid == after.st_gid
        && before.st_nlink == after.st_nlink
        && before.st_mtime == after.st_mtime
        && before.st_mtime_nsec == after.st_mtime_nsec
        && before.st_ctime == after.st_ctime
        && before.st_ctime_nsec == after.st_ctime_nsec
}

fn stable_file(before: &Stat, after: &Stat, length: usize) -> bool {
    before.st_dev == after.st_dev
        && before.st_ino == after.st_ino
        && before.st_mode == after.st_mode
        && before.st_uid == after.st_uid
        && before.st_gid == after.st_gid
        && before.st_nlink == after.st_nlink
        && before.st_size == after.st_size
        && before.st_mtime == after.st_mtime
        && before.st_mtime_nsec == after.st_mtime_nsec
        && before.st_ctime == after.st_ctime
        && before.st_ctime_nsec == after.st_ctime_nsec
        && usize::try_from(after.st_size) == Ok(length)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    #[test]
    fn bounded_query_rejects_oversized_timed_out_and_signaled_commands() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime must build");
        runtime.block_on(async {
            assert!(
                run_bounded_query(Path::new("/bin/sh"), &["-c", "printf 12345"], 4)
                    .await
                    .is_err()
            );
            assert!(
                run_bounded_query(Path::new("/bin/sh"), &["-c", "kill -TERM $$"], 4)
                    .await
                    .is_err()
            );
            assert!(
                run_bounded_query(Path::new("/bin/sh"), &["-c", "sleep 11"], 4)
                    .await
                    .is_err()
            );
        });
    }

    #[test]
    fn named_creation_has_exact_mode_before_repair_under_hostile_umask() {
        const CHILD: &str = "KAPSEL_INSTALLER_UMASK_CHILD";
        const TEST: &str =
            "linux::tests::named_creation_has_exact_mode_before_repair_under_hostile_umask";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(
                std::env::current_exe().expect("current test executable must resolve"),
            )
            .args(["--exact", TEST])
            .env(CHILD, "1")
            .status()
            .expect("isolated umask test must start");
            assert!(status.success());
            return;
        }

        let fixture =
            std::env::temp_dir().join(format!("kapsel-installer-creation-{}", std::process::id()));
        std::fs::create_dir(&fixture).expect("fixture parent must be created");
        let parent = rfs::openat(
            CWD,
            &fixture,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("fixture parent must open");
        rustix::process::umask(Mode::from_raw_mode(0o777));
        with_exact_creation_mode(|| rfs::mkdirat(&parent, "state", Mode::RWXU))
            .expect("state directory must be created");
        let lock = with_exact_creation_mode(|| {
            rfs::openat(
                &parent,
                "lock",
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
        })
        .expect("lock must be created");
        assert_eq!(
            std::fs::metadata(fixture.join("state"))
                .expect("state metadata must be readable")
                .permissions()
                .mode()
                & 0o7777,
            0o700
        );
        assert_eq!(
            rfs::fstat(&lock)
                .expect("lock metadata must be readable")
                .st_mode
                & 0o7777,
            0o600
        );
        drop(lock);
        drop(parent);
        std::fs::remove_dir_all(fixture).expect("fixture must be removed");
    }

    #[test]
    fn initial_publication_has_no_named_partial_before_link() {
        let Some((path, directory)) = transaction_test_directory() else {
            return;
        };
        let bytes = encode_transaction(&test_initial_transaction()).expect("fixture must encode");
        initial_publication_has_no_named_partial(&path, &directory, &bytes);
        successor_publication_recovers_and_preserves_conflicts(&path, &directory);
        drop(directory);
        std::fs::remove_file(path.join("transaction.json"))
            .expect("fixture transaction must be removed");
        std::fs::remove_dir(path).expect("fixture directory must be removed");
    }

    fn transaction_test_directory() -> Option<(std::path::PathBuf, OwnedFd)> {
        let path = std::env::temp_dir().join(format!(
            "kapsel-installer-transaction-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir(&path).expect("fixture directory must be created");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .expect("fixture mode must be set");
        let directory = rfs::openat(
            CWD,
            &path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("fixture directory must open");
        if rfs::fstat(&directory)
            .expect("fixture metadata must be readable")
            .st_uid
            == 0
        {
            Some((path, directory))
        } else {
            drop(directory);
            std::fs::remove_dir(&path).expect("fixture directory must be removed");
            None
        }
    }

    fn initial_publication_has_no_named_partial(
        path: &std::path::Path,
        directory: &OwnedFd,
        bytes: &[u8],
    ) {
        let unnamed = write_transaction_inode(directory, bytes, None).expect("O_TMPFILE must work");
        assert_eq!(
            std::fs::read_dir(path)
                .expect("fixture directory must be readable")
                .count(),
            0
        );
        drop(unnamed);
        assert_eq!(
            std::fs::read_dir(path)
                .expect("fixture directory must be readable")
                .count(),
            0
        );
        let linked = write_transaction_inode(directory, bytes, None).expect("O_TMPFILE must work");
        link_transaction_inode(directory, &linked, "transaction.json")
            .expect("AT_EMPTY_PATH must work");
        assert_eq!(
            std::fs::read(path.join("transaction.json")).expect("linked record must be readable"),
            bytes
        );
        rfs::fsync(directory).expect("fixture directory must sync");
        assert_eq!(
            read_transaction_leaf(directory, "transaction.json", false)
                .expect("published transaction must decode"),
            test_initial_transaction()
        );
    }

    fn successor_publication_recovers_and_preserves_conflicts(
        path: &std::path::Path,
        directory: &OwnedFd,
    ) {
        let mut next = test_initial_transaction();
        next.phase = TransactionPhase::Installing;
        let next_bytes = encode_transaction(&next).expect("successor must encode");
        let abandoned = write_transaction_inode(directory, &next_bytes, Some(&next.transaction_id))
            .expect("marked successor inode must be written");
        drop(abandoned);
        assert!(!path.join(".transaction.next").exists());
        let staged = write_transaction_inode(directory, &next_bytes, Some(&next.transaction_id))
            .expect("marked successor inode must be written");
        link_transaction_inode(directory, &staged, ".transaction.next")
            .expect("successor must link no-replace");
        assert_eq!(
            recover_transaction_successor(
                directory,
                &test_initial_transaction(),
                &next.bootstrap_kubeconfig_sha256,
            )
            .expect("linked successor must recover"),
            next
        );
        assert!(!path.join(".transaction.next").exists());
        let mut installed = next.clone();
        installed.phase = TransactionPhase::Installed;
        publish_transaction_successor(
            directory,
            &read_transaction_leaf(directory, "transaction.json", true)
                .expect("recovered successor must decode"),
            &installed,
        )
        .expect("complete successor protocol must publish");
        let mut invalid = installed;
        invalid.action = Action::Uninstall;
        invalid.phase = TransactionPhase::Uninstalled;
        let invalid_bytes = encode_transaction(&invalid).expect("invalid successor must encode");
        let conflicting =
            write_transaction_inode(directory, &invalid_bytes, Some(&invalid.transaction_id))
                .expect("conflicting successor inode must be written");
        link_transaction_inode(directory, &conflicting, ".transaction.next")
            .expect("conflicting successor must link");
        rfs::fsync(directory).expect("conflicting successor name must sync");
        let current = read_transaction_leaf(directory, "transaction.json", true)
            .expect("current transaction must decode");
        assert!(matches!(
            recover_transaction_successor(directory, &current, &next.bootstrap_kubeconfig_sha256,),
            Err(InstallerError::TransactionFailure)
        ));
        assert!(path.join(".transaction.next").exists());
        rfs::unlinkat(directory, ".transaction.next", AtFlags::empty())
            .expect("conflicting successor must be removed by the test");
        drop(conflicting);
        drop(staged);
    }

    #[test]
    fn filesystem_probe_exercises_publication_and_leaves_no_named_artifact() {
        if !rustix::process::geteuid().is_root() {
            return;
        }
        let path = std::path::PathBuf::from("/root").join(format!(
            "kapsel-installer-probe-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir(&path).expect("probe fixture must be created");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("probe fixture mode must be set");
        let directory = open_host_directory(&path).expect("probe fixture must open");
        probe_destination_filesystem(&directory).expect("filesystem probe must pass");
        assert_eq!(std::fs::read_dir(&path).unwrap().count(), 0);

        let conflict = path.join(".kapsel-installer-filesystem-probe");
        std::fs::write(&conflict, b"unowned").expect("probe conflict must be written");
        assert!(probe_destination_filesystem(&directory).is_err());
        assert_eq!(std::fs::read(&conflict).unwrap(), b"unowned");

        drop(directory);
        std::fs::remove_dir_all(path).expect("probe fixture must be removed");
    }

    #[test]
    fn host_file_foundation_publishes_exact_inode_and_rejects_unmarked_staging() {
        if !rustix::process::geteuid().is_root() {
            return;
        }
        let (transaction_path, transaction_directory) =
            transaction_test_directory().expect("root fixture must be available");
        let host_path = std::path::PathBuf::from("/root").join(format!(
            "kapsel-installer-host-file-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir(&host_path).expect("host fixture must be created");
        std::fs::set_permissions(&host_path, std::fs::Permissions::from_mode(0o755))
            .expect("host fixture mode must be set");
        let first_destination = host_path.join("asset-one");
        let first_destination = first_destination
            .to_str()
            .expect("host fixture destination must be UTF-8");
        let second_destination = host_path.join("asset-two");
        let second_destination = second_destination
            .to_str()
            .expect("host fixture destination must be UTF-8");

        let record = complete_identity_test_transaction();
        publish_initial_transaction(
            &transaction_directory,
            &encode_transaction(&record).expect("identity record must encode"),
        )
        .expect("identity record must publish");
        let mut transaction = OpenTransaction {
            directory: transaction_directory,
            record,
        };
        let first = HostFileSpec {
            bytes: b"first fixture bytes",
            destination: first_destination,
            gid: 0,
            mode: 0o644,
            staging: ".kapsel-stage-one",
            uid: 0,
        };
        ensure_host_file(&mut transaction, &first).expect("host file must publish");
        assert_eq!(
            std::fs::read(host_path.join("asset-one")).unwrap(),
            first.bytes
        );
        assert!(transaction.record.pending.is_none());
        assert_eq!(transaction.record.host_resources.len(), 5);
        ensure_host_file(&mut transaction, &first).expect("exact published inode must reopen");

        std::fs::write(host_path.join("asset-one"), b"changed").unwrap();
        assert!(ensure_host_file(&mut transaction, &first).is_err());
        std::fs::write(host_path.join("asset-one"), first.bytes).unwrap();
        ensure_host_file(&mut transaction, &first).expect("restored exact inode must reopen");

        let second = HostFileSpec {
            bytes: b"second fixture bytes",
            destination: second_destination,
            gid: 0,
            mode: 0o644,
            staging: ".kapsel-stage-two",
            uid: 0,
        };
        std::fs::write(host_path.join(second.staging), second.bytes).unwrap();
        std::fs::set_permissions(
            host_path.join(second.staging),
            std::fs::Permissions::from_mode(second.mode),
        )
        .unwrap();
        assert!(ensure_host_file(&mut transaction, &second).is_err());
        assert!(!host_path.join("asset-two").exists());
        assert!(matches!(
            transaction.record.pending,
            Some(PendingAction::StageHost {
                device: None,
                inode: None,
                ..
            })
        ));

        drop(transaction.directory);
        std::fs::remove_dir_all(host_path).unwrap();
        std::fs::remove_dir_all(transaction_path).unwrap();
    }

    fn complete_identity_test_transaction() -> InstallerTransaction {
        let mut transaction = test_initial_transaction();
        transaction.phase = TransactionPhase::Installing;
        transaction.host_resources = vec![
            HostResource::Group(GroupResource {
                gid: 999,
                kind: GroupResourceKind::Group,
                name: String::from("kapsel"),
            }),
            HostResource::Group(GroupResource {
                gid: 998,
                kind: GroupResourceKind::Group,
                name: String::from("kapsel-service-callers"),
            }),
            HostResource::User(UserResource {
                gecos_transaction_id: transaction.transaction_id.clone(),
                home: String::from("/var/lib/kapsel"),
                kind: UserResourceKind::User,
                locked: true,
                name: String::from("kapsel"),
                primary_gid: 999,
                shell: String::from("/usr/sbin/nologin"),
                uid: 997,
            }),
            HostResource::User(UserResource {
                gecos_transaction_id: transaction.transaction_id.clone(),
                home: String::from("/nonexistent"),
                kind: UserResourceKind::User,
                locked: true,
                name: String::from("kapsel-service-caller"),
                primary_gid: 998,
                shell: String::from("/usr/sbin/nologin"),
                uid: 996,
            }),
        ];
        transaction
    }
}
