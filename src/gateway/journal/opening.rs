//! Owner-private journal opening, backup verification, and rollback-file recovery.
//!
//! This implementation is Unix-specific and private to the journal. It creates no selectable
//! storage interface and exposes no backup, restore, migration, or filesystem sequencing to gateway
//! callers.

use std::{
    fs::{self, File},
    io::{self, Read as _, Seek as _, SeekFrom},
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
};

#[cfg(test)]
use rusqlite::Transaction;
use rusqlite::{limits::Limit, Connection, TransactionBehavior};
use rustix::fs::{open, Mode, OFlags};
use sha2::{Digest, Sha256};

use super::{schema, GatewayError};

const SQLITE_HEADER_BYTES: usize = 100;
const SQLITE_USER_VERSION_OFFSET: usize = 60;
const JOURNAL_BYTES_MAX: u64 = 64 * 1024 * 1024;
pub(super) const ROLLBACK_JOURNAL_BYTES_MAX: u64 = 65 * 1024 * 1024;
const BACKUP_SUFFIX: &str = ".kapsel-v011.backup";
const BACKUP_DIGEST_SUFFIX: &str = ".sha256";

const _: () = assert!(SQLITE_USER_VERSION_OFFSET + size_of::<u32>() <= SQLITE_HEADER_BYTES);
const _: () = assert!(JOURNAL_BYTES_MAX < ROLLBACK_JOURNAL_BYTES_MAX);

pub(super) struct OpenedJournal {
    pub(super) connection: Connection,
    pub(super) worker_lock: File,
}

pub(super) fn open_journal(path: &Path) -> Result<OpenedJournal, GatewayError> {
    require_private_parent(path).map_err(GatewayError::JournalFile)?;
    let mut database_file = open_private_file(path).map_err(GatewayError::JournalFile)?;
    let database_identity = database_file
        .metadata()
        .map_err(GatewayError::JournalFile)?;
    if database_identity.len() > JOURNAL_BYTES_MAX {
        return Err(GatewayError::InvalidPersistedState);
    }
    let fresh = database_identity.len() == 0;
    let initial_version = read_header_version(&mut database_file)?;
    if !fresh
        && initial_version != 0
        && initial_version != 2
        && initial_version != schema::JOURNAL_FORMAT_VERSION
    {
        return Err(GatewayError::UnsupportedJournalVersion);
    }
    recover_private_rollback_journal(path, &database_identity)?;
    let database_identity = database_file
        .metadata()
        .map_err(GatewayError::JournalFile)?;
    if database_identity.len() > JOURNAL_BYTES_MAX {
        return Err(GatewayError::InvalidPersistedState);
    }
    require_named_identity(path, &database_identity).map_err(GatewayError::JournalFile)?;
    let source_version = read_header_version(&mut database_file)?;
    if !fresh
        && source_version != 0
        && source_version != 2
        && source_version != schema::JOURNAL_FORMAT_VERSION
    {
        return Err(GatewayError::UnsupportedJournalVersion);
    }
    let backup_digest = if !fresh && source_version == 0 {
        Some(verify_offline_backup(
            path,
            &mut database_file,
            &database_identity,
        )?)
    } else {
        None
    };
    #[cfg(test)]
    migration_recovery_process_loss_seam(source_version);

    let mut connection = Connection::open(path).map_err(GatewayError::Database)?;
    connection
        .set_limit(Limit::SQLITE_LIMIT_LENGTH, schema::PERSISTED_ROW_BYTES_MAX)
        .map_err(GatewayError::Database)?;
    require_named_identity(path, &database_identity).map_err(GatewayError::JournalFile)?;
    require_private_parent(path).map_err(GatewayError::JournalFile)?;
    configure_durable_connection(&connection)?;
    let opened_version = connection
        .query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))
        .map_err(GatewayError::Database)?;
    if opened_version != source_version {
        return Err(GatewayError::InvalidPersistedState);
    }
    if fresh || source_version == 0 {
        initialize_journal(
            &mut connection,
            &mut database_file,
            fresh,
            backup_digest.as_deref(),
        )?;
    } else if source_version == 2 {
        schema::upgrade_v2(&mut connection)?;
    } else if !schema::recognized_supported_schema(&connection)? {
        return Err(GatewayError::InvalidPersistedState);
    }

    let worker_lock_path = worker_lock_path(path);
    let worker_lock = open_private_file(&worker_lock_path).map_err(GatewayError::WorkerLock)?;
    let worker_lock_identity = worker_lock.metadata().map_err(GatewayError::WorkerLock)?;
    require_named_identity(&worker_lock_path, &worker_lock_identity)
        .map_err(GatewayError::WorkerLock)?;
    Ok(OpenedJournal {
        connection,
        worker_lock,
    })
}

fn initialize_journal(
    connection: &mut Connection,
    database_file: &mut File,
    fresh: bool,
    backup_digest: Option<&str>,
) -> Result<(), GatewayError> {
    #[cfg(test)]
    migration_process_loss_seam("before_exclusive_transaction");
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Exclusive)
        .map_err(GatewayError::Database)?;
    if let Some(expected) = backup_digest {
        if digest_file(database_file).map_err(GatewayError::JournalBackup)? != expected {
            return Err(GatewayError::JournalBackupMismatch);
        }
        schema::require_integrity(&transaction)?;
    }
    schema::initialize_schema(&transaction, fresh)?;
    transaction
        .pragma_update(None, "user_version", schema::JOURNAL_FORMAT_VERSION)
        .map_err(GatewayError::Database)?;
    #[cfg(test)]
    force_hot_rollback_journal_for_process_loss(&transaction, database_file)?;
    #[cfg(test)]
    migration_process_loss_seam("marker_set_inside_exclusive_transaction");
    transaction.commit().map_err(GatewayError::Database)?;
    #[cfg(test)]
    migration_process_loss_seam("after_marker_commit");
    let version = connection
        .query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))
        .map_err(GatewayError::Database)?;
    if version != schema::JOURNAL_FORMAT_VERSION
        || !schema::recognized_supported_schema(connection)?
    {
        return Err(GatewayError::InvalidPersistedState);
    }
    Ok(())
}

#[cfg(test)]
fn force_hot_rollback_journal_for_process_loss(
    transaction: &Transaction<'_>,
    database_file: &mut File,
) -> Result<(), GatewayError> {
    use std::io::Write as _;
    if std::env::var("KAPSEL_V011_UPGRADE_MIGRATION_SEAM").as_deref()
        != Ok("marker_set_inside_exclusive_transaction")
    {
        return Ok(());
    }
    transaction
        .execute_batch(
            "PRAGMA cache_size = 1;
             PRAGMA cache_spill = ON;
             CREATE TABLE v011_upgrade_hot_rollback_probe (
                 page INTEGER PRIMARY KEY,
                 payload BLOB NOT NULL
             ) STRICT;",
        )
        .map_err(GatewayError::Database)?;
    for page in 0..32 {
        transaction
            .execute(
                "INSERT INTO v011_upgrade_hot_rollback_probe(page, payload)
                 VALUES (?1, zeroblob(8192))",
                [page],
            )
            .map_err(GatewayError::Database)?;
    }
    transaction.cache_flush().map_err(GatewayError::Database)?;
    // SQLite can keep page 1 pinned even after spilling the probe pages. This test-only write
    // materializes the transaction's already-selected marker bytes in that main-database page;
    // the hot journal still owns the original page and must restore marker 0 after process loss.
    database_file
        .seek(SeekFrom::Start(SQLITE_USER_VERSION_OFFSET as u64))
        .and_then(|_| database_file.write_all(&schema::JOURNAL_FORMAT_VERSION.to_be_bytes()))
        .and_then(|()| database_file.sync_all())
        .and_then(|()| database_file.seek(SeekFrom::Start(0)).map(|_| ()))
        .map_err(GatewayError::JournalFile)
}

#[cfg(test)]
fn migration_recovery_process_loss_seam(source_version: u32) {
    if std::env::var_os("KAPSEL_V011_UPGRADE_RECOVERY_CHILD").is_none() {
        return;
    }
    assert_eq!(
        source_version, 0,
        "hot rollback must restore the old marker"
    );
    migration_ready_marker(
        "KAPSEL_V011_UPGRADE_RECOVERY_READY",
        "hot_rollback_restored",
    );
}

#[cfg(test)]
fn migration_process_loss_seam(selected: &str) {
    if std::env::var("KAPSEL_V011_UPGRADE_MIGRATION_SEAM").as_deref() != Ok(selected) {
        return;
    }
    migration_ready_marker("KAPSEL_V011_UPGRADE_MIGRATION_READY", selected);
}

#[cfg(test)]
fn migration_ready_marker(environment: &str, selected: &str) {
    use std::{io::Write as _, os::unix::fs::OpenOptionsExt as _, time::Duration};

    let ready = PathBuf::from(
        std::env::var_os(environment)
            .expect("the migration process-loss seam requires a ready path"),
    );
    let mut marker = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&ready)
        .expect("the migration process-loss ready marker must be new");
    marker
        .write_all(selected.as_bytes())
        .expect("the migration process-loss marker must be writable");
    marker
        .sync_all()
        .expect("the migration process-loss marker must synchronize");
    loop {
        std::thread::sleep(Duration::from_mins(1));
    }
}

fn configure_durable_connection(connection: &Connection) -> Result<(), GatewayError> {
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(GatewayError::Database)?;
    let journal_mode = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
        .map_err(GatewayError::Database)?;
    if !journal_mode.eq_ignore_ascii_case("delete") {
        return Err(GatewayError::InvalidPersistedState);
    }
    connection
        .pragma_update(None, "journal_mode", "DELETE")
        .map_err(GatewayError::Database)?;
    let verified_mode = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
        .map_err(GatewayError::Database)?;
    let synchronous = connection
        .query_row("PRAGMA synchronous", [], |row| row.get::<_, i64>(0))
        .map_err(GatewayError::Database)?;
    if !verified_mode.eq_ignore_ascii_case("delete") || synchronous != 2 {
        return Err(GatewayError::InvalidPersistedState);
    }
    Ok(())
}

fn read_header_version(file: &mut File) -> Result<u32, GatewayError> {
    let length = file.metadata().map_err(GatewayError::JournalFile)?.len();
    if length == 0 {
        return Ok(0);
    }
    if length < SQLITE_HEADER_BYTES as u64 {
        return Err(GatewayError::InvalidPersistedState);
    }
    let mut header = [0_u8; SQLITE_HEADER_BYTES];
    file.seek(SeekFrom::Start(0))
        .and_then(|_| file.read_exact(&mut header))
        .map_err(GatewayError::JournalFile)?;
    if &header[..16] != b"SQLite format 3\0" || header[18] != 1 || header[19] != 1 {
        return Err(GatewayError::InvalidPersistedState);
    }
    Ok(u32::from_be_bytes([
        header[SQLITE_USER_VERSION_OFFSET],
        header[SQLITE_USER_VERSION_OFFSET + 1],
        header[SQLITE_USER_VERSION_OFFSET + 2],
        header[SQLITE_USER_VERSION_OFFSET + 3],
    ]))
}

fn recover_private_rollback_journal(
    database_path: &Path,
    database_identity: &fs::Metadata,
) -> Result<(), GatewayError> {
    for suffix in ["-wal", "-shm"] {
        let mut sidecar = database_path.as_os_str().to_os_string();
        sidecar.push(suffix);
        match fs::symlink_metadata(PathBuf::from(sidecar)) {
            Ok(_) => return Err(GatewayError::JournalBackupMismatch),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {},
            Err(error) => return Err(GatewayError::JournalBackup(error)),
        }
    }
    let mut journal_name = database_path.as_os_str().to_os_string();
    journal_name.push("-journal");
    let journal_path = PathBuf::from(journal_name);
    let journal = match open_existing_private_file(&journal_path) {
        Ok(journal) => journal,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(GatewayError::JournalBackup(error)),
    };
    let journal_identity = journal.metadata().map_err(GatewayError::JournalBackup)?;
    if journal_identity.len() > ROLLBACK_JOURNAL_BYTES_MAX {
        return Err(GatewayError::JournalBackupMismatch);
    }
    if database_identity.len() == 0 {
        return Err(GatewayError::InvalidPersistedState);
    }
    if journal_identity.dev() == database_identity.dev()
        && journal_identity.ino() == database_identity.ino()
    {
        return Err(GatewayError::JournalBackupMismatch);
    }
    require_named_identity(&journal_path, &journal_identity)
        .map_err(GatewayError::JournalBackup)?;
    require_named_identity(database_path, database_identity).map_err(GatewayError::JournalFile)?;
    require_private_parent(database_path).map_err(GatewayError::JournalFile)?;
    drop(journal);

    let connection = Connection::open(database_path).map_err(GatewayError::Database)?;
    configure_durable_connection(&connection)?;
    connection
        .query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))
        .map_err(GatewayError::Database)?;
    drop(connection);
    match open_existing_private_file(&journal_path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {},
        Err(error) => return Err(GatewayError::JournalBackup(error)),
        Ok(mut residual) => {
            let residual_identity = residual.metadata().map_err(GatewayError::JournalBackup)?;
            if residual_identity.dev() != journal_identity.dev()
                || residual_identity.ino() != journal_identity.ino()
            {
                return Err(GatewayError::JournalBackupMismatch);
            }
            let mut header = [0_u8; 8];
            residual
                .read_exact(&mut header)
                .map_err(GatewayError::JournalBackup)?;
            if header != [0_u8; 8] {
                return Err(GatewayError::InvalidPersistedState);
            }
            require_named_identity(&journal_path, &residual_identity)
                .map_err(GatewayError::JournalBackup)?;
            fs::remove_file(&journal_path).map_err(GatewayError::JournalBackup)?;
            File::open(database_path.parent().ok_or_else(|| {
                GatewayError::JournalBackup(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "journal path has no parent",
                ))
            })?)
            .and_then(|parent| parent.sync_all())
            .map_err(GatewayError::JournalBackup)?;
        },
    }
    require_named_identity(database_path, database_identity).map_err(GatewayError::JournalFile)
}

fn verify_offline_backup(
    database_path: &Path,
    database_file: &mut File,
    database_identity: &fs::Metadata,
) -> Result<String, GatewayError> {
    for suffix in ["-journal", "-wal", "-shm"] {
        let mut sidecar = database_path.as_os_str().to_os_string();
        sidecar.push(suffix);
        match fs::symlink_metadata(PathBuf::from(sidecar)) {
            Ok(_) => return Err(GatewayError::JournalBackupMismatch),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {},
            Err(error) => return Err(GatewayError::JournalBackup(error)),
        }
    }
    let backup_path = backup_path(database_path);
    let digest_path = backup_digest_path(database_path);
    let mut backup =
        open_existing_private_file(&backup_path).map_err(GatewayError::JournalBackup)?;
    let backup_identity = backup.metadata().map_err(GatewayError::JournalBackup)?;
    if backup_identity.len() > JOURNAL_BYTES_MAX || backup_identity.len() != database_identity.len()
    {
        return Err(GatewayError::JournalBackupMismatch);
    }
    if backup_identity.dev() == database_identity.dev()
        && backup_identity.ino() == database_identity.ino()
    {
        return Err(GatewayError::JournalBackupMismatch);
    }
    let mut digest_file_handle =
        open_existing_private_file(&digest_path).map_err(GatewayError::JournalBackup)?;
    let digest_identity = digest_file_handle
        .metadata()
        .map_err(GatewayError::JournalBackup)?;
    let mut expected = Vec::with_capacity(65);
    digest_file_handle
        .by_ref()
        .take(66)
        .read_to_end(&mut expected)
        .map_err(GatewayError::JournalBackup)?;
    if expected.len() != 65
        || expected[64] != b'\n'
        || !expected[..64]
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(GatewayError::JournalBackupMismatch);
    }
    let expected =
        std::str::from_utf8(&expected[..64]).map_err(|_| GatewayError::JournalBackupMismatch)?;
    let source_digest = digest_file(database_file).map_err(GatewayError::JournalBackup)?;
    let backup_digest = digest_file(&mut backup).map_err(GatewayError::JournalBackup)?;
    if source_digest != expected || backup_digest != expected {
        return Err(GatewayError::JournalBackupMismatch);
    }
    require_named_identity(&backup_path, &backup_identity).map_err(GatewayError::JournalBackup)?;
    require_named_identity(&digest_path, &digest_identity).map_err(GatewayError::JournalBackup)?;
    Ok(source_digest)
}

fn digest_file(file: &mut File) -> io::Result<String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    file.seek(SeekFrom::Start(0))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(digest
        .finalize()
        .iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
            output
        }))
}

fn backup_path(database_path: &Path) -> PathBuf {
    let mut path = database_path.as_os_str().to_os_string();
    path.push(BACKUP_SUFFIX);
    PathBuf::from(path)
}

fn backup_digest_path(database_path: &Path) -> PathBuf {
    let mut path = backup_path(database_path).into_os_string();
    path.push(BACKUP_DIGEST_SUFFIX);
    PathBuf::from(path)
}

fn open_private_file(path: &Path) -> io::Result<File> {
    let file = File::from(open(
        path,
        OFlags::CREATE | OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::RUSR | Mode::WUSR,
    )?);
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.nlink() != 1
        || (metadata.mode() & 0o7777) != 0o600
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "journal file is not owner-private",
        ));
    }
    Ok(file)
}

fn open_existing_private_file(path: &Path) -> io::Result<File> {
    let file = File::from(open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?);
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.nlink() != 1
        || (metadata.mode() & 0o7777) != 0o600
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "upgrade backup is not owner-private",
        ));
    }
    Ok(file)
}

fn require_private_parent(path: &Path) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "journal has no private parent",
        )
    })?;
    let metadata = if is_proc_self_fd_directory(parent) {
        fs::metadata(parent)?
    } else {
        fs::symlink_metadata(parent)?
    };
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || (metadata.mode() & 0o7777) != 0o700
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "journal parent is not owner-private",
        ));
    }
    Ok(())
}

fn is_proc_self_fd_directory(path: &Path) -> bool {
    let mut components = path.components();
    matches!(components.next(), Some(Component::RootDir))
        && matches!(components.next(), Some(Component::Normal(name)) if name == "proc")
        && matches!(components.next(), Some(Component::Normal(name)) if name == "self")
        && matches!(components.next(), Some(Component::Normal(name)) if name == "fd")
        && matches!(
            components.next(),
            Some(Component::Normal(descriptor))
                if descriptor
                    .to_str()
                    .is_some_and(|value| !value.is_empty()
                        && value.bytes().all(|byte| byte.is_ascii_digit()))
        )
        && components.next().is_none()
}

fn require_named_identity(path: &Path, expected: &fs::Metadata) -> io::Result<()> {
    let actual = fs::symlink_metadata(path)?;
    if !actual.is_file()
        || actual.dev() != expected.dev()
        || actual.ino() != expected.ino()
        || actual.uid() != expected.uid()
        || actual.nlink() != 1
        || (actual.mode() & 0o7777) != 0o600
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "journal file identity changed",
        ));
    }
    Ok(())
}

fn worker_lock_path(database_path: &Path) -> PathBuf {
    let mut lock_path = database_path.as_os_str().to_os_string();
    lock_path.push(".kap0038-worker.lock");
    PathBuf::from(lock_path)
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use std::os::fd::AsRawFd;
    use std::{fs, os::unix::fs::PermissionsExt};

    use super::*;
    use crate::gateway::journal::Journal;

    #[test]
    fn named_identity_rejects_a_simple_path_replacement() {
        let directory =
            std::env::temp_dir().join(format!("kapsel-journal-identity-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("journal.sqlite3");
        fs::write(&path, b"original").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let original = open_private_file(&path).unwrap();
        let identity = original.metadata().unwrap();
        let displaced = directory.join("displaced.sqlite3");
        fs::rename(&path, &displaced).unwrap();
        fs::write(&path, b"replacement").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        assert!(require_named_identity(&path, &identity).is_err());
        assert_eq!(fs::read(&displaced).unwrap(), b"original");
        assert_eq!(fs::read(&path).unwrap(), b"replacement");

        drop(original);
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sqlite_fails_closed_after_opened_descriptor_root_is_replaced() {
        let directory =
            std::env::temp_dir().join(format!("kapsel-journal-proc-root-{}", std::process::id()));
        let retained = directory.with_extension("retained");
        let _ = fs::remove_dir_all(&directory);
        let _ = fs::remove_dir_all(&retained);
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let handle = File::open(&directory).unwrap();
        let path = PathBuf::from(format!(
            "/proc/self/fd/{}/journal.sqlite3",
            handle.as_raw_fd()
        ));
        let journal = Journal::open(&path).unwrap();
        fs::rename(&directory, &retained).unwrap();
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();

        let result = journal
            .connection
            .execute_batch("BEGIN EXCLUSIVE; CREATE TABLE descriptor_probe(value INTEGER);");

        assert!(matches!(
            result,
            Err(rusqlite::Error::SqliteFailure(ref error, _))
                if error.code == rusqlite::ErrorCode::ReadOnly && error.extended_code == 1032
        ));
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 0);
        assert!(!retained.join("journal.sqlite3-journal").exists());
        drop(journal);
        drop(handle);
        fs::remove_dir_all(directory).unwrap();
        fs::remove_dir_all(retained).unwrap();
    }

    #[test]
    fn journal_uses_full_synchronous_rollback_durability() {
        let directory =
            std::env::temp_dir().join(format!("kapsel-journal-durability-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("journal.sqlite3");

        let journal = Journal::open(&path).unwrap();
        let journal_mode = journal
            .connection
            .query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
            .unwrap();
        let synchronous = journal
            .connection
            .query_row("PRAGMA synchronous", [], |row| row.get::<_, i64>(0))
            .unwrap();

        assert_eq!(journal_mode, "delete");
        assert_eq!(synchronous, 2);
        drop(journal);
        fs::remove_dir_all(directory).unwrap();
    }
}
