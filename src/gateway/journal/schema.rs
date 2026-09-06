//! Exact SQLite layout recognition and private journal migration.
//!
//! This implementation stays behind the journal interface. Callers cannot select a schema, SQL,
//! marker, migration step, or durable transition.

use rusqlite::{Connection, OptionalExtension, Transaction};

use super::{GatewayError, OPERATION_COUNT_MAX};
use crate::gateway::receipt::RECEIPT_BYTES_MAX;

pub(super) const JOURNAL_FORMAT_VERSION: u32 = 3;

pub(super) const PERSISTED_VALUE_BYTES_MAX: usize = 16 * 1024;
pub(super) const PERSISTED_ROW_BYTES_MAX: i32 = 64 * 1024;

const _: () = assert!(RECEIPT_BYTES_MAX <= PERSISTED_VALUE_BYTES_MAX);
const _: () = assert!(PERSISTED_VALUE_BYTES_MAX < PERSISTED_ROW_BYTES_MAX as usize);

const CURRENT_COLUMNS: &[&str] = &[
    "operation_id",
    "namespace",
    "deployment",
    "container",
    "immutable_image_digest",
    "authorization_id",
    "authorization_signer_key_id",
    "authorization_grant_digest",
    "state",
    "write_strategy",
    "target_rejection",
    "target_read_failures",
    "apply_attempted",
    "target_uid",
    "target_resource_version",
    "apply_accepted",
    "requested_generation",
    "apply_resource_version",
    "receiver_uid",
    "receiver_image",
    "receiver_operation_marker",
    "current_generation",
    "observed_generation",
    "receiver_resource_version",
    "desired_replicas",
    "updated_replicas",
    "available_replicas",
    "unavailable_replicas",
    "available_condition",
    "progress_deadline_exceeded",
    "result",
    "receipt_path",
    "receipt_digest",
    "receipt_bytes",
    "receipt_key_id",
    "rollout_condition_type",
    "rollout_condition_status",
    "rollout_condition_reason",
];

const LEGACY_COLUMNS: &[&str] = &[
    "operation_id",
    "namespace",
    "deployment",
    "container",
    "immutable_image_digest",
    "authorization_id",
    "state",
    "write_strategy",
    "apply_attempted",
    "target_uid",
    "target_resource_version",
    "apply_accepted",
    "requested_generation",
    "apply_resource_version",
    "receiver_uid",
    "receiver_image",
    "receiver_operation_marker",
    "current_generation",
    "observed_generation",
    "receiver_resource_version",
    "desired_replicas",
    "updated_replicas",
    "available_replicas",
    "unavailable_replicas",
    "available_condition",
    "progress_deadline_exceeded",
    "result",
];

const MIGRATED_LEGACY_COLUMNS: &[&str] = &[
    "operation_id",
    "namespace",
    "deployment",
    "container",
    "immutable_image_digest",
    "authorization_id",
    "state",
    "write_strategy",
    "apply_attempted",
    "target_uid",
    "target_resource_version",
    "apply_accepted",
    "requested_generation",
    "apply_resource_version",
    "receiver_uid",
    "receiver_image",
    "receiver_operation_marker",
    "current_generation",
    "observed_generation",
    "receiver_resource_version",
    "desired_replicas",
    "updated_replicas",
    "available_replicas",
    "unavailable_replicas",
    "available_condition",
    "progress_deadline_exceeded",
    "result",
    "authorization_signer_key_id",
    "authorization_grant_digest",
    "target_rejection",
    "target_read_failures",
    "receipt_path",
    "receipt_digest",
    "receipt_bytes",
    "receipt_key_id",
    "rollout_condition_type",
    "rollout_condition_status",
    "rollout_condition_reason",
];

const CREATE_OPERATION_TABLE: &str = "CREATE TABLE kubernetes_image_operations (
    operation_id TEXT PRIMARY KEY NOT NULL,
    namespace TEXT NOT NULL,
    deployment TEXT NOT NULL,
    container TEXT NOT NULL,
    immutable_image_digest TEXT NOT NULL,
    authorization_id TEXT,
    authorization_signer_key_id TEXT,
    authorization_grant_digest TEXT,
    state TEXT NOT NULL,
    write_strategy TEXT,
    target_rejection TEXT,
    target_read_failures INTEGER NOT NULL DEFAULT 0,
    apply_attempted INTEGER NOT NULL DEFAULT 0,
    target_uid TEXT,
    target_resource_version TEXT,
    apply_accepted INTEGER,
    requested_generation INTEGER,
    apply_resource_version TEXT,
    receiver_uid TEXT,
    receiver_image TEXT,
    receiver_operation_marker TEXT,
    current_generation INTEGER,
    observed_generation INTEGER,
    receiver_resource_version TEXT,
    desired_replicas INTEGER,
    updated_replicas INTEGER,
    available_replicas INTEGER,
    unavailable_replicas INTEGER,
    available_condition INTEGER,
    progress_deadline_exceeded INTEGER,
    result TEXT,
    receipt_path TEXT,
    receipt_digest TEXT,
    receipt_bytes BLOB,
    receipt_key_id TEXT,
    rollout_condition_type TEXT,
    rollout_condition_status TEXT,
    rollout_condition_reason TEXT
) STRICT;";

const LEGACY_OPERATION_TABLE: &str = "CREATE TABLE kubernetes_image_operations (
    operation_id TEXT PRIMARY KEY NOT NULL,
    namespace TEXT NOT NULL,
    deployment TEXT NOT NULL,
    container TEXT NOT NULL,
    immutable_image_digest TEXT NOT NULL,
    authorization_id TEXT,
    state TEXT NOT NULL,
    write_strategy TEXT,
    apply_attempted INTEGER NOT NULL DEFAULT 0,
    target_uid TEXT,
    target_resource_version TEXT,
    apply_accepted INTEGER,
    requested_generation INTEGER,
    apply_resource_version TEXT,
    receiver_uid TEXT,
    receiver_image TEXT,
    receiver_operation_marker TEXT,
    current_generation INTEGER,
    observed_generation INTEGER,
    receiver_resource_version TEXT,
    desired_replicas INTEGER,
    updated_replicas INTEGER,
    available_replicas INTEGER,
    unavailable_replicas INTEGER,
    available_condition INTEGER,
    progress_deadline_exceeded INTEGER,
    result TEXT
) STRICT;";

const MIGRATED_LEGACY_OPERATION_TABLE: &str = "CREATE TABLE kubernetes_image_operations (
    operation_id TEXT PRIMARY KEY NOT NULL,
    namespace TEXT NOT NULL,
    deployment TEXT NOT NULL,
    container TEXT NOT NULL,
    immutable_image_digest TEXT NOT NULL,
    authorization_id TEXT,
    state TEXT NOT NULL,
    write_strategy TEXT,
    apply_attempted INTEGER NOT NULL DEFAULT 0,
    target_uid TEXT,
    target_resource_version TEXT,
    apply_accepted INTEGER,
    requested_generation INTEGER,
    apply_resource_version TEXT,
    receiver_uid TEXT,
    receiver_image TEXT,
    receiver_operation_marker TEXT,
    current_generation INTEGER,
    observed_generation INTEGER,
    receiver_resource_version TEXT,
    desired_replicas INTEGER,
    updated_replicas INTEGER,
    available_replicas INTEGER,
    unavailable_replicas INTEGER,
    available_condition INTEGER,
    progress_deadline_exceeded INTEGER,
    result TEXT,
    authorization_signer_key_id TEXT,
    authorization_grant_digest TEXT,
    target_rejection TEXT,
    target_read_failures INTEGER NOT NULL DEFAULT 0,
    receipt_path TEXT,
    receipt_digest TEXT,
    receipt_bytes BLOB,
    receipt_key_id TEXT,
    rollout_condition_type TEXT,
    rollout_condition_status TEXT,
    rollout_condition_reason TEXT
) STRICT;";

pub(super) fn initialize_schema(
    transaction: &Transaction<'_>,
    fresh: bool,
) -> Result<(), GatewayError> {
    if fresh {
        transaction
            .execute_batch(CREATE_OPERATION_TABLE)
            .map_err(GatewayError::Database)?;
    } else if recognized_schema(transaction, CURRENT_COLUMNS, CREATE_OPERATION_TABLE)? {
        // Exact v0.1.1 operation rows need no transformation.
    } else if recognized_schema(transaction, LEGACY_COLUMNS, LEGACY_OPERATION_TABLE)? {
        migrate_receipt_schema(transaction)?;
    } else {
        return Err(GatewayError::InvalidPersistedState);
    }
    add_snapshot_columns(transaction)?;
    require_persisted_bounds(transaction)
}

pub(super) fn require_integrity(transaction: &Transaction<'_>) -> Result<(), GatewayError> {
    let mut statement = transaction
        .prepare("PRAGMA integrity_check")
        .map_err(GatewayError::Database)?;
    let results = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(GatewayError::Database)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(GatewayError::Database)?;
    if results == ["ok"] {
        Ok(())
    } else {
        Err(GatewayError::InvalidPersistedState)
    }
}

const SNAPSHOT_COLUMNS: &[&str] = &[
    "approved_uid",
    "approved_resource_version",
    "preflight_uid",
    "preflight_resource_version",
];

fn add_snapshot_columns(connection: &Connection) -> Result<(), GatewayError> {
    for column in SNAPSHOT_COLUMNS {
        connection
            .execute(
                &format!("ALTER TABLE kubernetes_image_operations ADD COLUMN {column} TEXT"),
                [],
            )
            .map_err(GatewayError::Database)?;
    }
    Ok(())
}

pub(super) fn upgrade_v2(connection: &mut Connection) -> Result<(), GatewayError> {
    let transaction = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Exclusive)
        .map_err(GatewayError::Database)?;
    if !recognized_schema(&transaction, CURRENT_COLUMNS, CREATE_OPERATION_TABLE)?
        && !recognized_schema(
            &transaction,
            MIGRATED_LEGACY_COLUMNS,
            MIGRATED_LEGACY_OPERATION_TABLE,
        )?
    {
        return Err(GatewayError::InvalidPersistedState);
    }
    require_integrity(&transaction)?;
    add_snapshot_columns(&transaction)?;
    require_persisted_bounds(&transaction)?;
    transaction
        .pragma_update(None, "user_version", JOURNAL_FORMAT_VERSION)
        .map_err(GatewayError::Database)?;
    transaction.commit().map_err(GatewayError::Database)
}

pub(super) fn recognized_supported_schema(connection: &Connection) -> Result<bool, GatewayError> {
    for (columns, sql) in [
        (CURRENT_COLUMNS, CREATE_OPERATION_TABLE),
        (MIGRATED_LEGACY_COLUMNS, MIGRATED_LEGACY_OPERATION_TABLE),
    ] {
        let columns = [columns, SNAPSHOT_COLUMNS].concat();
        let additions = format!(", {} TEXT", SNAPSHOT_COLUMNS.join(" TEXT, "));
        let sql = sql.replace("\n) STRICT;", &format!("{additions}\n) STRICT;"));
        if recognized_schema(connection, &columns, &sql)? {
            require_persisted_bounds(connection)?;
            return Ok(true);
        }
    }
    Ok(false)
}

fn require_persisted_bounds(connection: &Connection) -> Result<(), GatewayError> {
    let value_predicates = CURRENT_COLUMNS
        .iter()
        .chain(SNAPSHOT_COLUMNS.iter())
        .filter(|name| expected_column_type(name) != "INTEGER")
        .map(|name| format!("COALESCE(length(CAST({name} AS BLOB)), 0) > ?2"))
        .collect::<Vec<_>>()
        .join(" OR ");
    let query = format!(
        "SELECT
            (SELECT COUNT(*) FROM kubernetes_image_operations) <= ?1
            AND NOT EXISTS (
                SELECT 1 FROM kubernetes_image_operations
                WHERE {value_predicates}
                LIMIT 1
            )"
    );
    let value_max = i64::try_from(PERSISTED_VALUE_BYTES_MAX)
        .map_err(|_| GatewayError::InvalidPersistedState)?;
    let within_bounds = connection
        .query_row(&query, [OPERATION_COUNT_MAX, value_max], |row| {
            row.get::<_, bool>(0)
        })
        .map_err(GatewayError::Database)?;
    if within_bounds {
        Ok(())
    } else {
        Err(GatewayError::InvalidPersistedState)
    }
}

type SchemaEntry = (String, String, String, Option<String>);
type ColumnFact = (i64, String, String, i64, Option<String>, i64, i64);
type IndexFact = (i64, String, i64, String, i64);
type IndexColumnFact = (i64, i64, Option<String>, i64, String, i64);

fn schema_entries(connection: &Connection) -> Result<Vec<SchemaEntry>, GatewayError> {
    let mut statement = connection
        .prepare(
            "SELECT type, name, tbl_name, sql
             FROM sqlite_schema
             ORDER BY type, name",
        )
        .map_err(GatewayError::Database)?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .map_err(GatewayError::Database)?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(GatewayError::Database)
}

fn table_columns(connection: &Connection) -> Result<Vec<ColumnFact>, GatewayError> {
    let mut statement = connection
        .prepare("PRAGMA table_xinfo(kubernetes_image_operations)")
        .map_err(GatewayError::Database)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
            ))
        })
        .map_err(GatewayError::Database)?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(GatewayError::Database)
}

fn table_indexes(connection: &Connection) -> Result<Vec<IndexFact>, GatewayError> {
    let mut statement = connection
        .prepare("PRAGMA index_list(kubernetes_image_operations)")
        .map_err(GatewayError::Database)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })
        .map_err(GatewayError::Database)?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(GatewayError::Database)
}

fn primary_index_columns(connection: &Connection) -> Result<Vec<IndexColumnFact>, GatewayError> {
    let mut statement = connection
        .prepare("PRAGMA index_xinfo(sqlite_autoindex_kubernetes_image_operations_1)")
        .map_err(GatewayError::Database)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        })
        .map_err(GatewayError::Database)?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(GatewayError::Database)
}

fn recognized_schema(
    connection: &Connection,
    expected_columns: &[&str],
    expected_create_sql: &str,
) -> Result<bool, GatewayError> {
    let schema = schema_entries(connection)?;
    let expected_index = "sqlite_autoindex_kubernetes_image_operations_1";
    let expected_sql = normalize_schema_sql(expected_create_sql);
    if schema.len() != 2
        || schema[0]
            != (
                "index".into(),
                expected_index.into(),
                "kubernetes_image_operations".into(),
                None,
            )
        || schema[1].0 != "table"
        || schema[1].1 != "kubernetes_image_operations"
        || schema[1].2 != "kubernetes_image_operations"
        || schema[1].3.as_deref().map(normalize_schema_sql).as_deref()
            != Some(expected_sql.as_str())
    {
        return Ok(false);
    }
    let strict = connection
        .query_row(
            "SELECT strict FROM pragma_table_list WHERE name = 'kubernetes_image_operations'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(GatewayError::Database)?;
    if strict != Some(1) {
        return Ok(false);
    }
    let columns = table_columns(connection)?;
    if columns.len() != expected_columns.len()
        || !columns.iter().zip(expected_columns).enumerate().all(
            |(
                index,
                (
                    (column_id, name, declared_type, not_null, default_value, primary_key, hidden),
                    expected_name,
                ),
            )| {
                i64::try_from(index).is_ok_and(|expected_id| *column_id == expected_id)
                    && name == expected_name
                    && declared_type == expected_column_type(expected_name)
                    && *not_null == i64::from(expected_column_not_null(expected_name))
                    && default_value.as_deref() == expected_column_default(expected_name)
                    && *primary_key == i64::from(*expected_name == "operation_id")
                    && *hidden == 0
            },
        )
    {
        return Ok(false);
    }
    let indexes = table_indexes(connection)?;
    if indexes != [(0, expected_index.into(), 1, "pk".into(), 0)] {
        return Ok(false);
    }
    let index_columns = primary_index_columns(connection)?;
    Ok(index_columns
        == [
            (0, 0, Some("operation_id".into()), 0, "BINARY".into(), 1),
            (1, -1, None, 0, "BINARY".into(), 0),
        ])
}

fn normalize_schema_sql(sql: &str) -> String {
    sql.chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect::<String>()
        .trim_end_matches(';')
        .to_owned()
}

fn expected_column_type(name: &str) -> &'static str {
    match name {
        "receipt_bytes" => "BLOB",
        "target_read_failures"
        | "apply_attempted"
        | "apply_accepted"
        | "requested_generation"
        | "current_generation"
        | "observed_generation"
        | "desired_replicas"
        | "updated_replicas"
        | "available_replicas"
        | "unavailable_replicas"
        | "available_condition"
        | "progress_deadline_exceeded" => "INTEGER",
        _ => "TEXT",
    }
}

fn expected_column_not_null(name: &str) -> bool {
    matches!(
        name,
        "operation_id"
            | "namespace"
            | "deployment"
            | "container"
            | "immutable_image_digest"
            | "state"
            | "target_read_failures"
            | "apply_attempted"
    )
}

fn expected_column_default(name: &str) -> Option<&'static str> {
    matches!(name, "target_read_failures" | "apply_attempted").then_some("0")
}

fn migrate_receipt_schema(transaction: &Transaction<'_>) -> Result<(), GatewayError> {
    let columns = {
        let mut statement = transaction
            .prepare("PRAGMA table_info(kubernetes_image_operations)")
            .map_err(GatewayError::Database)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(GatewayError::Database)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(GatewayError::Database)?
    };
    for (name, declaration) in [
        (
            "authorization_signer_key_id",
            "authorization_signer_key_id TEXT",
        ),
        (
            "authorization_grant_digest",
            "authorization_grant_digest TEXT",
        ),
        ("target_rejection", "target_rejection TEXT"),
        (
            "target_read_failures",
            "target_read_failures INTEGER NOT NULL DEFAULT 0",
        ),
        ("receipt_path", "receipt_path TEXT"),
        ("receipt_digest", "receipt_digest TEXT"),
        ("receipt_bytes", "receipt_bytes BLOB"),
        ("receipt_key_id", "receipt_key_id TEXT"),
        ("rollout_condition_type", "rollout_condition_type TEXT"),
        ("rollout_condition_status", "rollout_condition_status TEXT"),
        ("rollout_condition_reason", "rollout_condition_reason TEXT"),
    ] {
        if !columns.iter().any(|column| column == name) {
            transaction
                .execute(
                    &format!("ALTER TABLE kubernetes_image_operations ADD COLUMN {declaration}"),
                    [],
                )
                .map_err(GatewayError::Database)?;
        }
    }
    transaction
        .execute(
            "UPDATE kubernetes_image_operations
             SET requested_generation = current_generation
             WHERE requested_generation IS NULL
                   AND result IN ('SUCCEEDED', 'FAILED')
                   AND target_uid IS NOT NULL
                   AND receiver_uid = target_uid
                   AND receiver_image = immutable_image_digest
                   AND receiver_operation_marker = operation_id
                   AND current_generation IS NOT NULL
                   AND observed_generation >= current_generation",
            [],
        )
        .map_err(GatewayError::Database)?;
    transaction
        .execute(
            "UPDATE kubernetes_image_operations
             SET rollout_condition_type = CASE
                    WHEN progress_deadline_exceeded = 1 THEN 'Progressing'
                    WHEN available_condition = 1 THEN 'Available'
                    ELSE NULL
                 END,
                 rollout_condition_status = CASE
                    WHEN progress_deadline_exceeded = 1 THEN 'False'
                    WHEN available_condition = 1 THEN 'True'
                    ELSE NULL
                 END,
                 rollout_condition_reason = CASE
                    WHEN progress_deadline_exceeded = 1 THEN 'ProgressDeadlineExceeded'
                    ELSE NULL
                 END
             WHERE rollout_condition_type IS NULL
                   AND (progress_deadline_exceeded = 1 OR available_condition = 1)",
            [],
        )
        .map_err(GatewayError::Database)?;
    Ok(())
}
