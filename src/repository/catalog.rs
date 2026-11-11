//! SQLite storage for occurrence metadata and repository relationships.
//!
//! Object bytes live in the filesystem. The catalog stores their identities,
//! occurrence records, indexed selection fields, ancestry, retained views, and
//! operation history. A repository mutation normally goes through
//! [`Repository::with_catalog`](super::storage::Repository::with_catalog) so it
//! shares the repository lock and serialized writer connection.
use super::{metadata::Occurrence, security, storage::valid_hash};
use crate::{
    app::config::SecurityMode, ingest::discovery::check_path, organization::rules::Planned,
    selection::Filters,
};
use anyhow::{Result, ensure};
use rusqlite::{Connection, OpenFlags, params, types::Value};
use std::{collections::BTreeSet, fs, path::Path};
pub const FILE_NAME: &str = "metadata.sqlite3";
const APPLICATION_ID: i64 = 0x42465331;
const VERSION: i64 = 3;
pub struct Catalog {
    connection: Connection,
}
#[derive(Debug, serde::Serialize)]
pub struct Counts {
    pub occurrences: u64,
    pub unique_objects: u64,
}
fn guard(root: &Path) -> Result<()> {
    check_path(root)?;
    let directory = fs::symlink_metadata(root)?;
    ensure!(directory.is_dir(), "catalog root is not a directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            directory.permissions().mode() & 0o777 == 0o700,
            "catalog root must be private (0700)"
        );
    }
    guard_files(&root.join(FILE_NAME))?;
    Ok(())
}
fn guard_files(database: &Path) -> Result<()> {
    for suffix in ["", "-journal", "-wal", "-shm"] {
        let mut path = database.as_os_str().to_owned();
        path.push(suffix);
        let path = Path::new(&path);
        check_path(path)?;
        if path.try_exists()? {
            security::validate_file(path, SecurityMode::Standard)?;
        }
    }
    Ok(())
}
pub fn exists(root: &Path) -> Result<bool> {
    guard(root)?;
    Ok(root.join(FILE_NAME).try_exists()?)
}
fn configure(connection: &Connection, write: bool) -> Result<()> {
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    connection.pragma_update(None, "trusted_schema", false)?;
    connection.pragma_update(None, "foreign_keys", true)?;
    if write {
        connection.pragma_update(None, "synchronous", "FULL")?;
        let mode: String = connection.query_row("PRAGMA journal_mode=DELETE", [], |r| r.get(0))?;
        ensure!(
            mode == "delete" || mode == "memory",
            "unsupported catalog journal mode"
        );
    }
    Ok(())
}
fn validate(connection: &Connection) -> Result<()> {
    let version: i64 = connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
    let app: i64 = connection.pragma_query_value(None, "application_id", |r| r.get(0))?;
    ensure!(
        version == VERSION && app == APPLICATION_ID,
        "unsupported SQLite catalog schema or application identity; re-ingest the original inputs into a fresh directory"
    );
    Ok(())
}
fn schema(connection: &Connection) -> Result<()> {
    connection.execute_batch("BEGIN;
CREATE TABLE objects(hash TEXT PRIMARY KEY,size INTEGER NOT NULL CHECK(size>=0));
CREATE TABLE occurrences(
    id TEXT PRIMARY KEY NOT NULL,
    hash TEXT NOT NULL REFERENCES objects(hash),
    structural INTEGER NOT NULL CHECK(structural IN (0,1)),
    input_mode TEXT NOT NULL,
    file_type TEXT NOT NULL,
    original_name TEXT NOT NULL,
    original_entry_name TEXT NOT NULL,
    original_stem TEXT NOT NULL,
    original_extension TEXT NOT NULL,
    normalized_extension TEXT GENERATED ALWAYS AS (lower(ltrim(original_extension,'.'))) VIRTUAL,
    source_archive TEXT NOT NULL,
    source_path TEXT NOT NULL,
    entry_index INTEGER NOT NULL CHECK(entry_index>=0),
    encrypted INTEGER NOT NULL CHECK(encrypted IN (0,1)),
    ingest_date TEXT NOT NULL,
    run_id TEXT NOT NULL,
    detected_format TEXT NOT NULL,
    detected_family TEXT NOT NULL,
    mime_type TEXT,
    confidence TEXT NOT NULL,
    detector_version TEXT NOT NULL CHECK(detector_version<>'bfs-2'),
    mismatch TEXT NOT NULL,
    mismatch_reason TEXT NOT NULL,
    evidence TEXT NOT NULL,
    alternatives TEXT NOT NULL,
    source_id TEXT,
    source_url TEXT,
    source_name TEXT,
    CHECK ((source_id IS NULL) = (source_url IS NULL) AND (source_id IS NULL) = (source_name IS NULL))
);
CREATE TABLE ancestry(
    occurrence_id TEXT PRIMARY KEY NOT NULL REFERENCES occurrences(id) DEFERRABLE INITIALLY DEFERRED,
    parent_id TEXT REFERENCES occurrences(id) DEFERRABLE INITIALLY DEFERRED,
    parent_hash TEXT NOT NULL,
    nested_version INTEGER NOT NULL CHECK(nested_version=1),
    root_source TEXT NOT NULL,
    root_input_hash TEXT NOT NULL,
    archive_depth INTEGER NOT NULL CHECK(archive_depth>=0),
    entry_chain TEXT NOT NULL
);
CREATE TABLE tombstones(id TEXT PRIMARY KEY);
CREATE TABLE view_entries(generation TEXT NOT NULL,path TEXT NOT NULL,occurrence_id TEXT NOT NULL REFERENCES occurrences(id),hash TEXT NOT NULL REFERENCES objects(hash),PRIMARY KEY(generation,path));
CREATE TABLE operations(id TEXT PRIMARY KEY,record TEXT NOT NULL);
CREATE TABLE operation_inputs(operation_id TEXT NOT NULL REFERENCES operations(id),source_path TEXT NOT NULL,state TEXT NOT NULL,error TEXT,PRIMARY KEY(operation_id,source_path));
CREATE INDEX occurrences_hash ON occurrences(hash);
CREATE INDEX occurrences_selection ON occurrences(normalized_extension,detected_format,mismatch);
CREATE INDEX occurrences_order ON occurrences(source_path,entry_index,id);
CREATE INDEX occurrences_format ON occurrences(detected_format);
CREATE INDEX occurrences_mismatch ON occurrences(mismatch);
CREATE INDEX objects_size ON objects(size);
PRAGMA application_id=1111905073;PRAGMA user_version=3;COMMIT;")?;
    Ok(())
}
/// Open an existing SQLite catalog read-only.
pub fn read(root: &Path) -> Result<Catalog> {
    require(root)?;
    open_read_only(&root.join(FILE_NAME))
}

pub(super) fn require(root: &Path) -> Result<()> {
    ensure!(
        exists(root)?,
        "metadata.sqlite3 is missing; restore the catalog or re-ingest the original inputs into a fresh directory"
    );
    Ok(())
}

fn open_read_only(path: &Path) -> Result<Catalog> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    configure(&connection, false)?;
    validate(&connection)?;
    Ok(Catalog { connection })
}

pub(super) fn import_rows(path: &Path) -> Result<Vec<Occurrence>> {
    guard_files(path)?;
    let catalog = open_read_only(path)?;
    let transaction = catalog.connection.unchecked_transaction()?;
    let (mut rows, removed) = catalog.integrity_records()?;
    rows.retain(|row| !removed.contains(&row.occurrence_id));
    transaction.commit()?;
    Ok(rows)
}

/// Initialize the catalog before publishing the security marker for a new repository.
pub(super) fn create(root: &Path) -> Result<()> {
    if exists(root)? {
        // Creation can be interrupted after the empty catalog is published.
        let catalog = read(root)?;
        catalog.integrity()?;
        let empty: bool = catalog.connection.query_row(
            "SELECT NOT EXISTS(SELECT 1 FROM objects) AND NOT EXISTS(SELECT 1 FROM operations) AND NOT EXISTS(SELECT 1 FROM tombstones)",
            [],
            |row| row.get(0),
        )?;
        ensure!(
            empty,
            "nonempty catalog is missing its repository security metadata"
        );
        return Ok(());
    }
    let temporary = tempfile::NamedTempFile::new_in(root)?;
    let connection = Connection::open(temporary.path())?;
    configure(&connection, true)?;
    schema(&connection)?;
    drop(connection);
    temporary.as_file().sync_all()?;
    temporary.persist_noclobber(root.join(FILE_NAME))?;
    fs::File::open(root)?.sync_all()?;
    Ok(())
}

/// Open the writable catalog.
///
/// The caller must hold the repository lock while writing.
pub fn write(root: &Path) -> Result<Catalog> {
    require(root)?;
    let connection = Connection::open_with_flags(
        root.join(FILE_NAME),
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    validate(&connection)?;
    configure(&connection, true)?;
    validate_relationships(&connection)?;
    Ok(Catalog { connection })
}
fn enum_text(value: &impl serde::Serialize) -> Result<String> {
    Ok(serde_json::to_value(value)?
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("invalid enum value"))?
        .to_owned())
}
const OCCURRENCES: &str = "SELECT o.id,o.hash,b.size,o.structural,o.input_mode,o.file_type,
    o.original_name,o.original_entry_name,o.original_stem,o.original_extension,
    o.source_archive,o.source_path,o.entry_index,o.encrypted,o.ingest_date,o.run_id,
    o.detected_format,o.detected_family,o.mime_type,o.confidence,o.detector_version,
    o.mismatch,o.mismatch_reason,o.evidence,o.alternatives,o.source_id,o.source_url,o.source_name,
    a.occurrence_id AS ancestor_id,a.parent_id,a.parent_hash,a.nested_version,a.root_source,
    a.root_input_hash,a.archive_depth,a.entry_chain
    FROM occurrences o JOIN objects b ON o.hash=b.hash
    LEFT JOIN ancestry a ON a.occurrence_id=o.id";

fn validate_occurrence(row: &Occurrence) -> Result<()> {
    row.validate()?;
    ensure!(
        row.detection.detector_version != "bfs-2",
        "obsolete bfs-2 detection; re-ingest the original inputs into a fresh directory"
    );
    Ok(())
}

fn decode_occurrence(row: &rusqlite::Row<'_>) -> Result<Occurrence> {
    use super::metadata::NestedProvenance;
    use crate::{
        collection::acquisition::Candidate,
        detection::{classifier::Detection, mismatch::Evaluation},
    };

    // Bound persisted metadata before allocating strings or parsing arrays.
    let mut bytes = 0;
    for index in 0..row.as_ref().column_count() {
        if let rusqlite::types::ValueRef::Text(text) = row.get_ref(index)? {
            bytes += text.len();
            ensure!(bytes <= 1024 * 1024, "oversized occurrence record");
        }
    }

    fn read_enum<T: serde::de::DeserializeOwned>(
        row: &rusqlite::Row<'_>,
        column: &str,
    ) -> Result<T> {
        Ok(serde_json::from_value(serde_json::Value::String(
            row.get(column)?,
        ))?)
    }

    let nested = if row.get::<_, Option<String>>("ancestor_id")?.is_some() {
        Some(NestedProvenance {
            schema_version: row.get("nested_version")?,
            parent_occurrence_id: row.get("parent_id")?,
            parent_sha256: row.get("parent_hash")?,
            root_source: row.get("root_source")?,
            root_input_hash: row.get("root_input_hash")?,
            archive_depth: usize::try_from(row.get::<_, i64>("archive_depth")?)?,
            entry_chain: serde_json::from_str(row.get_ref("entry_chain")?.as_str()?)?,
        })
    } else {
        None
    };
    let provenance = match (
        row.get("source_id")?,
        row.get("source_url")?,
        row.get("source_name")?,
    ) {
        (Some(source_id), Some(url), Some(name)) => Some(Candidate {
            source_id,
            url,
            name,
        }),
        (None, None, None) => None,
        _ => anyhow::bail!("incomplete remote provenance"),
    };
    let record = Occurrence {
        nested,
        provenance,
        structural: row.get("structural")?,
        detection: Detection {
            detected_format: read_enum(row, "detected_format")?,
            detected_family: read_enum(row, "detected_family")?,
            mime_type: row.get("mime_type")?,
            confidence: read_enum(row, "confidence")?,
            detector_version: row.get("detector_version")?,
            evidence: serde_json::from_str(row.get_ref("evidence")?.as_str()?)?,
            alternatives: serde_json::from_str(row.get_ref("alternatives")?.as_str()?)?,
        },
        mismatch: Evaluation {
            status: read_enum(row, "mismatch")?,
            reason: row.get("mismatch_reason")?,
        },
        input_mode: read_enum(row, "input_mode")?,
        occurrence_id: row.get("id")?,
        sha256: row.get("hash")?,
        size: u64::try_from(row.get::<_, i64>("size")?)?,
        file_type: row.get("file_type")?,
        original_name: row.get("original_name")?,
        original_entry_name: row.get("original_entry_name")?,
        original_stem: row.get("original_stem")?,
        original_extension: row.get("original_extension")?,
        source_archive: row.get("source_archive")?,
        source_path: row.get("source_path")?,
        entry_index: usize::try_from(row.get::<_, i64>("entry_index")?)?,
        encrypted: row.get("encrypted")?,
        ingest_date: row.get("ingest_date")?,
        run_id: row.get("run_id")?,
    };
    validate_occurrence(&record)?;
    Ok(record)
}

fn occurrence(connection: &Connection, id: &str) -> Result<Option<Occurrence>> {
    let mut statement = connection.prepare_cached(&format!("{OCCURRENCES} WHERE o.id=?1"))?;
    let mut rows = statement.query([id])?;
    rows.next()?.map(decode_occurrence).transpose()
}

fn insert(connection: &Connection, row: &Occurrence) -> Result<()> {
    validate_occurrence(row)?;
    ensure!(
        serde_json::to_vec(row)?.len() <= 1024 * 1024,
        "oversized occurrence record"
    );
    let size = i64::try_from(row.size)?;
    connection.execute(
        "INSERT INTO objects(hash,size) VALUES(?1,?2) ON CONFLICT(hash) DO NOTHING",
        params![row.sha256, size],
    )?;
    let stored: i64 = connection.query_row(
        "SELECT size FROM objects WHERE hash=?1",
        [&row.sha256],
        |r| r.get(0),
    )?;
    ensure!(stored == size, "conflicting object size");
    if let Some(previous) = occurrence(connection, &row.occurrence_id)? {
        ensure!(
            previous.sha256 == row.sha256,
            "conflicting occurrence metadata"
        );
        if previous.structural && !row.structural {
            connection.execute(
                "UPDATE occurrences SET structural=0 WHERE id=?1",
                [&row.occurrence_id],
            )?;
        }
        return Ok(());
    }
    let remote = row.provenance.as_ref();
    let d = &row.detection;
    connection.execute(
        "INSERT INTO occurrences(id,hash,structural,input_mode,file_type,original_name,
            original_entry_name,original_stem,original_extension,source_archive,source_path,
            entry_index,encrypted,ingest_date,run_id,detected_format,detected_family,mime_type,
            confidence,detector_version,mismatch,mismatch_reason,evidence,alternatives,source_id,
            source_url,source_name)
         VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        params![
            row.occurrence_id,
            row.sha256,
            row.structural,
            enum_text(&row.input_mode)?,
            row.file_type,
            row.original_name,
            row.original_entry_name,
            row.original_stem,
            row.original_extension,
            row.source_archive,
            row.source_path,
            i64::try_from(row.entry_index)?,
            row.encrypted,
            row.ingest_date,
            row.run_id,
            d.detected_format.as_str(),
            d.detected_family.as_str(),
            d.mime_type,
            d.confidence.as_str(),
            d.detector_version,
            row.mismatch.status.as_str(),
            row.mismatch.reason,
            serde_json::to_string(&d.evidence)?,
            serde_json::to_string(&d.alternatives)?,
            remote.map(|r| &r.source_id),
            remote.map(|r| &r.url),
            remote.map(|r| &r.name)
        ],
    )?;
    if let Some(n) = &row.nested {
        connection.execute(
            "INSERT INTO ancestry(occurrence_id,parent_id,parent_hash,nested_version,root_source,
                root_input_hash,archive_depth,entry_chain) VALUES(?,?,?,?,?,?,?,?)",
            params![
                row.occurrence_id,
                n.parent_occurrence_id,
                n.parent_sha256,
                n.schema_version,
                n.root_source,
                n.root_input_hash,
                i64::try_from(n.archive_depth)?,
                serde_json::to_string(&n.entry_chain)?
            ],
        )?;
    }
    Ok(())
}
fn predicate(filters: &Filters, include_removed: bool) -> Result<(String, Vec<Value>)> {
    filters.validate()?;
    let mut clauses = Vec::new();
    let mut values = Vec::new();
    if !include_removed {
        clauses.push("o.structural=0".into());
        clauses.push("NOT EXISTS(SELECT 1 FROM tombstones t WHERE t.id=o.id)".to_owned());
    }
    for (column, list, exclude) in [
        (
            "normalized_extension",
            filters
                .include_extensions
                .iter()
                .map(|s| crate::detection::mismatch::normalize_extension(s))
                .collect::<Vec<_>>(),
            false,
        ),
        (
            "normalized_extension",
            filters
                .exclude_extensions
                .iter()
                .map(|s| crate::detection::mismatch::normalize_extension(s))
                .collect(),
            true,
        ),
        (
            "detected_format",
            filters
                .include_formats
                .iter()
                .map(enum_text)
                .collect::<Result<Vec<_>>>()?,
            false,
        ),
        (
            "detected_format",
            filters
                .exclude_formats
                .iter()
                .map(enum_text)
                .collect::<Result<Vec<_>>>()?,
            true,
        ),
    ] {
        if list.is_empty() {
            continue;
        }
        let placeholders = vec!["?"; list.len()].join(",");
        clauses.push(format!(
            "o.{column} {}IN ({placeholders})",
            if exclude { "NOT " } else { "" }
        ));
        values.extend(list.into_iter().map(Value::Text));
    }
    if let Some(hash) = &filters.sha256 {
        clauses.push("o.hash=?".into());
        values.push(Value::Text(hash.clone()));
    }
    if let Some(status) = filters.mismatch {
        clauses.push("o.mismatch=?".into());
        values.push(Value::Text(status.as_str().into()));
    }
    if let Some(min) = filters.min_size {
        if let Ok(min) = i64::try_from(min) {
            clauses.push("b.size>=?".into());
            values.push(Value::Integer(min));
        } else {
            clauses.push("0".into());
        }
    }
    if let Some(max) = filters.max_size
        && let Ok(max) = i64::try_from(max)
    {
        clauses.push("b.size<=?".into());
        values.push(Value::Integer(max));
    }
    Ok((
        if clauses.is_empty() {
            "1".into()
        } else {
            clauses.join(" AND ")
        },
        values,
    ))
}
impl Catalog {
    pub fn insert(&mut self, row: &Occurrence) -> Result<()> {
        self.insert_many(std::slice::from_ref(row))
    }
    /// Insert a batch in a single transaction, including its ancestry links.
    ///
    /// Callers must publish and synchronize the referenced object files first.
    /// Existing identities retain their provenance. Re-inserting a structural
    /// record as visible promotes it into ordinary selections.
    pub fn insert_many(&mut self, rows: &[Occurrence]) -> Result<()> {
        let transaction = self.connection.transaction()?;
        for row in rows {
            insert(&transaction, row)?;
        }
        // Existing relationships were checked when opening the writer; only these identities changed.
        let mut check = transaction.prepare_cached("SELECT EXISTS(SELECT 1 FROM ancestry a JOIN occurrences p ON p.id=a.parent_id WHERE a.occurrence_id=?1 AND p.hash<>a.parent_hash) OR EXISTS(SELECT 1 FROM ancestry a JOIN tombstones parent ON parent.id=a.parent_id WHERE a.occurrence_id=?1 AND NOT EXISTS(SELECT 1 FROM tombstones child WHERE child.id=a.occurrence_id))")?;
        for row in rows {
            let invalid: bool = check.query_row([&row.occurrence_id], |r| r.get(0))?;
            ensure!(!invalid, "catalog reference identity mismatch");
        }
        drop(check);
        transaction.commit()?;
        Ok(())
    }
    pub fn update_classifications(&mut self, rows: &[Occurrence]) -> Result<()> {
        let transaction = self.connection.transaction()?;
        for row in rows {
            validate_occurrence(row)?;
            let mut original = occurrence(&transaction, &row.occurrence_id)?
                .ok_or(rusqlite::Error::QueryReturnedNoRows)?;
            ensure!(
                original.sha256 == row.sha256 && original.size == row.size,
                "classification identity mismatch"
            );
            original.detection.clone_from(&row.detection);
            original.mismatch.clone_from(&row.mismatch);
            validate_occurrence(&original)?;
            ensure!(
                serde_json::to_vec(&original)?.len() <= 1024 * 1024,
                "oversized occurrence record"
            );
            let d = &original.detection;
            transaction.execute(
                "UPDATE occurrences SET detected_format=?,detected_family=?,mime_type=?,confidence=?,
                    detector_version=?,mismatch=?,mismatch_reason=?,evidence=?,alternatives=? WHERE id=?",
                params![d.detected_format.as_str(), d.detected_family.as_str(), d.mime_type,
                    d.confidence.as_str(), d.detector_version, original.mismatch.status.as_str(),
                    original.mismatch.reason, serde_json::to_string(&d.evidence)?,
                    serde_json::to_string(&d.alternatives)?, original.occurrence_id],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }
    /// Decode and validate matching records in source path and entry order.
    ///
    /// Set `include_removed` to include both tombstoned and structural records.
    /// Ordinary queries keep it false to return visible, active occurrences.
    pub fn select(&self, filters: &Filters, include_removed: bool) -> Result<Vec<Occurrence>> {
        let (predicate, values) = predicate(filters, include_removed)?;
        let mut statement = self.connection.prepare(&format!(
            "{OCCURRENCES} WHERE {predicate} ORDER BY o.source_path,o.entry_index,o.id"
        ))?;
        let mut query = statement.query(rusqlite::params_from_iter(values))?;
        let mut result = Vec::new();
        while let Some(row) = query.next()? {
            result.push(decode_occurrence(row)?);
        }
        Ok(result)
    }
    /// Count visible occurrences and distinct object hashes directly in SQL.
    pub fn counts(&self, filters: &Filters) -> Result<Counts> {
        let (predicate, values) = predicate(filters, false)?;
        let (occurrences,unique_objects):(i64,i64)=self.connection.query_row(&format!("SELECT count(*),count(DISTINCT o.hash) FROM occurrences o JOIN objects b ON o.hash=b.hash WHERE {predicate}"),rusqlite::params_from_iter(values),|r|Ok((r.get(0)?,r.get(1)?)))?;
        Ok(Counts {
            occurrences: u64::try_from(occurrences)?,
            unique_objects: u64::try_from(unique_objects)?,
        })
    }
    pub fn removed(&self) -> Result<BTreeSet<String>> {
        let mut statement = self
            .connection
            .prepare("SELECT id FROM tombstones ORDER BY id")?;
        let rows = statement.query_map([], |r| r.get::<_, String>(0))?;
        let mut ids = BTreeSet::new();
        for id in rows {
            let id = id?;
            ensure!(valid_hash(&id), "invalid tombstone identity");
            ids.insert(id);
        }
        Ok(ids)
    }
    pub fn remove(&mut self, ids: &BTreeSet<String>) -> Result<()> {
        let transaction = self.connection.transaction()?;
        for id in ids {
            ensure!(valid_hash(id), "invalid removal identity");
            transaction.execute("INSERT OR IGNORE INTO tombstones(id) VALUES(?1)", [id])?;
        }
        let dangling:bool=transaction.query_row("SELECT EXISTS(SELECT 1 FROM ancestry a JOIN tombstones parent ON parent.id=a.parent_id WHERE NOT EXISTS(SELECT 1 FROM tombstones child WHERE child.id=a.occurrence_id))",[],|r|r.get(0))?;
        ensure!(
            !dangling,
            "removal would leave retained nested ancestry dangling"
        );
        transaction.commit()?;
        Ok(())
    }
    pub fn record_view(&mut self, generation: &str, plan: &[Planned]) -> Result<()> {
        let transaction = self.connection.transaction()?;
        for row in plan {
            view(
                &transaction,
                generation,
                &row.path,
                &row.occurrence_id,
                &row.sha256,
            )?;
        }
        transaction.commit()?;
        Ok(())
    }
    pub fn views(&self) -> Result<Vec<String>> {
        let mut statement = self
            .connection
            .prepare("SELECT DISTINCT generation FROM view_entries ORDER BY generation")?;
        Ok(statement
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?)
    }
    pub fn view_plan(&self, generation: &str) -> Result<Vec<Planned>> {
        let mut statement = self.connection.prepare(
            "SELECT path,hash,occurrence_id FROM view_entries WHERE generation=?1 ORDER BY path",
        )?;
        Ok(statement
            .query_map([generation], |r| {
                Ok(Planned {
                    path: r.get(0)?,
                    sha256: r.get(1)?,
                    occurrence_id: r.get(2)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?)
    }
    pub fn record_input(
        &mut self,
        operation_id: &str,
        input: &crate::operations::InputOutcome,
    ) -> Result<()> {
        self.record_inputs(operation_id, std::slice::from_ref(input))
    }
    pub fn record_inputs(
        &mut self,
        operation_id: &str,
        inputs: &[crate::operations::InputOutcome],
    ) -> Result<()> {
        let transaction = self.connection.transaction()?;
        for input in inputs {
            ensure!(
                !input.source_path.is_empty()
                    && input.source_path.len() <= 16384
                    && matches!(
                        input.state.as_str(),
                        "pending" | "completed" | "failed" | "interrupted"
                    ),
                "invalid input outcome"
            );
            transaction.execute("INSERT INTO operation_inputs(operation_id,source_path,state,error) VALUES(?1,?2,?3,?4) ON CONFLICT(operation_id,source_path) DO UPDATE SET state=excluded.state,error=excluded.error",params![operation_id,input.source_path,input.state,input.error])?;
        }
        transaction.commit()?;
        Ok(())
    }
    pub fn inputs(&self, operation_id: &str) -> Result<Vec<crate::operations::InputOutcome>> {
        let mut statement = self.connection.prepare("SELECT source_path,state,error FROM operation_inputs WHERE operation_id=?1 ORDER BY source_path")?;
        Ok(statement
            .query_map([operation_id], |r| {
                Ok(crate::operations::InputOutcome {
                    source_path: r.get(0)?,
                    state: r.get(1)?,
                    error: r.get(2)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?)
    }
    /// Collect object references from active records, ancestry, and retained views.
    ///
    /// Cleanup also checks recovery state before deciding which objects to prune.
    pub fn referenced_hashes(&self) -> Result<BTreeSet<String>> {
        let mut statement=self.connection.prepare("SELECT hash FROM occurrences o WHERE NOT EXISTS(SELECT 1 FROM tombstones t WHERE t.id=o.id) UNION SELECT hash FROM view_entries UNION SELECT parent_hash FROM ancestry a JOIN occurrences o ON a.occurrence_id=o.id WHERE NOT EXISTS(SELECT 1 FROM tombstones t WHERE t.id=o.id)")?;
        let rows = statement.query_map([], |r| r.get::<_, String>(0))?;
        let mut hashes = BTreeSet::new();
        for hash in rows {
            let hash = hash?;
            ensure!(valid_hash(&hash), "invalid referenced hash");
            hashes.insert(hash);
        }
        Ok(hashes)
    }
    pub fn operations(&self) -> Result<Vec<String>> {
        let mut statement = self
            .connection
            .prepare("SELECT id,record FROM operations ORDER BY id")?;
        let mut rows = statement.query([])?;
        let mut result = Vec::new();
        while let Some(row) = rows.next()? {
            let id: String = row.get(0)?;
            let text: String = row.get(1)?;
            validate_operation(&id, &text)?;
            result.push(text);
        }
        Ok(result)
    }
    pub fn put_operation(&mut self, id: &str, record: &str) -> Result<()> {
        validate_operation(id, record)?;
        self.connection.execute("INSERT INTO operations(id,record) VALUES(?1,?2) ON CONFLICT(id) DO UPDATE SET record=excluded.record",params![id,record])?;
        Ok(())
    }
    pub fn integrity(&self) -> Result<()> {
        self.integrity_records().map(drop)
    }

    fn integrity_records(&self) -> Result<(Vec<Occurrence>, BTreeSet<String>)> {
        validate(&self.connection)?;
        let check: String = self
            .connection
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
        ensure!(check == "ok", "catalog integrity failure: {check}");
        let mut statement = self.connection.prepare("PRAGMA foreign_key_check")?;
        ensure!(
            statement.query([])?.next()?.is_none(),
            "catalog foreign-key integrity failure"
        );
        let records = self.select(&Filters::default(), true)?;
        let removed = self.removed()?;
        self.operations()?;
        validate_relationships(&self.connection)?;
        let mut objects = self.connection.prepare("SELECT hash,size FROM objects")?;
        let mut rows = objects.query([])?;
        while let Some(row) = rows.next()? {
            let hash: String = row.get(0)?;
            let size: i64 = row.get(1)?;
            ensure!(
                valid_hash(&hash) && size >= 0,
                "invalid catalog object identity or size"
            );
        }
        let mut views = self
            .connection
            .prepare("SELECT generation,path,occurrence_id,hash FROM view_entries")?;
        let mut rows = views.query([])?;
        while let Some(row) = rows.next()? {
            let generation: String = row.get(0)?;
            let path: String = row.get(1)?;
            let id: String = row.get(2)?;
            let hash: String = row.get(3)?;
            validate_view_path(&generation, &path, &id, &hash)?;
        }
        Ok((records, removed))
    }
}
fn view(connection: &Connection, generation: &str, path: &str, id: &str, hash: &str) -> Result<()> {
    validate_view_path(generation, path, id, hash)?;
    let actual: String =
        connection.query_row("SELECT hash FROM occurrences WHERE id=?1", [id], |r| {
            r.get(0)
        })?;
    ensure!(actual == hash, "view occurrence/hash mismatch");
    connection.execute(
        "INSERT INTO view_entries(generation,path,occurrence_id,hash) VALUES(?1,?2,?3,?4)",
        params![generation, path, id, hash],
    )?;
    Ok(())
}

fn validate_operation(id: &str, text: &str) -> Result<()> {
    ensure!(text.len() <= 1024 * 1024, "oversized operation record");
    let record: crate::operations::Record = serde_json::from_str(text)?;
    ensure!(
        record.schema_version == 1
            && record.id == id
            && !id.is_empty()
            && id.len() <= 128
            && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && matches!(
                record.state.as_str(),
                "running" | "completed" | "failed" | "interrupted" | "cancelled"
            ),
        "invalid operation identity or schema"
    );
    Ok(())
}
fn validate_relationships(connection: &Connection) -> Result<()> {
    let invalid:bool=connection.query_row("SELECT EXISTS(SELECT 1 FROM ancestry a JOIN occurrences p ON p.id=a.parent_id WHERE p.hash<>a.parent_hash) OR EXISTS(SELECT 1 FROM view_entries v JOIN occurrences o ON o.id=v.occurrence_id WHERE o.hash<>v.hash) OR EXISTS(SELECT 1 FROM ancestry a JOIN tombstones parent ON parent.id=a.parent_id WHERE NOT EXISTS(SELECT 1 FROM tombstones child WHERE child.id=a.occurrence_id))",[],|r|r.get(0))?;
    ensure!(!invalid, "catalog reference identity mismatch");
    Ok(())
}

fn validate_view_path(generation: &str, path: &str, id: &str, hash: &str) -> Result<()> {
    ensure!(
        !generation.is_empty()
            && Path::new(generation).components().count() == 1
            && Path::new(generation)
                .components()
                .all(|c| matches!(c, std::path::Component::Normal(_)))
            && !generation.contains('\\'),
        "unsafe view generation"
    );
    ensure!(
        !path.is_empty()
            && Path::new(path)
                .components()
                .all(|c| matches!(c, std::path::Component::Normal(_)))
            && !path.contains('\\')
            && valid_hash(id)
            && valid_hash(hash),
        "unsafe view reference"
    );
    Ok(())
}
