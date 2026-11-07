//! SQLite storage for occurrence metadata and repository relationships.
//!
//! Object bytes live in the filesystem. The catalog stores their identities,
//! occurrence records, indexed selection fields, ancestry, retained views, and
//! operation history. A repository mutation normally goes through
//! [`Repository::with_catalog`](super::storage::Repository::with_catalog) so it
//! shares the repository lock and serialized writer connection.
use super::{
    metadata::{self, Occurrence},
    security,
    storage::valid_hash,
};
use crate::{
    app::config::SecurityMode, ingest::discovery::check_path, organization::rules::Planned,
    selection::Filters,
};
use anyhow::{Result, ensure};
use rusqlite::{Connection, OpenFlags, params, types::Value};
use std::{
    collections::BTreeSet,
    fs,
    io::{BufRead, BufReader, Read},
    path::Path,
};
pub const FILE_NAME: &str = "metadata.sqlite3";
const APPLICATION_ID: i64 = 0x42465331;
const VERSION: i64 = 2;
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
    for suffix in ["", "-journal", "-wal", "-shm"] {
        let path = root.join(format!("{FILE_NAME}{suffix}"));
        check_path(&path)?;
        if path.try_exists()? {
            security::validate_file(&path, SecurityMode::Standard)?;
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
        (version == 1 || version == VERSION) && app == APPLICATION_ID,
        "unsupported SQLite catalog schema or application identity"
    );
    Ok(())
}
fn schema(connection: &Connection) -> Result<()> {
    connection.execute_batch("BEGIN;
CREATE TABLE objects(hash TEXT PRIMARY KEY,size INTEGER NOT NULL CHECK(size>=0));
CREATE TABLE occurrences(id TEXT PRIMARY KEY,hash TEXT NOT NULL REFERENCES objects(hash),normalized_extension TEXT NOT NULL,detected_format TEXT NOT NULL,mismatch TEXT NOT NULL,source_path TEXT NOT NULL,entry_index INTEGER NOT NULL CHECK(entry_index>=0),record TEXT NOT NULL,structural INTEGER NOT NULL DEFAULT 0 CHECK(structural IN (0,1)));
CREATE TABLE ancestry(occurrence_id TEXT PRIMARY KEY REFERENCES occurrences(id) DEFERRABLE INITIALLY DEFERRED,parent_id TEXT REFERENCES occurrences(id) DEFERRABLE INITIALLY DEFERRED,parent_hash TEXT NOT NULL);
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
PRAGMA application_id=1111905073;PRAGMA user_version=2;COMMIT;")?;
    Ok(())
}
fn memory(root: &Path) -> Result<Catalog> {
    let mut catalog = Catalog {
        connection: Connection::open_in_memory()?,
    };
    configure(&catalog.connection, true)?;
    schema(&catalog.connection)?;
    catalog.import(root)?;
    Ok(catalog)
}
/// Open the existing catalog read-only, or load legacy records into memory.
///
/// A legacy read leaves the repository unchanged. If a database exists,
/// failure to open or validate it is returned to the caller.
pub fn read(root: &Path) -> Result<Catalog> {
    if !exists(root)? {
        return memory(root);
    }
    let connection = Connection::open_with_flags(
        root.join(FILE_NAME),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    configure(&connection, false)?;
    validate(&connection)?;
    Ok(Catalog { connection })
}
/// Open the writable catalog, migrating legacy metadata or schema as needed.
///
/// The caller must hold the repository lock while writing.
pub fn write(root: &Path) -> Result<Catalog> {
    if exists(root)? {
        let connection = Connection::open_with_flags(
            root.join(FILE_NAME),
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        validate(&connection)?;
        configure(&connection, true)?;
        if connection.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))? == 1 {
            connection.execute_batch("BEGIN IMMEDIATE; ALTER TABLE occurrences ADD COLUMN structural INTEGER NOT NULL DEFAULT 0 CHECK(structural IN (0,1)); CREATE TABLE operation_inputs(operation_id TEXT NOT NULL REFERENCES operations(id),source_path TEXT NOT NULL,state TEXT NOT NULL,error TEXT,PRIMARY KEY(operation_id,source_path)); PRAGMA user_version=2; COMMIT;")?;
        }
        validate_relationships(&connection)?;
        return Ok(Catalog { connection });
    }
    let temporary = tempfile::NamedTempFile::new_in(root)?;
    let connection = Connection::open(temporary.path())?;
    configure(&connection, true)?;
    schema(&connection)?;
    let mut catalog = Catalog { connection };
    catalog.import(root)?;
    catalog.integrity()?;
    drop(catalog);
    temporary.as_file().sync_all()?;
    temporary.persist_noclobber(root.join(FILE_NAME))?;
    fs::File::open(root)?.sync_all()?;
    write(root)
}
fn enum_text(value: &impl serde::Serialize) -> Result<String> {
    Ok(serde_json::to_value(value)?
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("invalid enum value"))?
        .to_owned())
}
fn insert(connection: &Connection, row: &Occurrence) -> Result<()> {
    row.validate()?;
    let serialized = serde_json::to_string(row)?;
    ensure!(
        serialized.len() <= 1024 * 1024,
        "oversized occurrence record"
    );
    let size = i64::try_from(row.size)?;
    let index = i64::try_from(row.entry_index)?;
    let old = connection.query_row(
        "SELECT hash,size FROM objects WHERE hash=?1",
        [&row.sha256],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
    );
    match old {
        Ok((_, existing)) => ensure!(existing == size, "conflicting object size"),
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            connection.execute(
                "INSERT INTO objects(hash,size) VALUES(?1,?2)",
                params![row.sha256, size],
            )?;
        }
        Err(e) => return Err(e.into()),
    }
    let old = connection.query_row(
        "SELECT hash,record FROM occurrences WHERE id=?1",
        [&row.occurrence_id],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
    );
    match old {
        Ok((hash, record)) => {
            let previous: Occurrence = serde_json::from_str(&record)?;
            previous.validate()?;
            ensure!(
                hash == row.sha256
                    && previous.sha256 == hash
                    && previous.occurrence_id == row.occurrence_id
                    && previous.size == row.size,
                "conflicting occurrence metadata"
            );
            if previous.structural && !row.structural {
                let mut promoted = previous;
                promoted.structural = false;
                connection.execute(
                    "UPDATE occurrences SET structural=0,record=?1 WHERE id=?2",
                    params![serde_json::to_string(&promoted)?, row.occurrence_id],
                )?;
            }
            return Ok(());
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => (),
        Err(e) => return Err(e.into()),
    }
    connection.execute("INSERT INTO occurrences(id,hash,normalized_extension,detected_format,mismatch,source_path,entry_index,record,structural) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",params![row.occurrence_id,row.sha256,crate::detection::mismatch::normalize_extension(&row.original_extension),enum_text(&row.detection.detected_format)?,row.mismatch.status.as_str(),row.source_path,index,serde_json::to_string(row)?,row.structural])?;
    if let Some(n) = &row.nested {
        connection.execute(
            "INSERT INTO ancestry(occurrence_id,parent_id,parent_hash) VALUES(?1,?2,?3)",
            params![row.occurrence_id, n.parent_occurrence_id, n.parent_sha256],
        )?;
    }
    Ok(())
}
fn predicate(
    filters: &Filters,
    include_removed: bool,
    structural_supported: bool,
) -> Result<(String, Vec<Value>)> {
    filters.validate()?;
    let mut clauses = Vec::new();
    let mut values = Vec::new();
    if !include_removed {
        if structural_supported {
            clauses.push("o.structural=0".into());
        }
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
    fn import(&mut self, root: &Path) -> Result<()> {
        let records = metadata::load_legacy(root)?;
        let removed = super::cleanup::removed_legacy(root)?;
        let transaction = self.connection.transaction()?;
        for row in &records {
            insert(&transaction, row)?;
        }
        for id in removed {
            ensure!(valid_hash(&id), "invalid removed occurrence identity");
            transaction.execute("INSERT INTO tombstones(id) VALUES(?1)", [id])?;
        }
        let views = root.join("views");
        check_path(&views)?;
        if views.try_exists()? {
            for entry in fs::read_dir(&views)? {
                let entry = entry?;
                if entry.file_name() == "CURRENT" {
                    security::validate_file(&entry.path(), SecurityMode::Standard)?;
                    ensure!(
                        entry.metadata()?.len() <= 4096,
                        "oversized current view pointer"
                    );
                    let pointer = fs::read_to_string(entry.path())?;
                    let generation = pointer.trim();
                    ensure!(
                        !generation.is_empty()
                            && Path::new(generation).components().count() == 1
                            && Path::new(generation)
                                .components()
                                .all(|c| matches!(c, std::path::Component::Normal(_)))
                            && !generation.contains('\\'),
                        "unsafe current view pointer"
                    );
                    check_path(&views.join(generation))?;
                    ensure!(
                        views.join(generation).is_dir(),
                        "missing current view generation"
                    );
                    continue;
                }
                let path = entry.path();
                check_path(&path)?;
                ensure!(entry.file_type()?.is_dir(), "invalid view generation");
                let generation = entry.file_name().to_string_lossy().into_owned();
                let layout = path.join("layout.jsonl");
                security::validate_file(&layout, SecurityMode::Standard)?;
                let mut reader = BufReader::new(fs::File::open(layout)?);
                loop {
                    let mut line = Vec::new();
                    let n =
                        Read::take(&mut reader, 1024 * 1024 + 1).read_until(b'\n', &mut line)?;
                    if n == 0 {
                        break;
                    }
                    ensure!(
                        n <= 1024 * 1024 && line.ends_with(b"\n"),
                        "invalid view layout record"
                    );
                    #[derive(serde::Deserialize)]
                    #[serde(deny_unknown_fields)]
                    struct Entry {
                        path: String,
                        sha256: String,
                        occurrence_id: String,
                    }
                    let row: Entry = serde_json::from_slice(&line)?;
                    view(
                        &transaction,
                        &generation,
                        &row.path,
                        &row.occurrence_id,
                        &row.sha256,
                    )?;
                }
            }
        }
        for record in crate::operations::load_legacy(root)? {
            transaction.execute(
                "INSERT INTO operations(id,record) VALUES(?1,?2)",
                params![record.id, serde_json::to_string(&record)?],
            )?;
        }
        validate_relationships(&transaction)?;
        transaction.commit()?;
        Ok(())
    }
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
            row.validate()?;
            let text: String = transaction.query_row(
                "SELECT record FROM occurrences WHERE id=?1",
                [&row.occurrence_id],
                |r| r.get(0),
            )?;
            let mut original: Occurrence = serde_json::from_str(&text)?;
            ensure!(
                original.sha256 == row.sha256 && original.size == row.size,
                "classification identity mismatch"
            );
            original.detection = row.detection.clone();
            original.mismatch = row.mismatch.clone();
            transaction.execute(
                "UPDATE occurrences SET detected_format=?1,mismatch=?2,record=?3 WHERE id=?4",
                params![
                    enum_text(&original.detection.detected_format)?,
                    original.mismatch.status.as_str(),
                    serde_json::to_string(&original)?,
                    original.occurrence_id
                ],
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
        let structural_supported =
            self.connection
                .pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))?
                >= 2;
        let structural = if structural_supported {
            "o.structural"
        } else {
            "0"
        };
        let (predicate, values) = predicate(filters, include_removed, structural_supported)?;
        let mut statement=self.connection.prepare(&format!("SELECT o.record,o.id,o.hash,b.size,o.normalized_extension,o.detected_format,o.mismatch,o.source_path,o.entry_index,{structural},a.occurrence_id,a.parent_id,a.parent_hash FROM occurrences o JOIN objects b ON o.hash=b.hash LEFT JOIN ancestry a ON a.occurrence_id=o.id WHERE {predicate} ORDER BY o.source_path,o.entry_index,o.id"))?;
        let mut query = statement.query(rusqlite::params_from_iter(values))?;
        let mut result = Vec::new();
        while let Some(row) = query.next()? {
            let text: String = row.get(0)?;
            ensure!(text.len() <= 1024 * 1024, "oversized occurrence record");
            let record: Occurrence = serde_json::from_str(&text)?;
            record.validate()?;
            ensure!(
                record.occurrence_id == row.get::<_, String>(1)?
                    && record.sha256 == row.get::<_, String>(2)?
                    && i64::try_from(record.size)? == row.get::<_, i64>(3)?
                    && crate::detection::mismatch::normalize_extension(&record.original_extension)
                        == row.get::<_, String>(4)?
                    && enum_text(&record.detection.detected_format)? == row.get::<_, String>(5)?
                    && record.mismatch.status.as_str() == row.get::<_, String>(6)?
                    && record.source_path == row.get::<_, String>(7)?
                    && i64::try_from(record.entry_index)? == row.get::<_, i64>(8)?
                    && record.structural == row.get::<_, bool>(9)?,
                "catalog record/index identity mismatch"
            );
            let ancestor_id: Option<String> = row.get(10)?;
            let parent: Option<String> = row.get(11)?;
            let hash: Option<String> = row.get(12)?;
            match (&record.nested, ancestor_id) {
                (None, None) => (),
                (Some(n), Some(_)) => ensure!(
                    n.parent_occurrence_id == parent && Some(&n.parent_sha256) == hash.as_ref(),
                    "catalog nested provenance/index mismatch"
                ),
                _ => anyhow::bail!("catalog nested provenance/index mismatch"),
            }
            result.push(record);
        }
        Ok(result)
    }
    /// Count visible occurrences and distinct object hashes directly in SQL.
    pub fn counts(&self, filters: &Filters) -> Result<Counts> {
        let structural_supported =
            self.connection
                .pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))?
                >= 2;
        let (predicate, values) = predicate(filters, false, structural_supported)?;
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
        if self
            .connection
            .pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))?
            < 2
        {
            return Ok(vec![]);
        }
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
        self.select(&Filters::default(), true)?;
        self.removed()?;
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
        Ok(())
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
