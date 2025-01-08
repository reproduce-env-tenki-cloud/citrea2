// SPDX-License-Identifier: Apache-2.0
// Adapted from aptos-core/schemadb

#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! This library implements a schematized DB on top of [RocksDB](https://rocksdb.org/). It makes
//! sure all data passed in and out are structured according to predefined schemas and prevents
//! access to raw keys and values. This library also enforces a set of specific DB options,
//! like custom comparators and schema-to-column-family mapping.
//!
//! It requires that different kinds of key-value pairs be stored in separate column
//! families.  To use this library to store a kind of key-value pairs, the user needs to use the
//! [`define_schema!`] macro to define the schema name, the types of key and value, and name of the
//! column family.

mod iterator;
mod metrics;
pub mod schema;
mod schema_batch;
pub mod snapshot;
#[cfg(feature = "test-utils")]
pub mod test;

use std::path::Path;
use std::time::Instant;

use ::metrics::{gauge, histogram};
use anyhow::format_err;
use iterator::ScanDirection;
pub use iterator::{RawDbReverseIterator, SchemaIterator, SeekKeyEncoder};
pub use rocksdb;
pub use rocksdb::DEFAULT_COLUMN_FAMILY_NAME;
use rocksdb::{DBIterator, ReadOptions};
use thiserror::Error;
use tracing::info;

pub use crate::metrics::SCHEMADB_METRICS;
pub use crate::schema::Schema;
use crate::schema::{ColumnFamilyName, KeyCodec, ValueCodec};
pub use crate::schema_batch::{SchemaBatch, SchemaBatchIterator};

/// This DB is a schematized RocksDB wrapper where all data passed in and out are typed according to
/// [`Schema`]s.
#[derive(Debug)]
pub struct DB {
    name: &'static str, // for logging
    inner: rocksdb::DB,
}

impl DB {
    /// Opens a database backed by RocksDB, using the provided column family names and default
    /// column family options.
    pub fn open(
        path: impl AsRef<Path>,
        name: &'static str,
        column_families: impl IntoIterator<Item = impl Into<String>>,
        options: &RawRocksdbOptions,
    ) -> anyhow::Result<Self> {
        let db = DB::open_with_cfds(
            &options.db_options,
            path,
            name,
            column_families.into_iter().map(|cf_name| {
                let mut cf_opts = rocksdb::Options::default();
                cf_opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
                cf_opts.set_block_based_table_factory(&options.block_options);
                rocksdb::ColumnFamilyDescriptor::new(cf_name, cf_opts)
            }),
        )?;
        Ok(db)
    }

    /// Returns the path of the DB.
    pub fn path(&self) -> &Path {
        self.inner.path()
    }

    /// Lists column families in the DB.
    pub fn list_column_families(&self) -> Vec<String> {
        rocksdb::DB::list_cf(&rocksdb::Options::default(), self.path())
            .expect("Should list column families")
    }

    /// Open RocksDB with the provided column family descriptors.
    /// This allows to configure options for each column family.
    pub fn open_with_cfds(
        db_opts: &rocksdb::Options,
        path: impl AsRef<Path>,
        name: &'static str,
        cfds: impl IntoIterator<Item = rocksdb::ColumnFamilyDescriptor>,
    ) -> anyhow::Result<DB> {
        let inner = rocksdb::DB::open_cf_descriptors(db_opts, path, cfds)?;
        Ok(Self::log_construct(name, inner))
    }

    /// Open db in readonly mode. This db is completely static, so any writes that occur on the primary
    /// after it has been opened will not be visible to the readonly instance.
    pub fn open_cf_readonly(
        opts: &rocksdb::Options,
        path: impl AsRef<Path>,
        name: &'static str,
        cfs: Vec<ColumnFamilyName>,
    ) -> anyhow::Result<DB> {
        let error_if_log_file_exists = false;
        let inner = rocksdb::DB::open_cf_for_read_only(opts, path, cfs, error_if_log_file_exists)?;

        Ok(Self::log_construct(name, inner))
    }

    /// Open db in secondary mode. A secondary db is does not support writes, but can be dynamically caught up
    /// to the primary instance by a manual call. See <https://github.com/facebook/rocksdb/wiki/Read-only-and-Secondary-instances>
    /// for more details.
    pub fn open_cf_as_secondary<P: AsRef<Path>>(
        opts: &rocksdb::Options,
        primary_path: P,
        secondary_path: P,
        name: &'static str,
        cfs: Vec<ColumnFamilyName>,
    ) -> anyhow::Result<DB> {
        let inner = rocksdb::DB::open_cf_as_secondary(opts, primary_path, secondary_path, cfs)?;
        Ok(Self::log_construct(name, inner))
    }

    fn log_construct(name: &'static str, inner: rocksdb::DB) -> DB {
        info!(rocksdb_name = name, "Opened RocksDB.");
        DB { name, inner }
    }

    /// Reads single record by key.
    pub fn get<S: Schema>(
        &self,
        schema_key: &impl KeyCodec<S>,
    ) -> anyhow::Result<Option<S::Value>> {
        tokio::task::block_in_place(|| self._get(schema_key))
    }

    fn _get<S: Schema>(&self, schema_key: &impl KeyCodec<S>) -> anyhow::Result<Option<S::Value>> {
        let start = Instant::now();

        let k = schema_key.encode_key()?;
        let cf_handle = self.get_cf_handle(S::COLUMN_FAMILY_NAME)?;

        let result = self.inner.get_pinned_cf(cf_handle, k)?;

        histogram!("schemadb_get_bytes", "cf_name" => S::COLUMN_FAMILY_NAME)
            .record(result.as_ref().map_or(0.0, |v| v.len() as f64));

        let result = result
            .map(|raw_value| <S::Value as ValueCodec<S>>::decode_value(&raw_value))
            .transpose()
            .map_err(|err| err.into());

        histogram!("schemadb_get_latency_seconds", "cf_name" => S::COLUMN_FAMILY_NAME).record(
            Instant::now()
                .saturating_duration_since(start)
                .as_secs_f64(),
        );
        result
    }

    /// Writes single record.
    pub fn put<S: Schema>(
        &self,
        key: &impl KeyCodec<S>,
        value: &impl ValueCodec<S>,
    ) -> anyhow::Result<()> {
        tokio::task::block_in_place(|| self._put(key, value))
    }

    fn _put<S: Schema>(
        &self,
        key: &impl KeyCodec<S>,
        value: &impl ValueCodec<S>,
    ) -> anyhow::Result<()> {
        // Not necessary to use a batch, but we'd like a central place to bump counters.
        // Used in tests only anyway.
        let mut batch = SchemaBatch::new();
        batch.put::<S>(key, value)?;
        self.write_schemas(batch)
    }

    /// Delete a single key from the database.
    pub fn delete<S: Schema>(&self, key: &impl KeyCodec<S>) -> anyhow::Result<()> {
        tokio::task::block_in_place(|| self._delete(key))
    }

    fn _delete<S: Schema>(&self, key: &impl KeyCodec<S>) -> anyhow::Result<()> {
        // Not necessary to use a batch, but we'd like a central place to bump counters.
        // Used in tests only anyway.
        let mut batch = SchemaBatch::new();
        batch.delete::<S>(key)?;
        self.write_schemas(batch)
    }

    /// Removes the database entries in the range `["from", "to")` using default write options.
    ///
    /// Note that this operation will be done lexicographic on the *encoding* of the seek keys. It is
    /// up to the table creator to ensure that the lexicographic ordering of the encoded seek keys matches the
    /// logical ordering of the type.
    pub fn delete_range<S: Schema>(
        &self,
        from: &impl SeekKeyEncoder<S>,
        to: &impl SeekKeyEncoder<S>,
    ) -> anyhow::Result<()> {
        tokio::task::block_in_place(|| self._delete_range(from, to))
    }

    fn _delete_range<S: Schema>(
        &self,
        from: &impl SeekKeyEncoder<S>,
        to: &impl SeekKeyEncoder<S>,
    ) -> anyhow::Result<()> {
        let cf_handle = self.get_cf_handle(S::COLUMN_FAMILY_NAME)?;
        let from = from.encode_seek_key()?;
        let to = to.encode_seek_key()?;
        self.inner.delete_range_cf(cf_handle, from, to)?;
        Ok(())
    }

    fn iter_with_direction<S: Schema>(
        &self,
        opts: ReadOptions,
        direction: ScanDirection,
    ) -> anyhow::Result<SchemaIterator<S>> {
        let cf_handle = self.get_cf_handle(S::COLUMN_FAMILY_NAME)?;
        Ok(SchemaIterator::new(
            self.inner.raw_iterator_cf_opt(cf_handle, opts),
            direction,
        ))
    }

    /// Returns a forward [`SchemaIterator`] on a certain schema with the default read options.
    pub fn iter<S: Schema>(&self) -> anyhow::Result<SchemaIterator<S>> {
        let mut read_options = ReadOptions::default();
        read_options.set_async_io(true);
        self.iter_with_direction::<S>(read_options, ScanDirection::Forward)
    }

    /// Drops a column family from the database.
    pub fn drop_cf(&mut self, cf_name: &str) -> anyhow::Result<()> {
        Ok(self.inner.drop_cf(cf_name)?)
    }

    /// Inserts a key value pair to a column family.
    pub fn put_cf(
        &self,
        cf_handle: &rocksdb::ColumnFamily,
        key: &[u8],
        value: &[u8],
    ) -> anyhow::Result<()> {
        self.inner.put_cf(cf_handle, key, value)?;
        Ok(())
    }

    /// Returns an iterator over a column family
    pub fn iter_cf<'a>(
        &'a self,
        cf_handle: &rocksdb::ColumnFamily,
        iter_mode: Option<rocksdb::IteratorMode>,
    ) -> DBIterator<'a> {
        self.inner
            .iterator_cf(cf_handle, iter_mode.unwrap_or(rocksdb::IteratorMode::Start))
    }

    /// Returns a [`RawDbReverseIterator`] which allows to iterate over raw values, backwards
    pub fn raw_iter<S: Schema>(&self) -> anyhow::Result<RawDbReverseIterator> {
        let cf_handle = self.get_cf_handle(S::COLUMN_FAMILY_NAME)?;
        Ok(RawDbReverseIterator::new(
            self.inner
                .raw_iterator_cf_opt(cf_handle, Default::default()),
        ))
    }

    /// Returns a forward [`SchemaIterator`] on a certain schema with the provided read options.
    pub fn iter_with_opts<S: Schema>(
        &self,
        opts: ReadOptions,
    ) -> anyhow::Result<SchemaIterator<S>> {
        self.iter_with_direction::<S>(opts, ScanDirection::Forward)
    }

    /// Writes a group of records wrapped in a [`SchemaBatch`].
    pub fn write_schemas(&self, batch: SchemaBatch) -> anyhow::Result<()> {
        tokio::task::block_in_place(|| self._write_schemas(batch))
    }

    fn _write_schemas(&self, batch: SchemaBatch) -> anyhow::Result<()> {
        let start = Instant::now();

        let mut db_batch = rocksdb::WriteBatch::default();
        for (cf_name, rows) in batch.last_writes.iter() {
            let cf_handle = self.get_cf_handle(cf_name)?;
            for (key, operation) in rows {
                match operation {
                    Operation::Put { value } => db_batch.put_cf(cf_handle, key, value),
                    Operation::Delete => db_batch.delete_cf(cf_handle, key),
                }
            }
        }
        let serialized_size = db_batch.size_in_bytes();

        self.inner.write_opt(db_batch, &default_write_options())?;

        // Bump counters only after DB write succeeds.
        for (cf_name, rows) in batch.last_writes.iter() {
            for (key, operation) in rows {
                match operation {
                    Operation::Put { value } => {
                        histogram!("schemadb_put_bytes").record((key.len() + value.len()) as f64);
                    }
                    Operation::Delete => {
                        gauge!("schemadb_deletes", "cf_name" => cf_name.to_owned()).increment(1)
                    }
                }
            }
        }

        histogram!("schemadb_batch_commit_bytes").record(serialized_size as f64);

        histogram!("schemadb_batch_commit_latency_seconds", "db_name" => self.name).record(
            Instant::now()
                .saturating_duration_since(start)
                .as_secs_f64(),
        );

        Ok(())
    }

    /// Returns the handle for a rocksdb column family.
    pub fn get_cf_handle(&self, cf_name: &str) -> anyhow::Result<&rocksdb::ColumnFamily> {
        self.inner.cf_handle(cf_name).ok_or_else(|| {
            format_err!(
                "DB::cf_handle not found for column family name: {}",
                cf_name
            )
        })
    }

    /// Flushes [MemTable](https://github.com/facebook/rocksdb/wiki/MemTable) data.
    /// This is only used for testing `get_approximate_sizes_cf` in unit tests.
    pub fn flush_cf(&self, cf_name: &str) -> anyhow::Result<()> {
        Ok(self.inner.flush_cf(self.get_cf_handle(cf_name)?)?)
    }

    /// Returns the current RocksDB property value for the provided column family name
    /// and property name.
    pub fn get_property(&self, cf_name: &str, property_name: &str) -> anyhow::Result<u64> {
        self.inner
            .property_int_value_cf(self.get_cf_handle(cf_name)?, property_name)?
            .ok_or_else(|| {
                format_err!(
                    "Unable to get property \"{}\" of  column family \"{}\".",
                    property_name,
                    cf_name,
                )
            })
    }

    /// Creates new physical DB checkpoint in directory specified by `path`.
    pub fn create_checkpoint<P: AsRef<Path>>(&self, path: P) -> anyhow::Result<()> {
        tokio::task::block_in_place(|| self._create_checkpoint(path))
    }

    fn _create_checkpoint<P: AsRef<Path>>(&self, path: P) -> anyhow::Result<()> {
        rocksdb::checkpoint::Checkpoint::new(&self.inner)?.create_checkpoint(path)?;
        Ok(())
    }
}

/// Raw rocksdb config wrapper. Useful to convert user provided config into
/// the actual rocksdb config with all defaults set.
pub struct RawRocksdbOptions {
    /// Global db options
    pub db_options: rocksdb::Options,
    /// Per column-family options
    pub block_options: rocksdb::BlockBasedOptions,
}

/// Readability alias for a key in the DB.
pub type SchemaKey = Vec<u8>;
/// Readability alias for a value in the DB.
pub type SchemaValue = Vec<u8>;

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
/// Represents operation written to the database
pub enum Operation {
    /// Writing a value to the DB.
    Put {
        /// Value to write
        value: SchemaValue,
    },
    /// Deleting a value
    Delete,
}

/// An error that occurred during (de)serialization of a [`Schema`]'s keys or
/// values.
#[derive(Error, Debug)]
pub enum CodecError {
    /// Unable to deserialize a key because it has a different length than
    /// expected.
    #[error("Invalid key length. Expected {expected:}, got {got:}")]
    #[allow(missing_docs)] // The fields' names are self-explanatory.
    InvalidKeyLength { expected: usize, got: usize },
    /// Some other error occurred when (de)serializing a key or value. Inspect
    /// the inner [`anyhow::Error`] for more details.
    #[error(transparent)]
    Wrapped(#[from] anyhow::Error),
    /// I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// For now we always use synchronous writes. This makes sure that once the operation returns
/// `Ok(())` the data is persisted even if the machine crashes. In the future we might consider
/// selectively turning this off for some non-critical writes to improve performance.
fn default_write_options() -> rocksdb::WriteOptions {
    let mut opts = rocksdb::WriteOptions::default();
    opts.set_sync(true);
    opts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_db_debug_output() {
        let tmpdir = tempfile::tempdir().unwrap();
        let column_families = vec![DEFAULT_COLUMN_FAMILY_NAME];

        let mut db_opts = rocksdb::Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);

        let block_opts = rocksdb::BlockBasedOptions::default();
        let db = DB::open(
            tmpdir.path(),
            "test_db_debug",
            column_families,
            &RawRocksdbOptions {
                db_options: db_opts,
                block_options: block_opts,
            },
        )
        .expect("Failed to open DB.");

        let db_debug = format!("{:?}", db);
        assert!(db_debug.contains("test_db_debug"));
        assert!(db_debug.contains(tmpdir.path().to_str().unwrap()));
    }
}
