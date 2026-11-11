//! Classify, store, and organize files and ZIP members.
//!
//! [Ingestion](ingest::pipeline) streams input into SHA-256-addressed objects.
//! The [repository catalog](repository::catalog) tracks each source occurrence
//! and its classification separately, so identical payloads can share storage
//! while retaining distinct provenance.
//!
//! Use [filters](selection::Filters) to select occurrences by saved metadata.
//! [Organization rules](organization::rules) decide their destination names.
//! [Reports](output::report) summarize the selection, and [ZIP export](output::archive)
//! packages it for use outside the repository. [Collection](collection) handles
//! remote discovery and downloads before ingestion.

pub mod app;
pub mod collection;
pub mod detection;
pub mod error;
pub mod ingest;
pub mod organization;
pub mod output;
pub mod repository;
pub mod selection;

pub mod operations;
