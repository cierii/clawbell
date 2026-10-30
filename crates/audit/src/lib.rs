//! Append-only audit persistence and safe history access.

#[cfg(unix)]
pub mod baseline;

#[cfg(unix)]
pub mod operations;
