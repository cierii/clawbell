//! Append-only audit persistence and safe history access.

#[cfg(unix)]
pub mod baseline;

#[cfg(unix)]
pub mod operations;

#[cfg(unix)]
mod storage;

#[cfg(unix)]
pub mod maintenance;
