//! Threat alarms (protocol P14): process starts from kernel audit, their
//! lineage, `process_event` rules, and delivery of collapsed, masked
//! alarms.

pub mod engine;
pub mod table;

#[cfg(test)]
mod engine_tests;
#[cfg(test)]
mod table_tests;
