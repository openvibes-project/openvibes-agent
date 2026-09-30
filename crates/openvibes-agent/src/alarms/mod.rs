//! Threat alarms (protocol P14): process starts from kernel audit, their
//! lineage, `process_event` rules, and delivery of collapsed, masked
//! alarms.

pub mod table;

#[cfg(test)]
mod table_tests;
