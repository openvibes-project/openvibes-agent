//! Inventories have their own limits (M1 limits review): up to 50,000
//! packages, and `package.names` is the only fact list above 10,000.

use openvibes_core::{
    Fact, FactSet, FactValue, Identifier, InstalledPackage, InventoryExport, InventoryReport,
    ResourceLimits, SchemaVersion, Validate,
};

fn package() -> InstalledPackage {
    serde_json::from_str(r#"{"manager":"rpm","name":"p","version":"1"}"#).unwrap()
}

#[test]
fn inventory_reports_take_up_to_50000_packages() {
    let mut report: InventoryReport = serde_json::from_str(
        r#"{"schema_version":1,"agent_id":"agent.1","os":{"id":"fedora","version_id":"44"},
            "collected_at_unix_ms":1,"packages":[]}"#,
    )
    .unwrap();
    report.packages = vec![package(); 50_000];
    report.validate(ResourceLimits::V1).unwrap();
    report.packages.push(package());
    assert!(report.validate(ResourceLimits::V1).is_err());
}

#[test]
fn inventory_exports_take_up_to_50000_packages() {
    let mut export: InventoryExport = serde_json::from_str(
        r#"{"schema_version":1,"install_id":"inst-1","scanner_version":"0.1.0",
            "collected_at_unix_ms":1,"packages":[]}"#,
    )
    .unwrap();
    export.packages = vec![package(); 50_000];
    export.validate(ResourceLimits::V1).unwrap();
    export.packages.push(package());
    assert!(export.validate(ResourceLimits::V1).is_err());
}

#[test]
fn package_names_is_the_only_fact_list_above_10000() {
    let names: Vec<String> = (0..20_000).map(|i| format!("p{i:05}")).collect();
    let set = |key: &str| FactSet {
        schema_version: SchemaVersion::V1,
        scan_id: Identifier::new("scan.1").unwrap(),
        collected_at_unix_ms: 1,
        facts: vec![Fact {
            key: Identifier::new(key).unwrap(),
            source: Identifier::new("packages").unwrap(),
            value: FactValue::StringList(names.clone()),
        }],
        errors: Vec::new(),
    };
    assert!(set("package.names").validate(ResourceLimits::V1).is_ok());
    assert!(set("process.names").validate(ResourceLimits::V1).is_err());
}

#[test]
fn the_new_limits_have_their_values() {
    assert_eq!(ResourceLimits::V1.inventory_items, 50_000);
    assert_eq!(ResourceLimits::V1.inventory_document_bytes, 8 * 1024 * 1024);
}
