#![forbid(unsafe_code)]

use ovsvms_core::ComponentDescriptor;

fn components() -> [ComponentDescriptor; 4] {
    [
        ovsvms_collectors::descriptor(),
        ovsvms_rules::descriptor(),
        ovsvms_storage::descriptor(),
        ovsvms_transport::descriptor(),
    ]
}

fn main() {
    let component_names = components().map(ComponentDescriptor::name);
    println!(
        "OVSVMS Scanner {} (components: {})",
        env!("CARGO_PKG_VERSION"),
        component_names.join(", ")
    );
}

#[cfg(test)]
mod tests {
    use super::components;

    #[test]
    fn composition_root_includes_all_boundary_crates() {
        assert_eq!(components().len(), 4);
    }
}
