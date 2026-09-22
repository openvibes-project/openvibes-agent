#![forbid(unsafe_code)]

use openvibes_core::ComponentDescriptor;

fn components() -> [ComponentDescriptor; 4] {
    [
        openvibes_collectors::descriptor(),
        openvibes_rules::descriptor(),
        openvibes_storage::descriptor(),
        openvibes_transport::descriptor(),
    ]
}

fn main() {
    let component_names = components().map(ComponentDescriptor::name);
    println!(
        "OpenVIBES Agent {} (components: {})",
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
