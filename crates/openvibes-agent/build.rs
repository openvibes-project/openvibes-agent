//! Windows: links the Event Log message table (`res/eventmsgs.rc`) into
//! `openvibes-agent.exe`, so Event Viewer shows the agent's lines (#129).

fn main() {
    println!("cargo:rerun-if-changed=res/eventmsgs.rc");
    println!("cargo:rerun-if-changed=res/MSG00409.bin");
    #[cfg(windows)]
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        winresource::WindowsResource::new()
            .set_resource_file("res/eventmsgs.rc")
            .compile_for("openvibes-agent")
            .expect("compiling the Event Log message table (needs rc.exe from the Windows SDK)");
    }
}
