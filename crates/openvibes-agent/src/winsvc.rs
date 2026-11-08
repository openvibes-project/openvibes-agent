//! The agent as a Windows service: `openvibes-agent service <config.toml>`,
//! started by the Service Control Manager under the name `openvibes-agent`.
//! Log lines go to the Windows Event Log (Application log, source
//! `openvibes-agent`; the installer registers the source so Event Viewer
//! shows the text without a "description cannot be found" note).

use std::{
    ffi::OsString,
    path::PathBuf,
    process::ExitCode,
    sync::{OnceLock, mpsc},
    time::Duration,
};

use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

const NAME: &str = "openvibes-agent";

/// The config path from the command line; the dispatcher calls
/// `service_main` with the start parameters instead.
static CONFIG: OnceLock<PathBuf> = OnceLock::new();

define_windows_service!(ffi_service_main, service_main);

pub(crate) fn start(config: &OsString) -> ExitCode {
    CONFIG.get_or_init(|| PathBuf::from(config));
    if winlog2::init(NAME).is_ok() {
        // `say!` writes to the logger directly; other crates stay silent.
        log::set_max_level(log::LevelFilter::Off);
    }
    match service_dispatcher::start(NAME, ffi_service_main) {
        // `service_main` has reported how the service ended.
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            say!(
                Error,
                "openvibes-agent: not started by the Service Control Manager (use the console mode outside a service): {error}"
            );
            ExitCode::FAILURE
        }
    }
}

fn service_main(_start_parameters: Vec<OsString>) {
    let (stop, stopped) = mpsc::channel();
    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            // The lifecycle loop stops before its next tick.
            let _ = stop.send(());
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status = match service_control_handler::register(NAME, handler) {
        Ok(status) => status,
        Err(error) => {
            say!(
                Error,
                "openvibes-agent: cannot register the service control handler: {error}"
            );
            return;
        }
    };
    let report = |state, controls_accepted, exit_code| {
        let set = status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted,
            exit_code,
            checkpoint: 0,
            wait_hint: Duration::ZERO,
            process_id: None,
        });
        if let Err(error) = set {
            say!(
                Error,
                "openvibes-agent: cannot report the service state: {error}"
            );
        }
    };
    report(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        ServiceExitCode::Win32(0),
    );
    let ended = match CONFIG.get() {
        Some(config) => super::run(config, &stopped),
        None => ExitCode::FAILURE,
    };
    let exit_code = if ended == ExitCode::SUCCESS {
        ServiceExitCode::Win32(0)
    } else {
        // The reason is the last line in the Event Log.
        ServiceExitCode::ServiceSpecific(1)
    };
    report(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        exit_code,
    );
}
