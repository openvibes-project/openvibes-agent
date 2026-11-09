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
    service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle},
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

/// How long a stop may take before the watchdog ends the process. Windows
/// Installer waits about 30 s for a service to stop; a request in flight can
/// take 60 s (`network_request_seconds`). A service still running then keeps
/// its exe locked, and replacing it would need a reboot (#125). Ending the
/// process mid-tick is safe: the SQLite state is crash-safe.
const STOP_GRACE: Duration = Duration::from_secs(10);

static STATUS: OnceLock<ServiceStatusHandle> = OnceLock::new();

fn service_main(_start_parameters: Vec<OsString>) {
    let (stop, stopped) = mpsc::channel();
    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            report(
                ServiceState::StopPending,
                ServiceExitCode::Win32(0),
                STOP_GRACE,
            );
            // The lifecycle loop stops before its next tick, or the watchdog
            // stops the process.
            let _ = stop.send(());
            std::thread::spawn(|| {
                std::thread::sleep(STOP_GRACE);
                say!(
                    Warn,
                    "openvibes-agent: a tick was still running {} s after Stop; stopping now",
                    STOP_GRACE.as_secs()
                );
                report(
                    ServiceState::Stopped,
                    ServiceExitCode::Win32(0),
                    Duration::ZERO,
                );
                std::process::exit(0);
            });
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    match service_control_handler::register(NAME, handler) {
        Ok(status) => {
            let _ = STATUS.set(status);
        }
        Err(error) => {
            say!(
                Error,
                "openvibes-agent: cannot register the service control handler: {error}"
            );
            return;
        }
    }
    report(
        ServiceState::Running,
        ServiceExitCode::Win32(0),
        Duration::ZERO,
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
    report(ServiceState::Stopped, exit_code, Duration::ZERO);
}

fn report(state: ServiceState, exit_code: ServiceExitCode, wait_hint: Duration) {
    let Some(status) = STATUS.get() else {
        return;
    };
    let controls_accepted = if state == ServiceState::Running {
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
    } else {
        ServiceControlAccept::empty()
    };
    let set = status.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted,
        exit_code,
        checkpoint: 0,
        wait_hint,
        process_id: None,
    });
    if let Err(error) = set {
        say!(
            Error,
            "openvibes-agent: cannot report the service state: {error}"
        );
    }
}
