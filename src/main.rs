//! Entry point: `grizzle-local` runs the server; `grizzle-local healthcheck` asks a running one.

use std::process::ExitCode;

use grizzle_local::config::Settings;
use grizzle_local::{healthcheck, logging, server, VERSION};

const USAGE: &str = "\
usage: grizzle-local [healthcheck | --version | --help]

  (no argument)  run the server; it is configured by environment variables (see README.md)
  healthcheck    exit 0 if the server configured by the same variables answers GET /health
";

fn main() -> ExitCode {
    match std::env::args().nth(1).as_deref() {
        None => {}
        Some("healthcheck") => return ExitCode::from(healthcheck::main()),
        Some("--version" | "-V") => {
            println!("grizzle-local {VERSION}");
            return ExitCode::SUCCESS;
        }
        Some("--help" | "-h") => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Some(other) => {
            eprint!("grizzle-local: unknown argument {other:?}\n{USAGE}");
            return ExitCode::from(2);
        }
    }
    let settings = match Settings::from_env() {
        Ok(settings) => settings,
        Err(err) => {
            eprintln!("grizzle-local: {err}");
            return ExitCode::from(2);
        }
    };
    logging::configure(&settings.log_level);
    // A bug that panics ends the task it happens in (one request, one station's turn in the
    // background loop) and nothing else. Say so in the log, in the log's format.
    std::panic::set_hook(Box::new(|panic| log::error!("a task failed: {panic}")));
    // One thread: a charger or two and a web page are not a workload, and everything the server
    // keeps in memory is behind one lock anyway.
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(err) => {
            log::error!("cannot start: {err}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(server::serve(settings)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            log::error!("{err}");
            ExitCode::FAILURE
        }
    }
}
