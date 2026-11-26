//! Local replacement for the Grizzl-E Connect cloud.
//!
//! An OCPP 1.6-J central system for the charger plus a REST API shaped like
//! `connect-api.unitedchargers.com` for the Home Assistant integration.

pub mod api;
pub mod config;
pub mod controller;
pub mod crypto;
pub mod healthcheck;
pub mod holidays;
pub mod logging;
pub mod net;
pub mod ocpp;
pub mod schedules;
pub mod server;
pub mod state;
pub mod store;
pub mod timeutil;
pub mod value;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
