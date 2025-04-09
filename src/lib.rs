pub mod sstp;
pub mod log;
pub mod route;
pub mod async_tun;
pub mod sstp_state_machine;
pub mod types;
pub mod parser;
pub mod ssl_verifiers;
pub mod dhcp;

use std::sync::atomic::AtomicBool;
pub static DEBUG_PARSE: AtomicBool = AtomicBool::new(false);