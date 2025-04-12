pub mod sstp;
pub mod log;
pub mod sstp_state_machine;
pub mod types;
pub mod parser;
pub mod ssl_verifiers;
pub mod dhcp;
pub mod tools;
#[cfg(target_os = "linux")]
pub mod async_tun_nix;

#[cfg(not(target_os = "linux"))]
pub mod async_tun;

use std::sync::atomic::AtomicBool;
pub static DEBUG_PARSE: AtomicBool = AtomicBool::new(false);