pub mod sstp;
pub mod parser;
pub mod route;
pub mod dhcp;
use std::sync::atomic::AtomicBool;
pub static DEBUG_PARSE: AtomicBool = AtomicBool::new(false);