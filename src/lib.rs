pub mod sstp; // Подключает файл src/sstp.rs
pub mod parser;
pub mod dhcp;
use std::sync::atomic::AtomicBool;
pub static DEBUG_PARSE: AtomicBool = AtomicBool::new(false);