pub mod sstp; // Подключает файл src/sstp.rs
pub mod parser;
use std::sync::atomic::{AtomicBool, Ordering};
pub static DEBUG_PARSE: AtomicBool = AtomicBool::new(false);