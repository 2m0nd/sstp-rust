use chrono::Local;

use crate::types::PppState;

/// Форматированный лог с временной меткой
pub fn log_line(msg: &str) {
    let now = Local::now().format("%H:%M:%S");
    println!("{} {}", now, msg);
}

/// Лог отправки пакета
pub fn log_send(label: &str, packet: &[u8], state: &PppState) {
    //println!("📤 {:?} → отправлено ({} байт): {:02X?}", state, packet.len(), packet);
    //println!("🔄 Текущий state: {:?}", state);
}

/// Лог отправки LCP опции
pub fn log_send_lcp(id: u8, option_type: u8, data: &[u8]) {
    let hex_str = data.iter().map(|b| format!("{:02X}", b)).collect::<String>();
    log_line(&format!("Send LCP #{} Option={} Data={}", id, option_type, hex_str));
}

/// Лог отправки LCP опции
pub fn log_send_ipcp(id: u8, option_type: u8, data: &[u8]) {
    let hex_str = data.iter().map(|b| format!("{:02X}", b)).collect::<String>();
    log_line(&format!("Send IPCP #{} Option={} Data={}", id, option_type, hex_str));
}

/// Лог отправки LCP опции
pub fn log_recv_ipcp(id: u8, option_type: u8, data: &[u8]) {
    let hex_str = data.iter().map(|b| format!("{:02X}", b)).collect::<String>();
    log_line(&format!("Received IPCP *{} Option={} Data={}", id, option_type, hex_str));
}

/// Лог получения LCP опции
pub fn log_recv_lcp(id: u8, option_type: u8, data: &[u8]) {
    let hex_str = data.iter().map(|b| format!("{:02X}", b)).collect::<String>();
    log_line(&format!("Received LCP *{} Option={} Data={}", id, option_type, hex_str));
}