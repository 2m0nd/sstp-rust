// src/parser.rs

use std::sync::atomic::{AtomicBool, Ordering};

use crate::DEBUG_PARSE;


pub struct PppParsedFrame {
    pub protocol: u16,
    pub code: u8,
    pub id: u8,
    pub length: u16,
    pub payload: Vec<u8>,
}

pub fn parse_ppp_frame(buf: &[u8]) -> Option<PppParsedFrame> {
    if buf.len() < 12 {
        return None;
    }

    // Проверка на PPP Data (SSTP обёртка)
    if buf[4] != 0xFF || buf[5] != 0x03 {
        return None;
    }

    let protocol = u16::from_be_bytes([buf[6], buf[7]]);
    let code = buf[8];
    let id = buf[9];
    let length = u16::from_be_bytes([buf[10], buf[11]]);

    if buf.len() < 12 + (length as usize - 4) {
        return None;
    }

    let payload = buf[12..12 + (length as usize - 4)].to_vec();
    
    match DEBUG_PARSE.load(Ordering::Relaxed) {
        true => {
            println!("✅ Распознан PPP пакет: proto={:#06X}, code={:#04X}, id={}, payload={:02X?}", protocol, code, id, payload);
        }
        false => (),
    }

    Some(PppParsedFrame {
        protocol,
        code,
        id,
        length,
        payload,
    })
}

/// Делит SSTP-стрим на отдельные фреймы
fn split_sstp_frames(buf: &[u8]) -> Vec<&[u8]> {
    let mut frames = Vec::new();
    let mut i = 0;

    while i + 4 <= buf.len() {
        if buf[i] != 0x10 {
            break; // не SSTP
        }

        let len = u16::from_be_bytes([buf[i + 2], buf[i + 3]]) as usize;
        if i + len > buf.len() {
            break; // не хватает байт
        }

        frames.push(&buf[i..i + len]);
        i += len;
    }

    frames
}

pub fn extract_option_value(payload: &[u8], target_type: u8) -> Option<[u8; 2]> {
    let mut i = 0;
    while i + 2 <= payload.len() {
        let opt_type = payload[i];
        let opt_len = payload[i + 1] as usize;

        if opt_len < 2 || i + opt_len > payload.len() {
            break; // повреждённый или выходящий за границы пакет
        }

        if opt_type == target_type {
            if opt_len == 4 {
                return Some([payload[i + 2], payload[i + 3]]);
            } else {
                return None; // например, длина не совпадает с ожидаемой
            }
        }

        i += opt_len;
    }

    None
}

fn extract_option(payload: &[u8], option_type: u8) -> Option<&[u8]> {
    let mut i = 0;
    while i + 2 <= payload.len() {
        let typ = payload[i];
        let len = payload[i + 1] as usize;
        if len < 2 || i + len > payload.len() {
            break;
        }
        if typ == option_type {
            return Some(&payload[i + 2..i + len]);
        }
        i += len;
    }
    None
}

/// Вернёт 4-байтовое значение (IP, DNS и т.п.)
pub fn extract_option_value_u32(payload: &[u8], option_type: u8) -> Option<[u8; 4]> {
    let slice = extract_option(payload, option_type)?;
    if slice.len() == 4 {
        Some([slice[0], slice[1], slice[2], slice[3]])
    } else {
        None
    }
}

/// Вернёт 2-байтовое значение (например, auth proto)
pub fn extract_option_value_u16(payload: &[u8], option_type: u8) -> Option<[u8; 2]> {
    let slice = extract_option(payload, option_type)?;
    if slice.len() == 2 {
        Some([slice[0], slice[1]])
    } else {
        None
    }
}

pub fn extract_lcp_payload(packet: &[u8]) -> Option<&[u8]> {
    // Пропускаем SSTP (4 байта) + PPP (4 байта) + LCP header (4 байта)
    if packet.len() > 12 && packet[4..8] == [0xFF, 0x03, 0xC0, 0x21] {
        Some(&packet[12..])
    } else {
        None
    }
}

pub fn extract_all_lcp_options(payload: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut i = 0;
    let mut result = Vec::new();
    while i + 2 <= payload.len() {
        let typ = payload[i];
        let len = payload[i + 1] as usize;
        if len < 2 || i + len > payload.len() {
            break;
        }
        let data = payload[i + 2..i + len].to_vec();
        result.push((typ, data));
        i += len;
    }
    result
}

pub fn to_array_4(vec: Vec<u8>) -> [u8; 4] {
    let slice = vec.as_slice();
    [slice[0], slice[1], slice[2], slice[3]]
}