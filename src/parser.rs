// src/parser.rs

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

    Some(PppParsedFrame {
        protocol,
        code,
        id,
        length,
        payload,
    })
}

pub fn extract_option_value(payload: &[u8], option_type: u8) -> Option<[u8; 4]> {
    let mut i = 0;
    while i + 6 <= payload.len() {
        if payload[i] == option_type && payload[i + 1] == 6 {
            return Some([payload[i + 2], payload[i + 3], payload[i + 4], payload[i + 5]]);
        }
        i += payload[i + 1] as usize; // длина текущей опции
    }
    None
}