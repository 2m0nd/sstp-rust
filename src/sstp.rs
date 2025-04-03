use tokio::io::AsyncReadExt;
use uuid::Uuid;
use crate::parser::parse_ppp_frame;
use crate::parser::PppParsedFrame;
use std::collections::HashMap;

pub fn build_sstp_hello(correlation_id: Uuid) -> Vec<u8> {
    let mut hello = vec![
        0x10, 0x01,       // Version (1.0) + Control Bit
        0x00, 0x0E,       // Length = 14 bytes
        0x00, 0x01,       // Message Type = Call Connect Request
        0x00, 0x01,       // Attribute Count = 1
        // AVP 1: Encapsulated Protocol
        0x01, 0x00,       // Attribute ID + Reserved
        0x00, 0x06,       // Attribute Length = 6
        0x00, 0x01        // Value = PPP
    ];

    println!("📦 Minimal SSTP Hello длина: {} байт", hello.len());
    hello
}

pub fn parse_sstp_control_packet(buf: &[u8]) {
    if buf.len() >= 6 && buf[0] == 0x10 && buf[1] == 0x01 {
        let length = u16::from_be_bytes([buf[2], buf[3]]);
        let message_type = u16::from_be_bytes([buf[4], buf[5]]);
        println!("🧩 SSTP Message: длина = {}, тип = 0x{:04X}", length, message_type);

        match message_type {
            0x0001 => println!("📨 Call Connect Request (от клиента)"),
            0x0002 => println!("✅ Получен Call Connect ACK — сервер подтвердил Hello"),
            0x0003 => println!("🎉 Получен Call Connected — соединение установлено, готов к PPP"),
            0x0004 => println!("⚠️ Получен Call Abort — аварийное завершение"),
            0x0005 => println!("⛔ Получен Call Disconnect — сервер сбросил соединение"),
            0x0006 => println!("🔄 Echo Request"),
            0x0007 => println!("📡 Echo Response"),
            0x0008 => println!("🔧 Set PPP Discriminator"),
            other => println!("❓ Неизвестный тип сообщения: 0x{:04X}", other),
        }
    } else {
        println!("⚠️ Ответ не похож на SSTP Control Packet.");
    }
}

pub fn parse_sstp_data_packet(buf: &[u8]) -> Option<PppParsedFrame> {
    if let Some(ppp) = parse_ppp_frame(buf) {
        // println!("📦 SSTP Data Packet: длина = {}", buf.len());
        // println!("🔗 PPP Protocol: 0x{:04X}", ppp.protocol);
        // println!("🔗 PPP Code: 0x{:04X}", ppp.code);

        let code_str = match ppp.code {
            1 => "Configure-Request",
            2 => "Configure-Ack",
            3 => "Configure-Nak",
            4 => "Configure-Reject",
            5 => "Terminate-Request",
            6 => "Terminate-Ack",
            9 => "Echo-Request",
            10 => "Echo-Reply",
            _ => "Неизвестно",
        };

        println!(
            "📨 PPP Frame: Code = {} ({}), ID = {}, Length = {}",
            ppp.code, code_str, ppp.id, ppp.length
        );
        Some(ppp)
    } else {
        println!("⚠️ Не удалось разобрать SSTP Data Packet как PPP.");
        return None;
    }
}

pub fn build_configure_ack(reply_id: u8, options: &[u8]) -> Vec<u8> {
    let mut ppp = vec![
        0xFF, 0x03,
        0xC0, 0x21,
        0x02,
        reply_id,
    ];

    let length = (options.len() + 4) as u16;
    ppp.push((length >> 8) as u8);
    ppp.push((length & 0xFF) as u8);
    ppp.extend_from_slice(options);

    let total_len = ppp.len() + 4;
    let mut sstp = vec![
        0x10, 0x00,
        (total_len >> 8) as u8,
        (total_len & 0xFF) as u8,
    ];
    sstp.extend_from_slice(&ppp);
    sstp
}

    pub fn build_lcp_configure_request() -> Vec<u8> {
        let options = vec![
            0x05, 0x06, 0xC2, 0x23 // CHAP only, no algorithm
        ];

        let mut ppp = vec![
            0xFF, 0x03,
            0xC0, 0x21,
            0x01,             // Code = Configure-Request
            0x01,             // ID
        ];

        let length = (options.len() + 4) as u16;
        ppp.push((length >> 8) as u8);
        ppp.push((length & 0xFF) as u8);
        ppp.extend_from_slice(&options);

        let total_len = ppp.len() + 4;
        let mut sstp = vec![
            0x10, 0x00,
            (total_len >> 8) as u8,
            (total_len & 0xFF) as u8,
        ];
        sstp.extend_from_slice(&ppp);
        sstp
    }


pub fn build_configure_ack_from_request(request: &[u8]) -> Option<Vec<u8>> {
    const SSTP_HEADER_LEN: usize = 4;
    const PPP_HEADER_LEN: usize = 2 + 2; // Address/Control + Protocol
    const PPP_LCP_HEADER_LEN: usize = 4; // Code, ID, Length

    // Если пакет слишком короткий, чтобы быть валидным Configure-Request
    if request.len() < SSTP_HEADER_LEN + PPP_HEADER_LEN + PPP_LCP_HEADER_LEN {
        println!("❌ Слишком короткий SSTP пакет для LCP.");
        return None;
    }

    // Смещаемся на начало пакета PPP (после заголовков SSTP и LCP)
    let ppp_start = SSTP_HEADER_LEN + PPP_HEADER_LEN;

    // Читаем код (должен быть 0x01 для Configure-Request)
    let code = request[ppp_start];
    let id = request[ppp_start + 1];
    let length = u16::from_be_bytes([request[ppp_start + 2], request[ppp_start + 3]]) as usize;

    // Если это не Configure-Request, возвращаем None
    if code != 0x01 {
        println!("⚠️ Это не Configure-Request (code = 0x{:02X})", code);
        return None;
    }

    let expected_total_len = ppp_start + length;
    if request.len() < expected_total_len {
        println!("❌ Пакет не содержит все опции, указанные в Length.");
        return None;
    }

    // Извлекаем параметры (опции) из пакета
    let options = &request[ppp_start + 4..expected_total_len];

    // Строим Configure-Ack с тем же ID и теми же опциями
    let mut ppp = vec![
        0xFF, 0x03,       // Address + Control
        0xC0, 0x21,       // LCP Protocol
        0x02,             // Code = Configure-Ack
        id,               // Используем тот же ID
    ];

    // Добавляем опции
    let ack_length = (options.len() + 4) as u16;
    ppp.push((ack_length >> 8) as u8);  // Длина пакета (старший байт)
    ppp.push((ack_length & 0xFF) as u8);  // Длина пакета (младший байт)
    ppp.extend_from_slice(options);

    // Строим SSTP пакет
    let total_len = ppp.len() + 4;  // Добавляем SSTP заголовок
    let mut sstp = vec![
        0x10, 0x00, // Тип сообщения SSTP (data packet)
        (total_len >> 8) as u8,
        (total_len & 0xFF) as u8,
    ];

    sstp.extend_from_slice(&ppp); // Добавляем сам пакет PPP

    Some(sstp)  // Возвращаем результат
}

pub fn build_configure_nak_from_request(sstp_payload: &[u8]) -> Option<Vec<u8>> {
    const SSTP_HEADER_LEN: usize = 4;
    const PPP_HEADER_LEN: usize = 2 + 2; // Address/Control + Protocol
    const PPP_LCP_HEADER_LEN: usize = 4; // Code, ID, Length

    if sstp_payload.len() < SSTP_HEADER_LEN + PPP_HEADER_LEN + PPP_LCP_HEADER_LEN {
        println!("❌ Слишком короткий SSTP пакет для LCP (Configure-Nak).");
        return None;
    }

    let ppp_start = SSTP_HEADER_LEN + PPP_HEADER_LEN;

    let code = sstp_payload[ppp_start];
    let id = sstp_payload[ppp_start + 1];

    if code != 0x01 {
        println!("⚠️ Это не Configure-Request (ожидался Code 0x01), а 0x{:02X}", code);
        return None;
    }

    // Предлагаем CHAP: Protocol ID = 0xC223, Value = 0x81 (MS-CHAPv2)
    let chap_option: [u8; 5] = [
        0x03,       // Option Type: Authentication Protocol
        0x05,       // Length
        0xC2, 0x23, // CHAP (0xC223)
        0x81        // Algorithm = 0x81 (MS-CHAPv2)
    ];

    let mut ppp = vec![
        0xFF, 0x03,       // Address + Control
        0xC0, 0x21,       // LCP Protocol
        0x03,             // Code = Configure-Nak
        id,               // Используем тот же ID
    ];

    let length = (chap_option.len() + 4) as u16;
    ppp.push((length >> 8) as u8);
    ppp.push((length & 0xFF) as u8);
    ppp.extend_from_slice(&chap_option);

    let total_len = ppp.len() + 4;
    let mut sstp = vec![
        0x10, 0x00,
        (total_len >> 8) as u8,
        (total_len & 0xFF) as u8,
    ];
    sstp.extend_from_slice(&ppp);

    Some(sstp)
}


pub fn is_lcp_configure_request(buf: &[u8]) -> bool {
    buf.len() >= 12 &&
    buf[4] == 0xFF &&
    buf[5] == 0x03 &&
    buf[6] == 0xC0 &&
    buf[7] == 0x21 &&
    buf[8] == 0x01
}

pub fn is_chap_challenge(buf: &[u8]) -> bool {
    buf.len() >= 12 &&
    buf[4] == 0xFF &&
    buf[5] == 0x03 &&
    buf[6] == 0xC2 &&
    buf[7] == 0x23 &&
    buf[8] == 0x01
}

pub fn build_lcp_configure_request_chap_simple() -> Vec<u8> {
    let options = vec![
        0x05, 0x04,       // Option Type = Auth Protocol (0x05), Length = 4
        0xC2, 0x23        // Value = CHAP
    ];

    let mut ppp = vec![
        0xFF, 0x03,
        0xC0, 0x21,
        0x01, // Code = Configure-Request
        0x02, // ID = 2
    ];

    let length = (options.len() + 4) as u16;
    ppp.push((length >> 8) as u8);
    ppp.push((length & 0xFF) as u8);
    ppp.extend_from_slice(&options);

    let total_len = ppp.len() + 4;
    let mut sstp = vec![
        0x10, 0x00,
        (total_len >> 8) as u8,
        (total_len & 0xFF) as u8,
    ];
    sstp.extend_from_slice(&ppp);
    sstp
}


pub fn build_lcp_configure_request_fallback() -> Vec<u8> {

    let options = vec![
        0x05, 0x06, 0xC2, 0x23 // CHAP only, no algorithm
    ];

    let mut ppp = vec![
        0xFF, 0x03,             // Address + Control
        0xC0, 0x21,             // Protocol: LCP
        0x01,                   // Code = Configure-Request
        0x01,                   // Identifier
        0x00, 0x0A              // Length (10 bytes total)
    ];
    ppp.extend_from_slice(&options);

    let total_len = ppp.len() + 4; // SSTP header
    let mut sstp = vec![
        0x10, 0x00,
        (total_len >> 8) as u8,
        (total_len & 0xFF) as u8,
    ];
    sstp.extend_from_slice(&ppp);
    sstp
}

pub fn build_sstp_ppp_lcp_request() -> Vec<u8> {
    let mut buf = Vec::new();

    // ===== SSTP Header =====
    let version: u8 = 0x10; // Version 1.0
    let control_bit: u8 = 0x00; // C = 0 → Data packet
    buf.push(version);
    buf.push(control_bit);

    // Мы пока не знаем длину полностью, вставим временно 0
    buf.extend_from_slice(&[0x00, 0x00]);

    // ===== PPP Frame =====
    buf.push(0xFF); // PPP Address (always 0xFF)
    buf.push(0x03); // PPP Control (always 0x03)
    buf.push(0xC0); // Protocol (0xC021 = LCP)
    buf.push(0x21);

    // LCP Configuration Request
    buf.push(0x01); // Code: Configure-Request
    buf.push(0x01); // Identifier
    buf.extend_from_slice(&[0x00, 0x0C]); // Length = 12 bytes

    // Option: Magic Number
    buf.push(0x05); // Type: Magic Number
    buf.push(0x06); // Length: 6
    buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Value: arbitrary magic

    // Обновляем длину пакета в SSTP заголовке (всего байт)
    let total_len = buf.len() as u16;
    let len_field = (total_len & 0x0FFF) | 0x0000; // R = 0
    buf[2] = (len_field >> 8) as u8;
    buf[3] = (len_field & 0xFF) as u8;

    buf
}

pub fn build_lcp_configure_ack(id: u8, payload: &[u8]) -> Vec<u8> {
    let length = (4 + payload.len()) as u16;
    let mut buf = Vec::new();
    buf.push(0x02); // Code: Configure-Ack
    buf.push(id);   // Identifier
    buf.extend_from_slice(&length.to_be_bytes()); // Length
    buf.extend_from_slice(payload); // Echo back the options exactly
    buf
}

/// Оборачивает LCP payload в PPP + SSTP Data пакет
pub fn wrap_lcp_packet(code: u8, id: u8, payload: &[u8]) -> Vec<u8> {
    let mut ppp = Vec::new();

    // ===== PPP Header =====
    ppp.extend_from_slice(&[0xFF, 0x03]);       // Address + Control
    ppp.extend_from_slice(&[0xC0, 0x21]);       // Protocol: LCP (0xC021)

    // ===== LCP Frame =====
    let lcp_length = (4 + payload.len()) as u16;
    ppp.push(code);                             // LCP Code (e.g., 0x02 = Ack)
    ppp.push(id);                               // Identifier
    ppp.extend_from_slice(&lcp_length.to_be_bytes()); // Length
    ppp.extend_from_slice(payload);             // Options / payload

    // ===== SSTP Header =====
    let total_len = (ppp.len() + 4) as u16;     // PPP + SSTP header
    let mut sstp = Vec::new();
    sstp.push(0x10);                            // SSTP Version 1.0
    sstp.push(0x00);                            // C = 0 (Data)
    sstp.extend_from_slice(&total_len.to_be_bytes()); // Length
    sstp.extend_from_slice(&ppp);               // Вставляем весь PPP-фрейм

    sstp
}

pub fn build_sstp_packet_from_ppp(code: u8, ppp: &PppParsedFrame) -> Vec<u8> {
    let mut ppp_frame = Vec::new();

    // PPP Header
    ppp_frame.extend_from_slice(&[0xFF, 0x03]);           // Address + Control
    ppp_frame.extend_from_slice(&ppp.protocol.to_be_bytes()); // e.g. 0xC021 for LCP

    // LCP или другой PPP фрейм
    let lcp_length = (4 + ppp.payload.len()) as u16;
    ppp_frame.push(code);                     // e.g. 0x02 = Configure-Ack
    ppp_frame.push(ppp.id);                   // тот же ID, что и в запросе
    ppp_frame.extend_from_slice(&lcp_length.to_be_bytes());
    ppp_frame.extend_from_slice(&ppp.payload); // Только опции

    // SSTP Header
    let total_len = (4 + ppp_frame.len()) as u16;
    let mut sstp_packet = Vec::new();
    sstp_packet.push(0x10);                   // Version 1.0
    sstp_packet.push(0x00);                   // C = 0 (Data packet)
    sstp_packet.extend_from_slice(&total_len.to_be_bytes());
    sstp_packet.extend_from_slice(&ppp_frame);

    sstp_packet
}

pub fn build_pap_authenticate_request(id: u8, username: &str, password: &str) -> Vec<u8> {
    let user_bytes = username.as_bytes();
    let pass_bytes = password.as_bytes();

    let total_len = 4 + 1 + user_bytes.len() + 1 + pass_bytes.len();

    let mut buf = Vec::with_capacity(total_len);

    // PAP Header
    buf.push(0x01); // Code: Authenticate-Request
    buf.push(id);   // Identifier
    buf.extend_from_slice(&(total_len as u16).to_be_bytes()); // Length

    // Payload
    buf.push(user_bytes.len() as u8);
    buf.extend_from_slice(user_bytes);

    buf.push(pass_bytes.len() as u8);
    buf.extend_from_slice(pass_bytes);

    buf
}

pub fn wrap_ppp_pap_packet(id: u8, username: &str, password: &str) -> Vec<u8> {
    let pap_payload = build_pap_authenticate_request(id, username, password);

    let mut ppp = Vec::new();
    ppp.extend_from_slice(&[0xFF, 0x03]);           // PPP Header
    ppp.extend_from_slice(&[0xC0, 0x23]);           // Protocol: PAP (0xC023)
    ppp.extend_from_slice(&pap_payload);

    let total_len = (ppp.len() + 4) as u16;

    let mut sstp = Vec::new();
    sstp.push(0x10); // SSTP Version
    sstp.push(0x00); // Data Packet
    sstp.extend_from_slice(&total_len.to_be_bytes());
    sstp.extend_from_slice(&ppp);

    sstp
}

/// Строит SSTP Data пакет с PPP IPCP Configure-Request (IP Address = 0.0.0.0)
pub fn build_ipcp_configure_request_packet(id: u8) -> Vec<u8> {
    let mut ppp = Vec::new();

    // === PPP Header ===
    ppp.extend_from_slice(&[0xFF, 0x03]);       // Address + Control
    ppp.extend_from_slice(&[0x80, 0x21]);       // Protocol = IPCP (0x8021)

    // === IPCP Configure-Request ===
    let payload = [
        0x01,                   // Code = Configure-Request
        id,                    // Identifier
        0x00, 0x0A,             // Length = 10 bytes
        0x03, 0x06,             // Option: IP Address (type=3, len=6)
        0x00, 0x00, 0x00, 0x00,  // IP Address = 0.0.0.0 (мы просим у сервера)
    ];
    ppp.extend_from_slice(&payload);

    // === SSTP Header ===
    let total_len = (ppp.len() + 4) as u16;
    let mut sstp = Vec::new();
    sstp.push(0x10); // Version 1.0
    sstp.push(0x00); // C = 0 (Data)
    sstp.extend_from_slice(&total_len.to_be_bytes());
    sstp.extend_from_slice(&ppp);

    sstp
}

pub fn wrap_ipcp_packet(code: u8, id: u8, options: &[u8]) -> Vec<u8> {
    let mut ppp = Vec::new();

    // PPP Header
    ppp.extend_from_slice(&[0xFF, 0x03, 0x80, 0x21]); // Address + Control + Protocol

    // IPCP Header
    let length = (4 + options.len()) as u16;
    ppp.push(code);
    ppp.push(id);
    ppp.extend_from_slice(&length.to_be_bytes());
    ppp.extend_from_slice(options);

    // SSTP Header
    let total_len = (ppp.len() + 4) as u16;
    let mut sstp = vec![0x10, 0x00];
    sstp.extend_from_slice(&total_len.to_be_bytes());
    sstp.extend_from_slice(&ppp);

    sstp
}

pub fn build_ipcp_configure_ack(id: u8, ip: [u8; 4]) -> Vec<u8> {
    let option = [0x03, 0x06, ip[0], ip[1], ip[2], ip[3]];
    wrap_ipcp_packet(0x02, id, &option)
}

pub fn build_ipcp_configure_reject(id: u8, option: &[u8]) -> Vec<u8> {
    wrap_ipcp_packet(0x04, id, option)
}

pub fn build_ipcp_request_any_ip(id: u8) -> Vec<u8> {
    let options = [
        0x03, 0x06, 0x00, 0x00, 0x00, 0x00, // IP = 0.0.0.0
        0x81, 0x06, 0x00, 0x00, 0x00, 0x00, // DNS = 0.0.0.0
    ];
    wrap_ipcp_packet(0x01, id, &options)
}

pub fn build_ipcp_request_with(ip: [u8; 4], dns: [u8; 4], id: u8) -> Vec<u8> {
    let mut options = vec![
        0x03, 0x06, ip[0], ip[1], ip[2], ip[3],
        0x81, 0x06, dns[0], dns[1], dns[2], dns[3],
    ];
    wrap_ipcp_packet(0x01, id, &options)
}

pub fn build_ipcp_request_with_only_ip(ip: [u8; 4], id: u8) -> Vec<u8> {
    let mut options = vec![
        0x03, 0x06, ip[0], ip[1], ip[2], ip[3]
    ];
    wrap_ipcp_packet(0x01, id, &options)
}

pub async fn read_and_parse<R: AsyncReadExt + Unpin>(
    stream: &mut R,
    buf: &mut [u8],
) -> Option<PppParsedFrame> {
    match stream.read(buf).await {
        Ok(n) if n > 0 => {
            println!("📥 Получено ({} байт): {:02X?}", n, &buf[..n]);
            parse_sstp_data_packet(&buf[..n])
        }
        Ok(_) => {
            println!("⚠️ Сервер закрыл соединение");
            None
        }
        Err(e) => {
            eprintln!("❌ Ошибка чтения: {}", e);
            None
        }
    }
}

pub fn build_sstp_call_connected_packet() -> Vec<u8> {
    vec![
        0x10, 0x02, 0x00, 0x10, // SSTP Header: Version 1.0, Control, Length=16
        0x00, 0x02,             // Message Type: CALL_CONNECTED
        0x00, 0x00,             // Attributes Count = 0
        0x00, 0x00, 0x00, 0x00, // Reserved
        0x00, 0x00, 0x00, 0x00, // Reserved
    ]
}

pub fn extract_all_ipcp_options(payload: &[u8]) -> HashMap<u8, [u8; 4]> {
    let mut options = HashMap::new();
    let mut i = 0;

    while i + 2 <= payload.len() {
        let opt_type = payload[i];
        let len = payload[i + 1] as usize;

        if len < 2 || i + len > payload.len() {
            println!("⚠️ IPCP option повреждена или выходит за границы: type={}, len={}", opt_type, len);
            break;
        }

        if len == 6 {
            options.insert(
                opt_type,
                [
                    payload[i + 2],
                    payload[i + 3],
                    payload[i + 4],
                    payload[i + 5],
                ],
            );
        } else {
            println!("ℹ️ Пропущена опция длиной {}, тип {}", len, opt_type);
        }

        i += len;
    }

    options
}