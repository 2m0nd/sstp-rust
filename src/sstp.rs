use uuid::Uuid;

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

pub fn parse_sstp_data_packet(buf: &[u8]) {
    if buf.len() < 6 {
        println!("⚠️ Слишком короткий пакет, не похоже на SSTP Data.");
        return;
    }

    let is_control = buf[1] & 0x01 != 0;
    if buf[0] != 0x10 || is_control {
        println!("⚠️ Это не SSTP Data Packet.");
        return;
    }

    let total_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    println!("📦 SSTP Data Packet: длина = {}", total_len);

    // PPP начинается с offset 4
    if buf.len() < 10 {
        println!("⚠️ Недостаточно данных для PPP.");
        return;
    }

    // Skip Address (0xFF) + Control (0x03)
    let ppp_protocol = u16::from_be_bytes([buf[6], buf[7]]);
    match ppp_protocol {
        0xC021 => println!("🔗 PPP Protocol: LCP (0xC021)"),
        0xC223 => println!("🔐 PPP Protocol: CHAP (0xC223)"),
        0x8021 => println!("🌐 PPP Protocol: IPCP (0x8021)"),
        other => println!("❓ Неизвестный PPP Protocol: 0x{:04X}", other),
    }

    if buf.len() >= 12 {
        let code = buf[8];
        let id = buf[9];
        let len = u16::from_be_bytes([buf[10], buf[11]]);

        let code_str = match code {
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
            code, code_str, id, len
        );
    }
}

pub fn build_configure_ack_from_request(sstp_payload: &[u8]) -> Option<Vec<u8>> {
    const SSTP_HEADER_LEN: usize = 4;
    const PPP_HEADER_LEN: usize = 2 + 2; // Addr/Control + Protocol
    const PPP_LCP_HEADER_LEN: usize = 4; // Code, ID, Length

    if sstp_payload.len() < SSTP_HEADER_LEN + PPP_HEADER_LEN + PPP_LCP_HEADER_LEN {
        println!("❌ Слишком короткий SSTP пакет для LCP.");
        return None;
    }

    let ppp_start = SSTP_HEADER_LEN + PPP_HEADER_LEN;

    let code = sstp_payload[ppp_start];
    let id = sstp_payload[ppp_start + 1];
    let length = u16::from_be_bytes([
        sstp_payload[ppp_start + 2],
        sstp_payload[ppp_start + 3],
    ]) as usize;

    if code != 0x01 {
        println!("⚠️ Это не Configure-Request (code = 0x{:02X})", code);
        return None;
    }

    let expected_total_len = ppp_start + length;
    if sstp_payload.len() < expected_total_len {
        println!("❌ Пакет не содержит все опции, указанные в Length.");
        return None;
    }

    let options = &sstp_payload[ppp_start + 4..expected_total_len];

    println!("📥 Оригинальный Configure-Request ({} байт): {:02X?}", length, &sstp_payload[ppp_start..ppp_start + length]);
    let ack = build_configure_ack(id, options);
    println!("📤 Сформированный Configure-Ack ({} байт): {:02X?}", ack.len(), &ack);
    Some(ack)
}

pub fn build_configure_ack(reply_id: u8, options: &[u8]) -> Vec<u8> {
    let mut ppp = vec![
        0xFF, 0x03,       // Address + Control
        0xC0, 0x21,       // LCP Protocol
        0x02,             // Code = Configure-Ack
        reply_id,
    ];

    let length = (options.len() + 4) as u16; // Code + ID + Length (4)
    ppp.push((length >> 8) as u8);
    ppp.push((length & 0xFF) as u8);
    ppp.extend_from_slice(options);

    // SSTP заголовок
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
        0x03, 0x04, 0xC0, 0x23,             // Magic Number
        0x05, 0x06, 0xC2, 0x23              // Auth Protocol: CHAP (0xC223)
    ];

    let mut ppp = vec![
        0xFF, 0x03,
        0xC0, 0x21,
        0x01,  // Code = Configure-Request
        0x01,  // ID
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


pub fn is_lcp_configure_request(buf: &[u8]) -> bool {
    buf.len() >= 12 &&
    buf[4] == 0xFF &&
    buf[5] == 0x03 &&
    buf[6] == 0xC0 &&
    buf[7] == 0x21 &&
    buf[8] == 0x01 // Code = Configure-Request
}

pub fn is_chap_challenge(buf: &[u8]) -> bool {
    buf.len() >= 12 &&
    buf[4] == 0xFF &&
    buf[5] == 0x03 &&
    buf[6] == 0xC2 &&
    buf[7] == 0x23 &&
    buf[8] == 0x01 // Code = Challenge
}