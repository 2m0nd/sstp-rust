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
    // Проверка минимальной длины: 4 байта SSTP + 6 PPP (без опций)
    if sstp_payload.len() < 12 {
        println!("❌ Слишком короткий SSTP пакет для LCP.");
        return None;
    }

    // Пропускаем 4 байта SSTP + 2 (Addr/Control) + 2 (Protocol)
    let code = sstp_payload[8];
    let id = sstp_payload[9];
    let length = u16::from_be_bytes([sstp_payload[10], sstp_payload[11]]) as usize;

    if code != 0x01 {
        println!("⚠️ Это не Configure-Request (code = 0x{:02X})", code);
        return None;
    }

    if sstp_payload.len() < 12 + (length - 6) {
        println!("❌ Пакет не содержит все опции, указанные в Length.");
        return None;
    }

    let options = &sstp_payload[12..12 + (length - 6)];

    println!("🧩 Отвечаем Configure-Ack с ID = {}, опций = {} байт", id, options.len());

    Some(build_configure_ack(id, options))
}

pub fn build_lcp_configure_request() -> Vec<u8> {
    let ppp_lcp = vec![
        0xC0, 0x21, // PPP Protocol = LCP (0xC021)
        0x01,       // Code = Configure-Request
        0x01,       // Identifier
        0x00, 0x04  // Length = 4 (заголовок без опций)
    ];

    let length = ppp_lcp.len() + 4;
    let mut sstp_data = vec![
        0x10, 0x00,                     // Version 1.0, Data Packet (Control bit = 0)
        (length >> 8) as u8, (length & 0xFF) as u8, // Length
    ];
    sstp_data.extend_from_slice(&ppp_lcp);
    sstp_data
}

pub fn build_configure_ack(reply_id: u8, options: &[u8]) -> Vec<u8> {
    let mut ppp = vec![
        0xFF, 0x03,       // PPP Address + Control
        0xC0, 0x21,       // Protocol = LCP
        0x02,             // Code = Configure-Ack
        reply_id,         // ID = такой же, как в запросе
    ];

    let length = (options.len() + 4) as u16;
    ppp.push((length >> 8) as u8);
    ppp.push((length & 0xFF) as u8);
    ppp.extend_from_slice(options);

    // SSTP Data Packet обёртка
    let total_len = ppp.len() + 4;
    let mut sstp = vec![
        0x10, 0x00,
        (total_len >> 8) as u8,
        (total_len & 0xFF) as u8,
    ];
    sstp.extend_from_slice(&ppp);
    sstp
}