use rand::Rng;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use uuid::Uuid;
use crate::parser::parse_ppp_frame;
use crate::parser::PppParsedFrame;
use std::collections::HashMap;
use std::collections::VecDeque;
use tokio::{net::TcpStream};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::{
    Certificate, ClientConfig, Error as TLSError, ServerName,
    client::ServerCertVerifier,
    client::ServerCertVerified,
};
use tokio::{io::{ split, ReadHalf, WriteHalf}};
use tun::{platform::Device as Tun};
use tokio_rustls::client::TlsStream;


pub async fn read_and_parse_all<R: AsyncRead + Unpin>(
    stream: &mut R,
    leftover: &mut Vec<u8>,
    queue: &mut VecDeque<PppParsedFrame>,
) -> std::io::Result<()> {
    use tokio::io::AsyncReadExt;

    // 🧪 Обрабатываем то, что осталось
    if !leftover.is_empty() {
        let packets = extract_ppp_from_sstp_stream(leftover);
        if packets.is_empty() {
            println!("📭 Нет распарсенных PPP пакетов (в leftover)");
        }
        queue.extend(packets);
    }

    // 💤 Если очередь пуста — читаем из стрима
    if queue.is_empty() {
        let mut buf = [0u8; 1600];
        let n = stream.read(&mut buf).await?;

        //println!("🔍 Получено {} байт из stream", n);
        //println!("🔍 Буфер: {:02X?}", &buf[..n]);

        if n == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "SSTP закрылся"));
        }

        leftover.extend_from_slice(&buf[..n]);

        let packets = extract_ppp_from_sstp_stream(leftover);
        if packets.is_empty() {
            println!("📭 Нет распарсенных PPP пакетов (из read)");
        }
        queue.extend(packets);
    }

    Ok(())
}


pub fn take_matching_packet<F>(
    queue: &mut VecDeque<PppParsedFrame>,
    matcher: F,
) -> Option<PppParsedFrame>
where
    F: Fn(&PppParsedFrame) -> bool,
{
    let index = queue.iter().position(|p| matcher(p))?;
    Some(queue.remove(index).unwrap())
}

/// Делит leftover на SSTP фреймы и вытаскивает PPP пакеты
fn extract_ppp_from_sstp_stream(leftover: &mut Vec<u8>) -> Vec<PppParsedFrame> {
    let mut parsed = Vec::new();
    let mut offset = 0;

    while offset + 4 <= leftover.len() {
        if leftover[offset] != 0x10 {
            println!("⚠️ Не SSTP фрейм по offset={}", offset);
            break;
        }

        let total_len = u16::from_be_bytes([leftover[offset + 2], leftover[offset + 3]]) as usize;
        if offset + total_len > leftover.len() {
            break; // фрейм неполный, ждём
        }

        let sstp_frame = &leftover[offset..offset + total_len];
        if let Some(ppp) = parse_ppp_frame(sstp_frame) {
            parsed.push(ppp);
        }

        offset += total_len;
    }

    // Убираем обработанную часть из leftover
    leftover.drain(0..offset);
    parsed
}


fn parse_all_ppp_packets(buf: &mut Vec<u8>) -> Vec<PppParsedFrame> {
    let mut packets = Vec::new();
    let mut i = 0;

    while i + 4 <= buf.len() {
        if buf[i] != 0x10 || buf[i + 1] != 0x00 {
            i += 1;
            continue;
        }

        let total_len = u16::from_be_bytes([buf[i + 2], buf[i + 3]]) as usize;
        if i + total_len > buf.len() {
            break; // ждём больше данных
        }

        let payload = &buf[i + 4..i + total_len];
        if let Some(ppp) = parse_ppp_frame(payload) {
            packets.push(ppp);
        }

        i += total_len;
    }

    buf.drain(..i); // убираем использованное
    packets
}


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

pub fn build_sstp_echo_response() -> Vec<u8> {
    vec![
        0x10, 0x01,             // SSTP v1.0, Control packet
        0x00, 0x08,             // Length = 8
        0x00, 0x06,             // Message Type = 0x0006 (ECHO_RESPONSE)
        0x00, 0x00              // Attribute length = 0
    ]
}

pub async fn read_and_parse<R: AsyncReadExt + Unpin>(
    stream: &mut R,
    buf: &mut [u8],
) -> Option<PppParsedFrame> {
    match stream.read(buf).await {
        Ok(n) if n > 0 => {
            // ({} байт): {:02X?}", n, &buf[..n]);
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

pub fn wrap_ip_in_ppp_sstp(ip_data: &[u8]) -> Vec<u8> {
    let n = ip_data.len();
    println!("SEND:\tWrite to SSTP: ({} байт): {:02X?}", n, &ip_data[..n]);

    let mut ppp = vec![
        0xFF, 0x03, // Address + Control
        0x00, 0x21, // Protocol = IP
    ];
    ppp.extend_from_slice(ip_data);

    let total_len = (ppp.len() + 4) as u16;
    let mut sstp = vec![
        0x10, 0x00, // SSTP v1, C = 0 (Data)
        (total_len >> 8) as u8,
        (total_len & 0xFF) as u8,
    ];
    sstp.extend_from_slice(&ppp);
    sstp
}

pub fn parse_ppp_ip_packet(buf: &[u8]) -> Option<&[u8]> {
    let n = buf.len();
    //println!("[SSTP->>TUN] ({} байт): {:02X?}", n, &buf[..n]);

    if buf.len() < 8 {
        return None;
    }

    if buf[4] == 0xFF && buf[5] == 0x03 &&
       buf[6] == 0x00 && buf[7] == 0x21 {
        // Это PPP + IP
        Some(&buf[8..])
    } else {
        None
    }
}
pub fn extract_all_lcp_option_types(payload: &[u8]) -> Vec<u8> {
    let mut i = 0;
    let mut types = Vec::new();
    while i + 2 <= payload.len() {
        let opt_type = payload[i];
        let opt_len = payload[i + 1] as usize;

        if opt_len < 2 || i + opt_len > payload.len() {
            break;
        }

        types.push(opt_type);
        i += opt_len;
    }
    types
}
pub fn build_lcp_configure_request_filtered(id: u8, reject_list: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();

    // Option 1: MRU
    if !reject_list.contains(&0x01) {
        payload.extend_from_slice(&[0x01, 0x04, 0x05, 0xDC]); // 1500
    }

    // Option 5: Magic Number
    if !reject_list.contains(&0x05) {
        payload.extend_from_slice(&[0x05, 0x04, 0x7B, 0xA7]); // any 2 bytes
    }

    // Option 7 and 8 — часто отвергаются, можно не включать
    // Option 3: Authentication Protocol
    if !reject_list.contains(&0x03) {
        payload.extend_from_slice(&[0x03, 0x04, 0xC0, 0x23]); // PAP
    }

    wrap_lcp_packet(0x01, id, &payload)
}


pub fn remove_rejected_lcp_options(payload: &[u8], rejected: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    let mut i = 0;

    while i + 2 <= payload.len() {
        let typ = payload[i];
        let len = payload[i + 1] as usize;

        if len < 2 || i + len > payload.len() {
            break;
        }

        if !rejected.contains(&typ) {
            result.extend_from_slice(&payload[i..i + len]);
        }

        i += len;
    }

    result
}

/// Собирает LCP Configure-Request + возвращает отдельно options
pub fn build_sstp_ppp_lcp_request_with_options(id: u8) -> (Vec<u8>, Vec<u8>) {
    let mut opts = Vec::new();
    let mut rng = rand::thread_rng();
    let magic = rng.gen::<u32>().to_be_bytes();
    opts.push(0x07); opts.push(2);              // ACCM (пустая)
    opts.push(0x05); opts.push(6); opts.extend_from_slice(&magic);
    opts.push(0x08); opts.push(2);              // Auth callback
    opts.push(0x01); opts.push(4); opts.extend_from_slice(&[0x0F, 0xFB]);

    // === Сборка PPP + LCP ===
    let lcp_len = (4 + opts.len()) as u16;

    let mut ppp = Vec::new();
    ppp.extend_from_slice(&[0xFF, 0x03]); // PPP Address/Control
    ppp.extend_from_slice(&[0xC0, 0x21]); // PPP Protocol: LCP

    ppp.push(0x01);             // LCP Code: Configure-Request
    ppp.push(id);               // Identifier
    ppp.extend_from_slice(&lcp_len.to_be_bytes());
    ppp.extend_from_slice(&opts);

    // === SSTP Header ===
    let total_len = (ppp.len() + 4) as u16;

    let mut sstp = Vec::new();
    sstp.push(0x10); // SSTP Version
    sstp.push(0x00); // C = 0
    sstp.extend_from_slice(&total_len.to_be_bytes());
    sstp.extend_from_slice(&ppp);

    (sstp, opts)
}

pub fn build_lcp_configure_request_filtered_with_mru(
    id: u8,
    mru: [u8; 2],
) -> (Vec<u8>, Vec<u8>) {
    let mut options = Vec::new();

    // Option 1: MRU
    options.extend_from_slice(&[0x01, 0x04, mru[0], mru[1]]);

    let payload = options.clone(); // сохраняем до упаковки

    let packet = wrap_lcp_packet(0x01, id, &options); // 0x01 = Configure-Request

    (packet, payload)
}

