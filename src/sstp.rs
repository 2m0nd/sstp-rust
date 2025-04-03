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

    // let corr_bytes = correlation_id.as_bytes(); // 16 байт UUID
    
    // let mut hello = vec![
    //         0x10, 0x01,       // Version + Control
    //         0x00, 0x20,       // Length = 32 → заменим позже
    //         0x00, 0x01,       // Message Type = Call Connect Request
    //         0x00, 0x02,       // Attribute Count = 2
    //     ];

    //     // AVP 1: Encapsulated Protocol
    //     hello.extend_from_slice(&[0x01, 0x00, 0x00, 0x06, 0x00, 0x01]);

    //     // AVP 2: SSTPCorrelationID
    //     hello.push(0x08);              // Attr ID
    //     hello.push(0x00);              // Reserved
    //     hello.extend_from_slice(&[0x00, 0x16]); // Length = 22
    //     hello.extend_from_slice(corr_bytes);    // 16 байт UUID

    //     // Обновим поле длины
    //     let len = hello.len();
    //     hello[2] = ((len >> 8) & 0xFF) as u8;
    //     hello[3] = (len & 0xFF) as u8;

    //     println!("📦 Hello с SSTPCorrelationID, длина: {} байт", len);
    //     hello
}

