use uuid::Uuid;

pub fn build_sstp_hello() -> Vec<u8> {
    let mut packet: Vec<u8> = Vec::new();

    // === SSTP Control Header ===
    let version = 0x10u8; // Version 1.0
    let c_type = 0x01u8;  // Control packet
    packet.push(version);
    packet.push(c_type);

    // Мы пока не знаем точную длину, временно 0x0000, позже запишем правильно
    packet.extend_from_slice(&[0x00, 0x00]);

    // === AVP: SSTP Version (0x01) ===
    // Attribute ID: 0x01, Mandatory (1 << 15)
    let attr_type = 0x8001u16;
    let attr_len = 8u16;
    packet.extend_from_slice(&attr_type.to_be_bytes());
    packet.extend_from_slice(&attr_len.to_be_bytes());
    packet.extend_from_slice(&[0x01, 0x00]); // Version 1.0

    // === AVP: Client’s GUID (0x02) ===
    let guid = Uuid::new_v4(); // или можно зашить свой
    let attr_type = 0x8002u16;
    let attr_len = 20u16;
    packet.extend_from_slice(&attr_type.to_be_bytes());
    packet.extend_from_slice(&attr_len.to_be_bytes());
    packet.extend_from_slice(guid.as_bytes());

    // === AVP: Encapsulation Protocols (0x03) ===
    // Значение: 0x00000001 (1 = PPP)
    let attr_type = 0x8003u16;
    let attr_len = 8u16;
    let encapsulation = 1u32;
    packet.extend_from_slice(&attr_type.to_be_bytes());
    packet.extend_from_slice(&attr_len.to_be_bytes());
    packet.extend_from_slice(&encapsulation.to_be_bytes());

    // === Update packet length ===
    let total_len = packet.len() as u16;
    packet[2] = (total_len >> 8) as u8;
    packet[3] = (total_len & 0xFF) as u8;

    packet
}