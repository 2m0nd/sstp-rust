use uuid::Uuid;

pub fn build_sstp_hello() -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0x10);
    packet.push(0x01);
    packet.extend_from_slice(&[0x00, 0x0E]); // length = 14 bytes
    packet.extend_from_slice(&[0x00, 0x01]); // message type = Call Connect Request
    packet.extend_from_slice(&[0x00, 0x01]); // num attributes = 1
    packet.push(0x00);
    packet.push(0x01);
    packet.extend_from_slice(&[0x00, 0x06]);
    packet.extend_from_slice(&[0x00, 0x01]); // Encapsulation = PPP
    packet
}

