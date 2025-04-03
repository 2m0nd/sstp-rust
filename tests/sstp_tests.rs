use sstp_rust::sstp::build_lcp_configure_ack;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_build_lcp_configure_ack() {
        let id = 0x01;
        let options = vec![0x03, 0x04, 0xC0, 0x23]; // Auth-Protocol = PAP

        let packet = build_lcp_configure_ack(id, &options);

        // Ожидаемый результат:
        // Code: 0x02 (Ack)
        // ID: 0x01
        // Length: 0x0008 (4 + 4 bytes)
        // Payload: 03 04 C0 23
        let expected = vec![
            0x02,       // Code
            0x01,       // ID
            0x00, 0x08, // Length
            0x03, 0x04, 0xC0, 0x23,
        ];

        assert_eq!(packet, expected, "LCP Configure-Ack packet doesn't match expected");
    }
}