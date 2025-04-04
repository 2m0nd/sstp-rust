use sstp_rust::sstp::*;
use sstp_rust::dhcp::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_wrap_lcp_packet() {
        let payload = [0x03, 0x04, 0xC0, 0x23]; // LCP Option: Auth Protocol = PAP
        let packet = wrap_lcp_packet(0x02, 0x01, &payload); // Configure-Ack, ID = 1

        // Ожидаемая структура:
        // SSTP Header (4 bytes): 0x10, 0x00, 0x00, 0x14 (len=20)
        // PPP Header: 0xFF, 0x03, 0xC0, 0x21
        // LCP Header: 0x02, 0x01, 0x00, 0x08
        // Payload: 0x03, 0x04, 0xC0, 0x23

        let expected = vec![
            0x10, 0x00, 0x00, 0x10, // SSTP Header
            0xFF, 0x03, 0xC0, 0x21, // PPP
            0x02, 0x01, 0x00, 0x08, // LCP: Configure-Ack, ID=1, Length=8
            0x03, 0x04, 0xC0, 0x23, // Option: PAP
        ];

        assert_eq!(packet, expected, "LCP packet not wrapped correctly into SSTP");
    }

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

    #[test]
    fn test_ack_generation_from_parsed_ppp() {
        // Входящий SSTP Data пакет, содержащий PPP LCP Configure-Request с PAP
        let incoming: [u8; 16] = [
            0x10, 0x00, 0x00, 0x10,       // SSTP Header (16 байт)
            0xFF, 0x03, 0xC0, 0x21,       // PPP Header (LCP)
            0x01, 0x00, 0x00, 0x08,       // LCP: Code = Configure-Request, ID = 0, Len = 8
            0x03, 0x04, 0xC0, 0x23        // Option: Auth-Protocol = PAP
        ];

        // Используем тот же парсер, что и в основном коде
        if let Some(ppp) = parse_sstp_data_packet(&incoming) {
            assert_eq!(ppp.code, 0x01, "Ожидался Configure-Request");
            
            let ack_packet = build_sstp_packet_from_ppp(0x02, &ppp); // Configure-Ack
            // Ожидаемый пакет
            let expected = vec![
                0x10, 0x00, 0x00, 0x10,       // SSTP Header: len = 16
                0xFF, 0x03, 0xC0, 0x21,       // PPP
                0x02, 0x00, 0x00, 0x08,       // LCP Configure-Ack
                0x03, 0x04, 0xC0, 0x23        // Опция PAP
            ];
            
            assert_eq!(ack_packet, expected, "❌ ACK не совпадает с ожидаемым");  
        }
        else {
            panic!("❌ parse_sstp_data_packet вернул None");
        }
    }

    #[test]
    pub fn test_remove_rejected_ipcp_options() {
        // Содержит 3 опции:
        // - 0x83 (тип, длина 6, данные 0.0.0.0)
        // - 0x03 (тип, длина 6, данные 0.0.0.0)
        // - 0x81 (тип, длина 6, данные 0.0.0.0)
        let source_payload = vec![
            0x83, 0x06, 0x00, 0x00, 0x00, 0x00, // option 131
            0x03, 0x06, 0x00, 0x00, 0x00, 0x00, // option 3
            0x81, 0x06, 0x00, 0x00, 0x00, 0x00, // option 129
        ];
        
        // Скажем, что сервер отверг опцию 131 (0x83)
        let rejected = vec![0x83];

        let expected_filtered = vec![
            0x03, 0x06, 0x00, 0x00, 0x00, 0x00, // option 3
            0x81, 0x06, 0x00, 0x00, 0x00, 0x00, // option 129
        ];

        let actual = remove_rejected_ipcp_options(&source_payload, &rejected);

        assert_eq!(actual, expected_filtered, "Фильтрация IPCP опций работает неверно");
    }

    #[test]
    pub fn test_parse_dhcp_ack() {
        let data: Vec<u8> = vec![
            0x54, 0x5F, 0x00, 0x00, 0x80, 0x11, 0x27, 0xE9, 0xC0, 0xA8, 0x1E, 0x01, 0xC0, 0xA8, 0x1E, 0x0B,
            0x00, 0x43, 0x00, 0x44, 0x01, 0x34, 0xF3, 0x15, 0x02, 0x01, 0x06, 0x00, 0xCD, 0x80, 0x31, 0x06,
            // [... snip middle ...]
            0x63, 0x82, 0x53, 0x63, // Magic cookie
            0x35, 0x01, 0x05,       // Option 53 = 05 (ACK)
            0x36, 0x04, 0xC0, 0xA8, 0x1E, 0x01, // Option 54 = 192.168.30.1
            0x01, 0x04, 0xFF, 0xFF, 0xFF, 0x00, // Subnet mask = 255.255.255.0
            0x03, 0x04, 0xC0, 0xA8, 0x1E, 0x01, // Router = 192.168.30.1
            0x06, 0x04, 0xC0, 0xA8, 0x1E, 0x01, // DNS = 192.168.30.1
            0xFF, // End option
        ];

        let result = 
        parse_dhcp_ack_from_ip_payload(&data).expect("should parse successfully");

        assert_eq!(result.get(&53), Some(&vec![0x05])); // DHCP Ack
        assert_eq!(result.get(&54), Some(&vec![0xC0, 0xA8, 0x1E, 0x01])); // DHCP server
        assert_eq!(result.get(&1), Some(&vec![0xFF, 0xFF, 0xFF, 0x00])); // Subnet
        assert_eq!(result.get(&3), Some(&vec![0xC0, 0xA8, 0x1E, 0x01])); // Router
        assert_eq!(result.get(&6), Some(&vec![0xC0, 0xA8, 0x1E, 0x01])); // DNS
    }


}