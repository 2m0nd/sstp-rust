use rand::Rng;
use std::collections::HashMap;

pub fn parse_dhcp_ack_from_ip_payload(payload: &[u8]) -> Option<HashMap<u8, Vec<u8>>> {
    let ip_header_len = (payload[0] & 0x0F) as usize * 4;
    
    //println!("IP header len: {}", ip_header_len);

    if payload.len() < ip_header_len + 8 {
        println!("❌ Too short for UDP header");
        return None;
    }

    let udp_payload_offset = ip_header_len + 8;
    let udp_payload = &payload[udp_payload_offset..];

    let magic_cookie = [0x63, 0x82, 0x53, 0x63];
    let cookie_pos = udp_payload.windows(4).position(|win| win == magic_cookie)?;

    //println!("Magic cookie found at offset {}", cookie_pos);

    let mut options = HashMap::new();
    let mut i = cookie_pos + 4;

    while i + 2 <= udp_payload.len() {
        let opt_type = udp_payload[i];
        if opt_type == 0xFF {
            break;
        }

        let opt_len = *udp_payload.get(i + 1)? as usize;
        if i + 2 + opt_len > udp_payload.len() {
            println!("❌ Option length out of bounds: type={}, len={}", opt_type, opt_len);
            break;
        }

        let data = udp_payload[i + 2..i + 2 + opt_len].to_vec();
        options.insert(opt_type, data);
        i += 2 + opt_len;
    }

    Some(options)
}




pub fn build_dhcp_inform_ppp_packet(client_ip: [u8; 4]) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let xid = rng.gen::<u32>();

    // --- DHCP payload ---
    let mut dhcp = vec![];
    dhcp.push(0x01); // op = BOOTREQUEST
    dhcp.push(0x01); // htype = Ethernet
    dhcp.push(0x06); // hlen = 6
    dhcp.push(0x00); // hops
    dhcp.extend_from_slice(&xid.to_be_bytes()); // xid
    dhcp.extend_from_slice(&[0x00, 0x00]); // secs
    dhcp.extend_from_slice(&[0x80, 0x00]); // flags (broadcast)

    dhcp.extend_from_slice(&client_ip); // ciaddr
    dhcp.extend_from_slice(&[0; 4]); // yiaddr
    dhcp.extend_from_slice(&[0; 4]); // siaddr
    dhcp.extend_from_slice(&[0; 4]); // giaddr

    dhcp.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // chaddr (MAC)
    dhcp.extend_from_slice(&[0; 10]); // padding to 16 bytes

    dhcp.extend_from_slice(&[0; 64]); // sname
    dhcp.extend_from_slice(&[0; 128]); // file

    dhcp.extend_from_slice(&[99, 130, 83, 99]); // magic cookie

    // DHCP options
    dhcp.extend_from_slice(&[53, 1, 0x08]); // DHCP Message Type = INFORM
    dhcp.extend_from_slice(&[55, 3, 1, 3, 6]); // Parameter Request List: Subnet Mask, Router, DNS
    dhcp.push(255); // end

    // Pad to min size (300 bytes)
    while dhcp.len() < 300 {
        dhcp.push(0x00);
    }

    // --- UDP Header ---
    let src_port = 68u16;
    let dst_port = 67u16;
    let udp_len = (8 + dhcp.len()) as u16;

    let mut udp = vec![];
    udp.extend_from_slice(&src_port.to_be_bytes());
    udp.extend_from_slice(&dst_port.to_be_bytes());
    udp.extend_from_slice(&udp_len.to_be_bytes());
    udp.extend_from_slice(&[0x00, 0x00]); // checksum (ignored)
    udp.extend_from_slice(&dhcp);

    // --- IP Header ---
    let total_len = (20 + udp.len()) as u16;
    let mut ip = vec![
        0x45, 0x00,
        (total_len >> 8) as u8, total_len as u8,
        0x00, 0x00, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00, // TTL + UDP + checksum
        client_ip[0], client_ip[1], client_ip[2], client_ip[3],
        255, 255, 255, 255,
    ];
    ip.extend_from_slice(&udp);

    // --- PPP + IP ---
    let mut ppp = vec![0xFF, 0x03, 0x00, 0x21]; // PPP for IP
    ppp.extend_from_slice(&ip);

    // --- SSTP Wrapper ---
    let total_len = (ppp.len() + 4) as u16;
    let mut sstp = vec![0x10, 0x00];
    sstp.extend_from_slice(&total_len.to_be_bytes());
    sstp.extend_from_slice(&ppp);

    sstp
}
