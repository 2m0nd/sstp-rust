use rand::Rng;
use std::net::Ipv4Addr;

pub struct DhcpAckInfo {
    pub dns: [u8; 4],
    pub gateway: [u8; 4],
    pub subnet_mask: [u8; 4],
}

pub fn build_dhcp_inform_packet(
    client_ip: [u8; 4]) -> Vec<u8> {
        let mut packet = Vec::new();

        // PPP header
        packet.extend_from_slice(&[0xFF, 0x03]);           // Address, Control
        packet.extend_from_slice(&[0x00, 0x21]);           // Protocol: IPv4 (0x0021)
    
        // IPv4 header
        packet.extend_from_slice(&[
            0x45,                   // Version + IHL
            0x00,                   // DSCP/ECN
            0x01, 0x14,             // Total Length = 276 (DHCP packet + headers)
            0x00, 0x00,             // Identification
            0x00, 0x00,             // Flags + Fragment offset
            0x80,                   // TTL
            0x11,                   // Protocol: UDP
            0x00, 0x00,             // Header checksum (we'll skip real calculation)
            client_ip[0], client_ip[1], client_ip[2], client_ip[3], // Source IP
            255, 255, 255, 255      // Dest IP (broadcast)
        ]);
    
        // UDP header
        let src_port = 68u16.to_be_bytes(); // BOOTP client
        let dst_port = 67u16.to_be_bytes(); // BOOTP server
        let udp_len = 276u16.to_be_bytes(); // UDP length (header + data)
    
        packet.extend_from_slice(&src_port);
        packet.extend_from_slice(&dst_port);
        packet.extend_from_slice(&udp_len);
        packet.extend_from_slice(&[0x00, 0x00]); // checksum = 0 (skip)
    
        // DHCP payload
        let mut dhcp = Vec::new();
        dhcp.push(0x01);                     // op: BOOTREQUEST
        dhcp.push(0x01);                     // htype: Ethernet
        dhcp.push(0x06);                     // hlen: MAC length
        dhcp.push(0x00);                     // hops
        let xid: u32 = rand::thread_rng().gen(); // random transaction ID
        dhcp.extend_from_slice(&xid.to_be_bytes()); // xid
        dhcp.extend_from_slice(&[0x00, 0x00]); // secs
        dhcp.extend_from_slice(&[0x80, 0x00]); // flags: broadcast
        dhcp.extend_from_slice(&client_ip);   // ciaddr (client IP from IPCP)
        dhcp.extend_from_slice(&[0; 4 * 3]);  // yiaddr, siaddr, giaddr
        dhcp.extend_from_slice(&[0xCA, 0x54, 0xDC, 0x54, 0x01, 0xA0]); // chaddr (MAC addr placeholder)
        dhcp.extend_from_slice(&[0; 10]);     // padding chaddr
        dhcp.extend_from_slice(&[0; 192]);    // bootp legacy zeros
        dhcp.extend_from_slice(&[99, 130, 83, 99]); // magic cookie
    
        // DHCP options
        dhcp.extend_from_slice(&[53, 1, 8]);       // Option 53: DHCP INFORM
        dhcp.extend_from_slice(&[55, 2, 3, 6]);    // Option 55: Parameter Request List: Router, DNS
        dhcp.extend_from_slice(&[255]);           // End option
    
        packet.extend_from_slice(&dhcp);
        packet
}

fn build_udp_packet(
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    _src_ip: Ipv4Addr,
    _dst_ip: Ipv4Addr,
) -> Vec<u8> {
    let len = 8 + payload.len();
    let mut pkt = Vec::with_capacity(len);
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&(len as u16).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(payload);
    pkt
}

fn build_ipv4_packet(payload: &[u8], src: Ipv4Addr, dst: Ipv4Addr, proto: u8) -> Vec<u8> {
    let total_len = 20 + payload.len();
    let mut pkt = Vec::with_capacity(total_len);

    pkt.extend_from_slice(&[
        0x45, 0x00,
        (total_len >> 8) as u8,
        (total_len & 0xFF) as u8,
        0x00, 0x00,
        0x00, 0x00,
        0x80,
        proto,
        0x00, 0x00,
    ]);
    pkt.extend_from_slice(&src.octets());
    pkt.extend_from_slice(&dst.octets());

    let checksum = ipv4_checksum(&pkt);
    pkt[10] = (checksum >> 8) as u8;
    pkt[11] = (checksum & 0xFF) as u8;

    pkt.extend_from_slice(payload);
    pkt
}

fn ipv4_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for i in (0..data.len()).step_by(2) {
        let word = u16::from_be_bytes([data[i], data[i + 1]]);
        sum = sum.wrapping_add(word as u32);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn build_ppp_packet(ip_payload: &[u8]) -> Vec<u8> {
    let mut ppp = vec![0xFF, 0x03, 0x00, 0x21];
    ppp.extend_from_slice(ip_payload);
    ppp
}

pub fn try_parse_dhcp_ack(packet: &[u8]) -> Option<DhcpAckInfo> {
    if packet.len() < 240 { return None; }
    let cookie = &packet[236..240];
    if cookie != &[99, 130, 83, 99] {
        return None;
    }

    let mut dns = [0, 0, 0, 0];
    let mut gateway = [0, 0, 0, 0];
    let mut subnet = [0, 0, 0, 0];

    let mut i = 240;
    while i < packet.len() {
        let opt = packet[i];
        if opt == 255 { break; }
        if i + 1 >= packet.len() { break; }
        let len = packet[i + 1] as usize;
        if i + 2 + len > packet.len() { break; }

        let data = &packet[i + 2..i + 2 + len];

        match opt {
            1 if len >= 4 => subnet.copy_from_slice(&data[0..4]),
            3 if len >= 4 => gateway.copy_from_slice(&data[0..4]),
            6 if len >= 4 => dns.copy_from_slice(&data[0..4]),
            _ => {}
        }

        i += 2 + len;
    }

    Some(DhcpAckInfo { dns, gateway, subnet_mask: subnet })
}