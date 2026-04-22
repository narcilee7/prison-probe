use anyhow::{Context, Result};
use rand::Rng;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

/// 默认公共 STUN 服务器列表
pub const DEFAULT_STUN_SERVERS: &[(&str, u16)] = &[
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
    ("stun2.l.google.com", 19302),
];

/// 向 STUN 服务器发送 Binding Request 并解析响应中的公网映射地址
pub async fn query_stun_server(host: &str, port: u16, timeout: Duration) -> Result<IpAddr> {
    let addrs: Vec<_> = tokio::net::lookup_host(format!("{}:{}", host, port))
        .await
        .context("STUN 服务器 DNS 解析失败")?
        .collect();

    let addr = addrs.into_iter().next().context("STUN 服务器无可用地址")?;

    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
        .await
        .context("绑定 UDP socket 失败")?;

    // 构造 STUN Binding Request
    let mut tx_id = [0u8; 12];
    rand::thread_rng().fill(&mut tx_id);

    let mut request = Vec::with_capacity(20);
    request.extend_from_slice(&0x0001u16.to_be_bytes()); // Binding Request
    request.extend_from_slice(&0x0000u16.to_be_bytes()); // Message Length = 0
    request.extend_from_slice(&0x2112A442u32.to_be_bytes()); // Magic Cookie
    request.extend_from_slice(&tx_id); // Transaction ID

    socket
        .send_to(&request, addr)
        .await
        .with_context(|| format!("向 STUN 服务器 {} 发送请求失败", addr))?;

    let mut buf = [0u8; 512];
    let result = tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await;

    let (len, _from) = match result {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return Err(anyhow::anyhow!("接收 STUN 响应失败: {}", e)),
        Err(_) => return Err(anyhow::anyhow!("STUN 查询超时")),
    };

    parse_stun_response(&buf[..len], &tx_id)
}

/// 解析 STUN Binding Response，提取 XOR-MAPPED-ADDRESS 或 MAPPED-ADDRESS
fn parse_stun_response(buf: &[u8], expected_tx_id: &[u8; 12]) -> Result<IpAddr> {
    if buf.len() < 20 {
        anyhow::bail!("STUN 响应过短");
    }

    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let magic = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);

    if magic != 0x2112A442 {
        anyhow::bail!("无效的 STUN Magic Cookie: 0x{:08x}", magic);
    }

    if &buf[8..20] != expected_tx_id {
        anyhow::bail!("STUN Transaction ID 不匹配");
    }

    // 0x0101 = Binding Success Response
    if msg_type != 0x0101 {
        anyhow::bail!("STUN 响应类型非成功: 0x{:04x}", msg_type);
    }

    // 解析属性
    let mut offset = 20;
    let end = 20 + msg_len;

    while offset + 4 <= end.min(buf.len()) {
        let attr_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let attr_len = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
        offset += 4;

        if offset + attr_len > buf.len() {
            break;
        }

        let attr_data = &buf[offset..offset + attr_len];

        // 0x0020 = XOR-MAPPED-ADDRESS
        if attr_type == 0x0020 {
            if attr_len < 4 {
                offset += attr_len;
                align_offset(&mut offset);
                continue;
            }
            let family = attr_data[1];

            if family == 0x01 && attr_len >= 8 {
                // IPv4
                let x_addr = u32::from_be_bytes([attr_data[4], attr_data[5], attr_data[6], attr_data[7]]);
                let addr = x_addr ^ 0x2112A442; // XOR with magic cookie
                return Ok(IpAddr::V4(Ipv4Addr::from(addr)));
            }

            if family == 0x02 && attr_len >= 20 {
                // IPv6
                let mut x_addr = [0u8; 16];
                x_addr.copy_from_slice(&attr_data[4..20]);
                // XOR with magic cookie (4 bytes) + transaction ID (12 bytes)
                let xor_key: [u8; 16] = [
                    buf[4], buf[5], buf[6], buf[7],
                    buf[8], buf[9], buf[10], buf[11],
                    buf[12], buf[13], buf[14], buf[15],
                    buf[16], buf[17], buf[18], buf[19],
                ];
                let mut addr = [0u8; 16];
                for i in 0..16 {
                    addr[i] = x_addr[i] ^ xor_key[i];
                }
                return Ok(IpAddr::V6(Ipv6Addr::from(addr)));
            }
        }

        // 0x0001 = MAPPED-ADDRESS (fallback)
        if attr_type == 0x0001 {
            if attr_len < 4 {
                offset += attr_len;
                align_offset(&mut offset);
                continue;
            }
            let family = attr_data[1];

            if family == 0x01 && attr_len >= 8 {
                let addr = u32::from_be_bytes([attr_data[4], attr_data[5], attr_data[6], attr_data[7]]);
                return Ok(IpAddr::V4(Ipv4Addr::from(addr)));
            }

            if family == 0x02 && attr_len >= 20 {
                let mut addr = [0u8; 16];
                addr.copy_from_slice(&attr_data[4..20]);
                return Ok(IpAddr::V6(Ipv6Addr::from(addr)));
            }
        }

        offset += attr_len;
        align_offset(&mut offset);
    }

    anyhow::bail!("STUN 响应中未找到 MAPPED-ADDRESS 属性")
}

fn align_offset(offset: &mut usize) {
    if !(*offset).is_multiple_of(4) {
        *offset += 4 - (*offset % 4);
    }
}
