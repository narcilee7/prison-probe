use crate::probe::{Evidence, EvidenceBuilder, Probe, ProbeCategory, ProbeContext, RiskLevel};
use anyhow::{Context, Result};
use async_trait::async_trait;
use rand::Rng;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

/// WebRTC 本地 IP 暴露检测器
///
/// 通过枚举系统网络接口 + STUN 反射测试，检测本地内网 IP
/// 是否可能在 WebRTC ICE 候选收集中被暴露给远端。
pub struct WebRTCLeakProbe;

impl WebRTCLeakProbe {
    pub fn new() -> Self {
        Self
    }

    /// 枚举系统所有网络接口的 IP 地址
    fn enumerate_local_ips(&self) -> Result<Vec<(String, IpAddr)>> {
        let ifaces = local_ip_address::list_afinet_netifas()
            .context("枚举网络接口失败")?;

        Ok(ifaces.into_iter().collect())
    }

    /// 判断是否为内网地址
    fn is_private_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                // 10.0.0.0/8
                if octets[0] == 10 {
                    return true;
                }
                // 172.16.0.0/12
                if octets[0] == 172 && (16..=31).contains(&octets[1]) {
                    return true;
                }
                // 192.168.0.0/16
                if octets[0] == 192 && octets[1] == 168 {
                    return true;
                }
                // 127.0.0.0/8 (loopback) — WebRTC 通常不会暴露 loopback，但我们也标记
                if octets[0] == 127 {
                    return true;
                }
                false
            }
            IpAddr::V6(v6) => {
                let segments = v6.segments();
                // fc00::/7 Unique Local Address
                if (segments[0] & 0xfe00) == 0xfc00 {
                    return true;
                }
                // fe80::/10 Link-Local Address
                if (segments[0] & 0xffc0) == 0xfe80 {
                    return true;
                }
                // ::1 loopback
                if v6.is_loopback() {
                    return true;
                }
                false
            }
        }
    }

    /// 通过 STUN 获取公网映射 IP
    async fn get_stun_mapped_ip(&self, timeout: Duration) -> Result<IpAddr> {
        let stun_servers = [
            ("stun.l.google.com", 19302),
            ("stun1.l.google.com", 19302),
        ];

        for (host, port) in &stun_servers {
            match query_stun_server(host, *port, timeout).await {
                Ok(ip) => return Ok(ip),
                Err(e) => tracing::debug!(host, error = %e, "STUN query failed"),
            }
        }

        Err(anyhow::anyhow!("所有 STUN 服务器查询失败"))
    }
}

#[async_trait]
impl Probe for WebRTCLeakProbe {
    fn name(&self) -> &'static str {
        "webrtc_leak"
    }

    fn category(&self) -> ProbeCategory {
        ProbeCategory::Quick
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(15)
    }

    async fn run(&self, ctx: &ProbeContext) -> Result<Evidence> {
        // 1. 枚举本地 IP
        let local_ips = self.enumerate_local_ips()?;

        let private_ips: Vec<_> = local_ips
            .iter()
            .filter(|(_, ip)| self.is_private_ip(*ip))
            .cloned()
            .collect();

        let non_loopback_private: Vec<_> = private_ips
            .iter()
            .filter(|(_, ip)| !ip.is_loopback())
            .cloned()
            .collect();

        // 2. STUN 映射 IP
        let stun_result = self.get_stun_mapped_ip(ctx.timeout).await;

        let mut details = EvidenceBuilder::new(self.name())
            .detail("total_interfaces", local_ips.len())
            .detail("private_ips_count", private_ips.len())
            .detail("non_loopback_private_count", non_loopback_private.len());

        // 记录所有接口
        let iface_list: Vec<_> = local_ips
            .iter()
            .map(|(name, ip)| format!("{}: {}", name, ip))
            .collect();
        details = details.detail("interfaces", iface_list);

        // 记录内网地址
        if !non_loopback_private.is_empty() {
            let leak_list: Vec<_> = non_loopback_private
                .iter()
                .map(|(name, ip)| format!("{}: {}", name, ip))
                .collect();
            details = details.detail("leaked_private_ips", leak_list);
        }

        // 记录 STUN 结果
        match &stun_result {
            Ok(ip) => {
                details = details.detail("stun_mapped_ip", ip.to_string());
            }
            Err(e) => {
                details = details.detail("stun_error", e.to_string());
            }
        }

        // 3. 风险判定
        if non_loopback_private.is_empty() {
            // 没有内网地址（罕见，通常是容器/VPN 环境）
            Ok(details
                .risk_level(RiskLevel::Clean)
                .confidence(0.9)
                .summary("未发现非 loopback 的内网 IP 地址")
                .mitigation("当前网络环境可能为公网直连或容器化环境，WebRTC 本地 IP 暴露风险较低")
                .build())
        } else {
            // 有内网地址！WebRTC 可能暴露
            let leaked = non_loopback_private
                .iter()
                .map(|(_, ip)| ip.to_string())
                .collect::<Vec<_>>()
                .join(", ");

            let summary = format!(
                "检测到 {} 个内网 IP 地址可能被 WebRTC 暴露: {}",
                non_loopback_private.len(),
                leaked
            );

            Ok(details
                .risk_level(RiskLevel::Compromised)
                .confidence(0.88)
                .summary(summary)
                .mitigation("WebRTC 可能在建立 P2P 连接时暴露你的真实内网 IP 地址")
                .mitigation("建议在浏览器或应用设置中禁用 WebRTC，或使用禁用 WebRTC 的浏览器扩展")
                .mitigation("通过 VPN 时，WebRTC 可能绕过 VPN 隧道直接暴露本地 IP")
                .build())
        }
    }
}

impl Default for WebRTCLeakProbe {
    fn default() -> Self {
        Self::new()
    }
}

/// 向 STUN 服务器发送 Binding Request 并解析响应中的 XOR-MAPPED-ADDRESS
async fn query_stun_server(host: &str, port: u16, timeout: Duration) -> Result<IpAddr> {
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

    if msg_type != 0x0101 {
        anyhow::bail!("STUN 响应类型非成功: 0x{:04x}", msg_type);
    }

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

        // XOR-MAPPED-ADDRESS (0x0020)
        if attr_type == 0x0020 && attr_len >= 8 {
            let family = attr_data[1];
            if family == 0x01 && attr_len >= 8 {
                let x_addr = u32::from_be_bytes([attr_data[4], attr_data[5], attr_data[6], attr_data[7]]);
                let addr = x_addr ^ 0x2112A442;
                return Ok(IpAddr::V4(Ipv4Addr::from(addr)));
            }
        }

        // MAPPED-ADDRESS (0x0001)
        if attr_type == 0x0001 && attr_len >= 8 {
            let family = attr_data[1];
            if family == 0x01 && attr_len >= 8 {
                let addr = u32::from_be_bytes([attr_data[4], attr_data[5], attr_data[6], attr_data[7]]);
                return Ok(IpAddr::V4(Ipv4Addr::from(addr)));
            }
        }

        offset += attr_len;
        if offset % 4 != 0 {
            offset += 4 - (offset % 4);
        }
    }

    anyhow::bail!("STUN 响应中未找到 MAPPED-ADDRESS 属性")
}
