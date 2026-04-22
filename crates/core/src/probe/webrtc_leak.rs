use crate::probe::{stun, Evidence, EvidenceBuilder, Probe, ProbeCategory, ProbeContext, RiskLevel};
use anyhow::{Context, Result};
use async_trait::async_trait;
use std::net::IpAddr;
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
                // 127.0.0.0/8 (loopback)
                if octets[0] == 127 {
                    return true;
                }
                // 100.64.0.0/10 (CGNAT / carrier-grade NAT)
                if octets[0] == 100 && (64..=127).contains(&octets[1]) {
                    return true;
                }
                // 169.254.0.0/16 (link-local)
                if octets[0] == 169 && octets[1] == 254 {
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

    /// 判断接口名是否属于 VPN/TUN 类型
    fn is_vpn_interface(&self, name: &str) -> bool {
        let lower = name.to_lowercase();
        [
            "tun", "utun", "tap", "vpn", "wg", "wireguard", "ppp",
            "ipsec", "l2tp", "pptp", "openvpn", "nordlynx", "proton",
        ]
        .iter()
        .any(|&prefix| lower.contains(prefix))
    }

    /// 通过 STUN 获取公网映射 IP
    async fn get_stun_mapped_ip(&self, timeout: Duration) -> Result<IpAddr> {
        for (host, port) in stun::DEFAULT_STUN_SERVERS.iter().take(2) {
            match stun::query_stun_server(host, *port, timeout).await {
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

        let vpn_interfaces: Vec<_> = local_ips
            .iter()
            .filter(|(name, _)| self.is_vpn_interface(name))
            .cloned()
            .collect();

        // 2. STUN 映射 IP
        let stun_result = self.get_stun_mapped_ip(ctx.timeout).await;

        let mut details = EvidenceBuilder::new(self.name())
            .detail("total_interfaces", local_ips.len())
            .detail("private_ips_count", private_ips.len())
            .detail("non_loopback_private_count", non_loopback_private.len())
            .detail("vpn_interfaces_count", vpn_interfaces.len());

        // 记录所有接口
        let iface_list: Vec<_> = local_ips
            .iter()
            .map(|(name, ip)| format!("{}: {}", name, ip))
            .collect();
        details = details.detail("interfaces", iface_list);

        // 记录 VPN 接口
        if !vpn_interfaces.is_empty() {
            let vpn_list: Vec<_> = vpn_interfaces
                .iter()
                .map(|(name, ip)| format!("{}: {}", name, ip))
                .collect();
            details = details.detail("vpn_interfaces", vpn_list);
        }

        // 记录内网地址
        if !non_loopback_private.is_empty() {
            let leak_list: Vec<_> = non_loopback_private
                .iter()
                .map(|(name, ip)| format!("{}: {}", name, ip))
                .collect();
            details = details.detail("private_ips", leak_list);
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

        // 3. 风险判定（改进版：区分普通内网与 VPN 场景）
        if non_loopback_private.is_empty() {
            Ok(details
                .risk_level(RiskLevel::Clean)
                .confidence(0.9)
                .summary("未发现非 loopback 的内网 IP 地址")
                .mitigation("当前网络环境可能为公网直连或容器化环境，WebRTC 本地 IP 暴露风险较低")
                .build())
        } else if vpn_interfaces.is_empty() {
            // 普通内网环境（家庭/办公室）：WebRTC 暴露内网 IP 是预期行为，非漏洞
            let leaked = non_loopback_private
                .iter()
                .map(|(_, ip)| ip.to_string())
                .collect::<Vec<_>>()
                .join(", ");

            Ok(details
                .risk_level(RiskLevel::Clean)
                .confidence(0.75)
                .summary(format!(
                    "检测到 {} 个内网 IP (普通网络环境，WebRTC 暴露属预期行为): {}",
                    non_loopback_private.len(),
                    leaked
                ))
                .mitigation("在家庭/办公室等普通内网中，WebRTC 暴露本地 IP 是标准行为")
                .mitigation("如使用 VPN，建议配合禁用 WebRTC 的浏览器扩展以确保隐私")
                .build())
        } else {
            // 存在 VPN 接口 + 内网 IP：WebRTC 可能绕过 VPN 隧道
            let leaked = non_loopback_private
                .iter()
                .map(|(_, ip)| ip.to_string())
                .collect::<Vec<_>>()
                .join(", ");

            Ok(details
                .risk_level(RiskLevel::Suspicious)
                .confidence(0.82)
                .summary(format!(
                    "VPN 环境下检测到 {} 个内网 IP，WebRTC 可能绕过 VPN 隧道暴露: {}",
                    non_loopback_private.len(),
                    leaked
                ))
                .mitigation("WebRTC 可能通过本地接口绕过 VPN，暴露真实内网拓扑")
                .mitigation("建议在浏览器中禁用 WebRTC，或使用 uBlock Origin / WebRTC Control 等扩展")
                .mitigation("确认 VPN 是否提供 WebRTC 泄漏保护功能")
                .build())
        }
    }
}

impl Default for WebRTCLeakProbe {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_ipv4() {
        let probe = WebRTCLeakProbe::new();
        assert!(probe.is_private_ip("10.0.0.1".parse().unwrap()));
        assert!(probe.is_private_ip("172.16.5.5".parse().unwrap()));
        assert!(probe.is_private_ip("192.168.1.1".parse().unwrap()));
        assert!(probe.is_private_ip("127.0.0.1".parse().unwrap()));
        assert!(probe.is_private_ip("100.64.0.1".parse().unwrap()));
        assert!(probe.is_private_ip("169.254.1.1".parse().unwrap()));
    }

    #[test]
    fn test_public_ipv4() {
        let probe = WebRTCLeakProbe::new();
        assert!(!probe.is_private_ip("8.8.8.8".parse().unwrap()));
        assert!(!probe.is_private_ip("1.1.1.1".parse().unwrap()));
        assert!(!probe.is_private_ip("203.0.113.1".parse().unwrap()));
    }

    #[test]
    fn test_private_ipv6() {
        let probe = WebRTCLeakProbe::new();
        assert!(probe.is_private_ip("fc00::1".parse().unwrap()));
        assert!(probe.is_private_ip("fe80::1".parse().unwrap()));
        assert!(probe.is_private_ip("::1".parse().unwrap()));
    }

    #[test]
    fn test_public_ipv6() {
        let probe = WebRTCLeakProbe::new();
        assert!(!probe.is_private_ip("2001:4860:4860::8888".parse().unwrap()));
        assert!(!probe.is_private_ip("2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn test_vpn_interface_detection() {
        let probe = WebRTCLeakProbe::new();
        assert!(probe.is_vpn_interface("utun3"));
        assert!(probe.is_vpn_interface("tun0"));
        assert!(probe.is_vpn_interface("wg0"));
        assert!(probe.is_vpn_interface("vpn-ipv4"));
        assert!(!probe.is_vpn_interface("en0"));
        assert!(!probe.is_vpn_interface("eth0"));
        assert!(!probe.is_vpn_interface("Wi-Fi"));
    }
}


