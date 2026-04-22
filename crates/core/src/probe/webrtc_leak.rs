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


