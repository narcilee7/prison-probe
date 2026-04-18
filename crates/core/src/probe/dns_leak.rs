use crate::probe::{Evidence, EvidenceBuilder, Probe, ProbeCategory, ProbeContext, RiskLevel};
use anyhow::Result;
use async_trait::async_trait;
use hickory_resolver::{
    config::{ResolverConfig, ResolverOpts},
    TokioResolver,
};
use serde_json::json;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

/// 已知的公共 DNS 服务器 IP 白名单（用于判断是否存在 DNS 泄漏）
const KNOWN_PUBLIC_DNS: &[&str] = &[
    // Cloudflare
    "1.1.1.1",
    "1.0.0.1",
    "2606:4700:4700::1111",
    "2606:4700:4700::1001",
    // Google
    "8.8.8.8",
    "8.8.4.4",
    "2001:4860:4860::8888",
    "2001:4860:4860::8844",
    // Quad9
    "9.9.9.9",
    "149.112.112.112",
    "2620:fe::fe",
    "2620:fe::9",
    // AdGuard
    "94.140.14.14",
    "94.140.15.15",
    // OpenDNS
    "208.67.222.222",
    "208.67.220.220",
    // DNS.SB
    "185.222.222.222",
    "185.184.222.222",
];

/// DNS 泄漏探测器
///
/// 通过 whoami 服务检测实际处理 DNS 查询的解析器 IP，
/// 判断是否存在 ISP DNS 泄漏（即未通过加密 DNS 却暴露了运营商 DNS）
pub struct DNSLeakProbe;

impl DNSLeakProbe {
    pub fn new() -> Self {
        Self
    }

    /// 使用系统默认解析器查询 whoami 服务
    async fn detect_system_dns(&self, _timeout: Duration) -> Result<Vec<IpAddr>> {
        let resolver = TokioResolver::builder_tokio()
            .map_err(|e| anyhow::anyhow!("创建系统 DNS 解析器失败: {}", e))?
            .build();

        let mut detected = Vec::new();

        // 使用多个 whoami 服务增加覆盖
        let whoami_hosts = ["whoami.ipv4.akahelp.net", "whoami.akamai.net"];

        for host in &whoami_hosts {
            match resolver.lookup_ip(*host).await {
                Ok(response) => {
                    for ip in response.iter() {
                        detected.push(ip);
                    }
                }
                Err(e) => {
                    tracing::debug!(host, error = %e, "whoami query failed");
                }
            }
        }

        Ok(detected)
    }

    /// 检测通过特定公共 DNS 解析的结果（作为对比基线）
    async fn detect_via_public_dns(
        &self,
        dns_ip: Ipv4Addr,
        timeout: Duration,
    ) -> Result<Vec<IpAddr>> {
        use hickory_resolver::config::NameServerConfig;
        use hickory_resolver::name_server::TokioConnectionProvider;
        use hickory_resolver::proto::xfer::Protocol;

        let mut config = ResolverConfig::new();
        config.add_name_server(NameServerConfig::new(
            SocketAddr::new(IpAddr::V4(dns_ip), 53),
            Protocol::Udp,
        ));

        let mut opts = ResolverOpts::default();
        opts.timeout = timeout;
        opts.attempts = 2;

        let resolver = TokioResolver::builder_with_config(config, TokioConnectionProvider::default())
            .with_options(opts)
            .build();

        let mut detected = Vec::new();

        match resolver.lookup_ip("whoami.ipv4.akahelp.net").await {
            Ok(response) => {
                for ip in response.iter() {
                    detected.push(ip);
                }
            }
            Err(e) => {
                tracing::debug!(dns = %dns_ip, error = %e, "whoami query via public dns failed");
            }
        }

        Ok(detected)
    }

    /// 检查 IP 是否属于已知公共 DNS
    fn is_known_public_dns(&self, ip: IpAddr) -> bool {
        let ip_str = ip.to_string();
        KNOWN_PUBLIC_DNS.contains(&ip_str.as_str())
    }
}

#[async_trait]
impl Probe for DNSLeakProbe {
    fn name(&self) -> &'static str {
        "dns_leak"
    }

    fn category(&self) -> ProbeCategory {
        ProbeCategory::Quick
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(15)
    }

    async fn run(&self, ctx: &ProbeContext) -> Result<Evidence> {
        let timeout = ctx.timeout;

        // 并发执行系统 DNS 检测和公共 DNS 对比
        let (system_result, cf_result, google_result) = tokio::join!(
            self.detect_system_dns(timeout),
            self.detect_via_public_dns(Ipv4Addr::new(1, 1, 1, 1), timeout),
            self.detect_via_public_dns(Ipv4Addr::new(8, 8, 8, 8), timeout),
        );

        let mut details = EvidenceBuilder::new(self.name());
        let mut system_ips: Vec<IpAddr> = Vec::new();
        let mut baseline_ips: HashSet<IpAddr> = HashSet::new();

        // 收集系统 DNS 检测结果
        match system_result {
            Ok(ips) => {
                system_ips = ips.clone();
                let unique_ips: Vec<String> = ips
                    .iter()
                    .map(|ip| ip.to_string())
                    .collect::<HashSet<_>>()
                    .into_iter()
                    .collect();
                details = details.detail("system_dns_ips", json!(unique_ips));
                tracing::info!(ips = ?unique_ips, "system DNS detected");
            }
            Err(e) => {
                details = details.detail("system_dns_error", e.to_string());
                tracing::warn!(error = %e, "system DNS detection failed");
            }
        }

        // 收集 Cloudflare DNS 基线
        match cf_result {
            Ok(ips) => {
                let unique_ips: Vec<String> = ips
                    .iter()
                    .map(|ip| ip.to_string())
                    .collect::<HashSet<_>>()
                    .into_iter()
                    .collect();
                details = details.detail("cloudflare_dns_ips", json!(unique_ips));
                baseline_ips.extend(ips);
            }
            Err(e) => {
                details = details.detail("cloudflare_dns_error", e.to_string());
            }
        }

        // 收集 Google DNS 基线
        match google_result {
            Ok(ips) => {
                let unique_ips: Vec<String> = ips
                    .iter()
                    .map(|ip| ip.to_string())
                    .collect::<HashSet<_>>()
                    .into_iter()
                    .collect();
                details = details.detail("google_dns_ips", json!(unique_ips));
                baseline_ips.extend(ips);
            }
            Err(e) => {
                details = details.detail("google_dns_error", e.to_string());
            }
        }

        // 分析泄漏情况
        if system_ips.is_empty() {
            return Ok(details
                .risk_level(RiskLevel::Suspicious)
                .confidence(0.6)
                .summary("无法检测系统 DNS 状态，whoami 查询全部失败")
                .mitigation("请检查网络连接和 DNS 配置")
                .mitigation("如果使用 VPN，请确认 VPN 的 DNS 推送配置正确")
                .build());
        }

        // 去重系统 DNS IP
        let unique_system_ips: HashSet<_> = system_ips.iter().copied().collect();

        // 检查是否有非公共 DNS 的系统 DNS
        let unknown_dns: Vec<IpAddr> = unique_system_ips
            .iter()
            .filter(|ip| !self.is_known_public_dns(**ip))
            .copied()
            .collect();

        // 检查系统 DNS 是否与公共 DNS 基线一致
        let system_matches_baseline: HashSet<_> = unique_system_ips
            .intersection(&baseline_ips)
            .copied()
            .collect();

        if unknown_dns.is_empty() {
            // 所有检测到的 DNS 都是已知公共 DNS
            let ip_list = unique_system_ips
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join(", ");

            Ok(details
                .risk_level(RiskLevel::Clean)
                .confidence(0.85)
                .summary(format!(
                    "DNS 查询经过已知公共 DNS 服务器 ({}, {} 个)",
                    if system_matches_baseline.is_empty() {
                        "未与加密 DNS 基线匹配"
                    } else {
                        "与加密 DNS 基线一致"
                    },
                    unique_system_ips.len()
                ))
                .detail("detected_servers", json!(ip_list))
                .detail(
                    "is_encrypted",
                    system_matches_baseline.len() == unique_system_ips.len(),
                )
                .mitigation("DNS 配置正常，未发现 ISP DNS 泄漏")
                .build())
        } else {
            // 发现非公共 DNS！可能存在泄漏
            let unknown_list: Vec<String> = unknown_dns.iter().map(|ip| ip.to_string()).collect();
            let known_list: Vec<String> = unique_system_ips
                .iter()
                .filter(|ip| self.is_known_public_dns(**ip))
                .map(|ip| ip.to_string())
                .collect();

            let summary = if known_list.is_empty() {
                format!(
                    "DNS 泄漏 detected！所有 DNS 查询经过非公共 DNS 服务器: {}",
                    unknown_list.join(", ")
                )
            } else {
                format!(
                    "DNS 泄漏 detected！发现 {} 个非公共 DNS 服务器: {}（另有 {} 个公共 DNS）",
                    unknown_dns.len(),
                    unknown_list.join(", "),
                    known_list.len()
                )
            };

            Ok(details
                .risk_level(RiskLevel::Compromised)
                .confidence(0.9)
                .summary(summary)
                .detail("unknown_dns_servers", json!(unknown_list))
                .detail("known_dns_servers", json!(known_list))
                .detail("leak_detected", true)
                .mitigation("你的 DNS 查询正经过 ISP 或其他未加密 DNS 服务器，存在监控风险")
                .mitigation("建议启用 DoH (DNS over HTTPS) 或 DoT (DNS over TLS)")
                .mitigation("检查系统/VPN 的 DNS 设置，确保所有查询通过加密通道")
                .build())
        }
    }
}

impl Default for DNSLeakProbe {
    fn default() -> Self {
        Self::new()
    }
}
