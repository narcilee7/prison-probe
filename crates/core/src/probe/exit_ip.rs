use crate::probe::{stun, Evidence, EvidenceBuilder, Probe, ProbeCategory, ProbeContext, RiskLevel};
use anyhow::{Context, Result};
use async_trait::async_trait;
use hickory_resolver::{
    config::{ResolverConfig, ResolverOpts},
    TokioResolver,
};
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

/// 出口 IP 一致性探测器
///
/// 通过三个独立信道获取公网 IP 并比对一致性：
/// 1. HTTPS API 查询
/// 2. UDP STUN 协议
/// 3. DNS A 查询 (OpenDNS myip)
pub struct ExitIPConsistencyProbe;

impl ExitIPConsistencyProbe {
    pub fn new() -> Self {
        Self
    }

    /// 通过 HTTPS API 获取公网 IP
    async fn get_ip_via_https(&self, timeout: Duration) -> Result<IpAddr> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .use_rustls_tls()
            .build()
            .context("构建 HTTP 客户端失败")?;

        // 使用多个服务并发查询，取第一个成功的结果
        let urls = [
            "https://api.ipify.org?format=json",
            "https://checkip.amazonaws.com/",
            "https://httpbin.org/ip",
        ];

        let mut last_err = None;

        for url in &urls {
            match client.get(*url).send().await {
                Ok(resp) => {
                    let text = resp.text().await.unwrap_or_default();
                    // 尝试不同格式的解析
                    if let Some(ip) = parse_ip_from_text(&text) {
                        return Ok(ip);
                    }
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }

        Err(anyhow::anyhow!(
            "所有 HTTPS IP 查询服务均失败: {:?}",
            last_err
        ))
    }

    /// 通过 STUN 协议获取公网 IP
    async fn get_ip_via_stun(&self, timeout: Duration) -> Result<IpAddr> {
        for (host, port) in stun::DEFAULT_STUN_SERVERS {
            match stun::query_stun_server(host, *port, timeout).await {
                Ok(ip) => return Ok(ip),
                Err(e) => tracing::debug!(host, error = %e, "STUN query failed"),
            }
        }

        Err(anyhow::anyhow!("所有 STUN 服务器查询失败"))
    }

    /// 通过 DNS 查询获取公网 IP (OpenDNS myip)
    async fn get_ip_via_dns(&self, timeout: Duration) -> Result<IpAddr> {
        use hickory_resolver::name_server::TokioConnectionProvider;
        use hickory_resolver::proto::xfer::Protocol;
        use hickory_resolver::config::NameServerConfig;

        // 使用 OpenDNS 的解析器，它会对 myip.opendns.com 返回请求者的公网 IP
        let mut config = ResolverConfig::new();
        config.add_name_server(NameServerConfig::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(208, 67, 222, 222)), 53),
            Protocol::Udp,
        ));
        config.add_name_server(NameServerConfig::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(208, 67, 220, 220)), 53),
            Protocol::Udp,
        ));

        let mut opts = ResolverOpts::default();
        opts.timeout = timeout;
        opts.attempts = 2;

        let resolver = TokioResolver::builder_with_config(config, TokioConnectionProvider::default())
            .with_options(opts)
            .build();

        let response = resolver
            .lookup_ip("myip.opendns.com.")
            .await
            .map_err(|e| anyhow::anyhow!("DNS 查询失败: {}", e))?;

        let ips: Vec<_> = response.iter().collect();
        ips.into_iter()
            .next()
            .context("DNS 响应中未找到 IP 地址")
    }
}

#[async_trait]
impl Probe for ExitIPConsistencyProbe {
    fn name(&self) -> &'static str {
        "exit_ip_consistency"
    }

    fn category(&self) -> ProbeCategory {
        ProbeCategory::Quick
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(15)
    }

    async fn run(&self, ctx: &ProbeContext) -> Result<Evidence> {
        let timeout = ctx.timeout;

        // 并发执行三种探测
        let (https_result, stun_result, dns_result) = tokio::join!(
            self.get_ip_via_https(timeout),
            self.get_ip_via_stun(timeout),
            self.get_ip_via_dns(timeout),
        );

        let mut details = EvidenceBuilder::new(self.name());
        let mut all_ips = Vec::new();

        // HTTPS 结果
        match &https_result {
            Ok(ip) => {
                all_ips.push((*ip, "https"));
                details = details.detail("ip_https", ip.to_string());
            }
            Err(e) => {
                details = details.detail("https_error", e.to_string());
            }
        }

        // STUN 结果
        match &stun_result {
            Ok(ip) => {
                all_ips.push((*ip, "stun"));
                details = details.detail("ip_stun", ip.to_string());
            }
            Err(e) => {
                details = details.detail("stun_error", e.to_string());
            }
        }

        // DNS 结果
        match &dns_result {
            Ok(ip) => {
                all_ips.push((*ip, "dns"));
                details = details.detail("ip_dns", ip.to_string());
            }
            Err(e) => {
                details = details.detail("dns_error", e.to_string());
            }
        }

        // 分析一致性
        if all_ips.is_empty() {
            return Ok(
                details
                    .risk_level(RiskLevel::Compromised)
                    .confidence(1.0)
                    .summary("所有 IP 探测信道均失败，无法确认网络状态")
                    .mitigation("请检查网络连接是否可用")
                    .mitigation("如使用代理，请确认代理配置正确")
                    .build(),
            );
        }

        // 检查所有 IP 是否一致
        let first_ip = all_ips[0].0;
        let all_match = all_ips.iter().all(|(ip, _)| *ip == first_ip);

        if all_ips.len() == 3 && all_match {
            Ok(details
                .risk_level(RiskLevel::Clean)
                .confidence(0.95)
                .summary(format!("出口 IP 一致 ({})", first_ip))
                .detail("consistency_score", 100)
                .detail("is_proxy_layered", false)
                .mitigation("无需操作，网络出口正常")
                .build())
        } else if all_ips.len() >= 2 {
            // 部分成功但有差异或部分失败
            let unique_ips: std::collections::HashSet<_> =
                all_ips.iter().map(|(ip, _)| *ip).collect();

            if unique_ips.len() == 1 {
                // IP 一致但部分信道失败
                Ok(details
                    .risk_level(RiskLevel::Suspicious)
                    .confidence(0.7)
                    .summary(format!(
                        "出口 IP 一致 ({})，但仅 {}/3 个信道可用",
                        first_ip,
                        all_ips.len()
                    ))
                    .detail("consistency_score", 70)
                    .detail("is_proxy_layered", false)
                    .mitigation("某些网络协议可能被限制，建议检查防火墙规则")
                    .build())
            } else {
                // IP 不一致！可能存在代理分层或 DNS 泄漏
                let ip_map: std::collections::HashMap<String, Vec<&str>> = all_ips
                    .iter()
                    .fold(std::collections::HashMap::new(), |mut acc, (ip, channel)| {
                        acc.entry(ip.to_string()).or_default().push(*channel);
                        acc
                    });

                let summary = format!(
                    "出口 IP 不一致！检测到 {} 个不同 IP: {}",
                    unique_ips.len(),
                    all_ips
                        .iter()
                        .map(|(ip, ch)| format!("{}({})", ip, ch))
                        .collect::<Vec<_>>()
                        .join(", ")
                );

                Ok(details
                    .risk_level(RiskLevel::Compromised)
                    .confidence(0.9)
                    .summary(summary)
                    .detail("consistency_score", 0)
                    .detail("is_proxy_layered", true)
                    .detail("ip_map", json!(ip_map))
                    .mitigation("HTTP 与 UDP IP 不同 → 可能存在代理分层（HTTP 代理在 VPN 上层或反之）")
                    .mitigation("DNS 解析 IP 与其他不同 → 可能存在 DNS 泄漏或 GeoDNS 异常")
                    .mitigation("建议检查代理/VPN 配置，确保所有流量通过同一出口")
                    .build())
            }
        } else {
            // 只有一个信道成功
            Ok(details
                .risk_level(RiskLevel::Suspicious)
                .confidence(0.5)
                .summary(format!(
                    "仅 1 个信道返回 IP ({}), 无法验证一致性",
                    first_ip
                ))
                .detail("consistency_score", 30)
                .mitigation("网络限制可能导致部分探测失败，建议更换网络环境重试")
                .build())
        }
    }
}

impl Default for ExitIPConsistencyProbe {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ip_from_json_ip() {
        let text = r#"{"ip": "1.2.3.4"}"#;
        assert_eq!(parse_ip_from_text(text), Some("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn test_parse_ip_from_json_origin() {
        let text = r#"{"origin": "203.0.113.5"}"#;
        assert_eq!(parse_ip_from_text(text), Some("203.0.113.5".parse().unwrap()));
    }

    #[test]
    fn test_parse_ip_plain_text() {
        let text = "  198.51.100.42  \n";
        assert_eq!(parse_ip_from_text(text), Some("198.51.100.42".parse().unwrap()));
    }

    #[test]
    fn test_extract_ip_from_text() {
        let text = "Your IP address is 192.0.2.1 and port 8080";
        assert_eq!(extract_ip_from_text(text), Some("192.0.2.1".parse().unwrap()));
    }

    #[test]
    fn test_parse_ip_invalid() {
        let text = "no ip here";
        assert_eq!(parse_ip_from_text(text), None);
    }
}

/// 从文本中解析 IP 地址
fn parse_ip_from_text(text: &str) -> Option<IpAddr> {
    let trimmed = text.trim();

    // 尝试解析 JSON 格式 {"ip": "x.x.x.x"}
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(trimmed) {
        if let Some(ip_str) = json.get("ip").and_then(|v| v.as_str()) {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                return Some(ip);
            }
            if let Ok(ip) = ip_str.trim().parse::<IpAddr>() {
                return Some(ip);
            }
        }
        if let Some(origin_str) = json.get("origin").and_then(|v| v.as_str())
            && let Ok(ip) = origin_str.parse::<IpAddr>()
        {
            return Some(ip);
        }
    }

    // 尝试直接解析纯文本 IP
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Some(ip);
    }

    // 尝试在文本中提取 IP 地址
    extract_ip_from_text(trimmed)
}

fn extract_ip_from_text(text: &str) -> Option<IpAddr> {
    use regex::Regex;
    use std::str::FromStr;
    let re = Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b").ok()?;
    for cap in re.captures_iter(text) {
        if let Ok(ip) = IpAddr::from_str(&cap[1]) {
            return Some(ip);
        }
    }
    None
}


