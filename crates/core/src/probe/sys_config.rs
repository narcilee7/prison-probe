use crate::probe::{Evidence, EvidenceBuilder, Probe, ProbeCategory, ProbeContext, RiskLevel};
use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::json;
use std::collections::HashMap;
use std::time::Duration;

/// 系统代理配置审计探测器
///
/// macOS: 通过 networksetup 读取系统代理配置
/// 同时检测环境变量中的代理设置
pub struct SysConfigProbe;

impl SysConfigProbe {
    pub fn new() -> Self {
        Self
    }

    /// 获取所有网络服务列表
    fn list_network_services(&self) -> Result<Vec<String>> {
        let output = std::process::Command::new("networksetup")
            .args(["-listallnetworkservices"])
            .output()
            .context("执行 networksetup 失败")?;

        if !output.status.success() {
            anyhow::bail!(
                "networksetup 返回错误: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let text = String::from_utf8_lossy(&output.stdout);
        let mut services = Vec::new();
        let mut skip_first = true;

        for line in text.lines() {
            if skip_first {
                skip_first = false;
                continue; // 跳过 "An asterisk (*) denotes..." 这一行
            }
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('*') {
                services.push(trimmed.to_string());
            }
        }

        Ok(services)
    }

    /// 获取指定服务的代理配置
    fn get_proxy_settings(&self, service: &str) -> Result<ProxySettings> {
        let mut settings = ProxySettings {
            service: service.to_string(),
            web_proxy: None,
            secure_web_proxy: None,
            socks_proxy: None,
            auto_proxy_url: None,
            bypass_domains: Vec::new(),
        };

        // Web Proxy
        if let Ok(out) = self.run_networksetup(&["-getwebproxy", service]) {
            settings.web_proxy = self.parse_proxy_output(&out);
        }

        // Secure Web Proxy
        if let Ok(out) = self.run_networksetup(&["-getsecurewebproxy", service]) {
            settings.secure_web_proxy = self.parse_proxy_output(&out);
        }

        // SOCKS Firewall Proxy
        if let Ok(out) = self.run_networksetup(&["-getsocksfirewallproxy", service]) {
            settings.socks_proxy = self.parse_proxy_output(&out);
        }

        // Auto Proxy URL (PAC)
        if let Ok(out) = self.run_networksetup(&["-getautoproxyurl", service]) {
            settings.auto_proxy_url = self.parse_pac_url(&out);
        }

        // Proxy Bypass Domains
        if let Ok(out) = self.run_networksetup(&["-getproxybypassdomains", service]) {
            settings.bypass_domains = self.parse_bypass_domains(&out);
        }

        Ok(settings)
    }

    fn run_networksetup(&self, args: &[&str]) -> Result<String> {
        let output = std::process::Command::new("networksetup")
            .args(args)
            .output()
            .context("执行 networksetup 失败")?;

        if !output.status.success() {
            anyhow::bail!(
                "networksetup {:?} 返回错误: {}",
                args,
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// 解析 proxy 输出，例如:
    /// Enabled: Yes
    /// Server: 127.0.0.1
    /// Port: 7890
    /// Authenticated Proxy Enabled: 0
    fn parse_proxy_output(&self, text: &str) -> Option<ProxyConfig> {
        let mut enabled = false;
        let mut server = None;
        let mut port = None;

        for line in text.lines() {
            if let Some(v) = line.strip_prefix("Enabled: ") {
                enabled = v.trim().eq_ignore_ascii_case("yes");
            } else if let Some(v) = line.strip_prefix("Server: ") {
                server = Some(v.trim().to_string());
            } else if let Some(v) = line.strip_prefix("Port: ") {
                port = v.trim().parse::<u16>().ok();
            }
        }

        if enabled {
            Some(ProxyConfig {
                enabled,
                server,
                port,
            })
        } else {
            None
        }
    }

    /// 解析 PAC URL 输出，例如:
    /// URL: http://proxy.pac
    /// Enabled: Yes
    fn parse_pac_url(&self, text: &str) -> Option<String> {
        let mut enabled = false;
        let mut url = None;

        for line in text.lines() {
            if let Some(v) = line.strip_prefix("Enabled: ") {
                enabled = v.trim().eq_ignore_ascii_case("yes");
            } else if let Some(v) = line.strip_prefix("URL: ") {
                url = Some(v.trim().to_string());
            }
        }

        if enabled {
            url
        } else {
            None
        }
    }

    /// 解析 bypass domains 输出
    fn parse_bypass_domains(&self, text: &str) -> Vec<String> {
        text.lines()
            .skip(1) // 跳过可能的标题行
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with("There aren't"))
            .collect()
    }

    /// 读取环境变量代理配置
    fn get_env_proxies(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        for key in ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"] {
            if let Ok(val) = std::env::var(key) {
                map.insert(key.to_string(), val);
            }
        }
        map
    }

    /// 分析风险指标
    fn analyze_risks(&self, settings: &[ProxySettings], env_proxies: &HashMap<String, String>) -> Vec<(String, String)> {
        let mut risks = Vec::new();

        for s in settings {
            // 本地 PAC 文件若非用户自行创建，可能存在恶意软件植入嫌疑
            if let Some(ref url) = s.auto_proxy_url
                && url.starts_with("file://")
            {
                let path = url.strip_prefix("file://").unwrap_or(url);
                if std::path::Path::new(path).exists() {
                    risks.push((
                        format!("服务 '{}' 使用本地 PAC 文件: {}", s.service, path),
                        "本地 PAC 文件若非用户自行创建，可能存在恶意软件植入嫌疑".to_string(),
                    ));
                }
            }

            // 绕过规则中若包含公网域名通配符，则属于可疑配置
            for domain in &s.bypass_domains {
                let d = domain.to_lowercase();
                // 标准本地 bypass 规则是正常配置，不做告警
                let is_standard_local = d == "localhost"
                    || d == "127.0.0.1"
                    || d == "::1"
                    || d.ends_with(".local")
                    || d.ends_with(".lan")
                    || d.ends_with(".localhost");

                if !is_standard_local {
                    // 检测公网通配符绕过（如 *.com, *.cn）
                    if d.starts_with("*.") && !d.contains("local") && !d.contains("lan") {
                        risks.push((
                            format!("服务 '{}' 存在公网域名通配符绕过规则: {}", s.service, domain),
                            "公网通配符绕过可能导致大量流量绕过代理，存在数据泄漏风险".to_string(),
                        ));
                    }
                }
            }

            // HTTP 代理启用但 HTTPS 代理未启用：流量分裂风险
            if s.web_proxy.is_some() && s.secure_web_proxy.is_none() {
                risks.push((
                    format!("服务 '{}' 启用了 HTTP 代理但未启用 HTTPS 代理", s.service),
                    "HTTPS 流量可能未经过代理，存在流量分裂和 DNS 泄漏风险".to_string(),
                ));
            }
        }

        // 环境变量代理：仅在同时配置了 HTTP 和 ALL_PROXY（重复/冲突）时告警
        let has_http_env = env_proxies.contains_key("HTTP_PROXY") || env_proxies.contains_key("http_proxy");
        let has_all_env = env_proxies.contains_key("ALL_PROXY") || env_proxies.contains_key("all_proxy");
        if has_http_env && has_all_env {
            risks.push((
                "环境变量中同时配置了 HTTP_PROXY 和 ALL_PROXY".to_string(),
                "代理配置重复可能导致行为不可预期，请检查是否存在冲突".to_string(),
            ));
        }

        risks
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ProxyConfig {
    enabled: bool,
    server: Option<String>,
    port: Option<u16>,
}

#[derive(Debug, Clone)]
struct ProxySettings {
    service: String,
    web_proxy: Option<ProxyConfig>,
    secure_web_proxy: Option<ProxyConfig>,
    socks_proxy: Option<ProxyConfig>,
    auto_proxy_url: Option<String>,
    bypass_domains: Vec<String>,
}

#[async_trait]
impl Probe for SysConfigProbe {
    fn name(&self) -> &'static str {
        "sys_config_audit"
    }

    fn category(&self) -> ProbeCategory {
        ProbeCategory::System
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(10)
    }

    async fn run(&self, _ctx: &ProbeContext) -> Result<Evidence> {
        // 如果不是 macOS，直接跳过
        if !cfg!(target_os = "macos") {
            return Ok(Evidence::builder(self.name())
                .risk_level(RiskLevel::Clean)
                .confidence(1.0)
                .summary("系统配置审计仅支持 macOS，当前平台跳过")
                .detail("platform", std::env::consts::OS)
                .build());
        }

        let services = self.list_network_services()?;
        let mut all_settings = Vec::new();

        for service in &services {
            match self.get_proxy_settings(service) {
                Ok(settings) => {
                    all_settings.push(settings);
                }
                Err(e) => {
                    tracing::warn!(service, error = %e, "failed to get proxy settings");
                }
            }
        }

        let env_proxies = self.get_env_proxies();
        let risks = self.analyze_risks(&all_settings, &env_proxies);

        // 构建详情
        let mut details = EvidenceBuilder::new(self.name());

        let service_details: Vec<_> = all_settings
            .iter()
            .map(|s| {
                json!({
                    "service": &s.service,
                    "web_proxy": s.web_proxy.as_ref().map(|p| json!({"server": p.server, "port": p.port})),
                    "secure_web_proxy": s.secure_web_proxy.as_ref().map(|p| json!({"server": p.server, "port": p.port})),
                    "socks_proxy": s.socks_proxy.as_ref().map(|p| json!({"server": p.server, "port": p.port})),
                    "auto_proxy_url": &s.auto_proxy_url,
                    "bypass_domains": &s.bypass_domains,
                })
            })
            .collect();

        details = details.detail("services", json!(service_details));
        details = details.detail("env_proxies", json!(env_proxies));

        if risks.is_empty() {
            Ok(details
                .risk_level(RiskLevel::Clean)
                .confidence(0.9)
                .summary(format!("系统代理配置正常 ({} 个网络服务已检查)", all_settings.len()))
                .mitigation("无需操作")
                .build())
        } else {
            let summary = format!(
                "发现 {} 项系统代理配置风险 ({} 个网络服务已检查)",
                risks.len(),
                all_settings.len()
            );

            let mut evidence = details
                .risk_level(RiskLevel::Suspicious)
                .confidence(0.8)
                .summary(summary);

            for (risk, mitigation) in &risks {
                evidence = evidence.mitigation(format!("{} — {}", risk, mitigation));
            }

            Ok(evidence.build())
        }
    }
}

impl Default for SysConfigProbe {
    fn default() -> Self {
        Self::new()
    }
}
