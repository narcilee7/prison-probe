use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

pub mod dns_leak;
pub mod exit_ip;
pub mod ja3_fingerprint;
pub mod ssl_baseline;
pub mod stun;
pub mod sys_config;
pub mod webrtc_leak;

/// 风险等级
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    Clean,
    Suspicious,
    Compromised,
}

impl RiskLevel {
    pub fn emoji(&self) -> &'static str {
        match self {
            RiskLevel::Clean => "✓",
            RiskLevel::Suspicious => "⚠️",
            RiskLevel::Compromised => "✗",
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Clean => "Clean",
            RiskLevel::Suspicious => "Suspicious",
            RiskLevel::Compromised => "Compromised",
        }
    }
}

/// 探测器分类
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeCategory {
    Quick,
    Deep,
    System,
}

/// 探测器上下文
#[derive(Debug, Clone)]
pub struct ProbeContext {
    pub timeout: Duration,
    pub proxy_url: Option<String>,
    /// SSL/JA3 探测的目标域名，默认为 cloudflare.com
    pub target_domain: String,
    /// SSL/JA3 探测的目标端口，默认为 443
    pub target_port: u16,
}

impl Default for ProbeContext {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            proxy_url: None,
            target_domain: "cloudflare.com".to_string(),
            target_port: 443,
        }
    }
}

/// 证据结构（可序列化存储）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub probe_name: String,
    pub timestamp: DateTime<Utc>,
    pub risk_level: RiskLevel,
    pub confidence: f32,
    pub summary: String,
    pub technical_details: HashMap<String, serde_json::Value>,
    pub raw_bytes: Option<Vec<u8>>,
    pub mitigations: Vec<String>,
}

impl Evidence {
    pub fn builder(probe_name: &str) -> EvidenceBuilder {
        EvidenceBuilder::new(probe_name)
    }
}

pub struct EvidenceBuilder {
    probe_name: String,
    risk_level: RiskLevel,
    confidence: f32,
    summary: String,
    technical_details: HashMap<String, serde_json::Value>,
    raw_bytes: Option<Vec<u8>>,
    mitigations: Vec<String>,
}

impl EvidenceBuilder {
    pub fn new(probe_name: &str) -> Self {
        Self {
            probe_name: probe_name.to_string(),
            risk_level: RiskLevel::Clean,
            confidence: 1.0,
            summary: String::new(),
            technical_details: HashMap::new(),
            raw_bytes: None,
            mitigations: Vec::new(),
        }
    }

    pub fn risk_level(mut self, level: RiskLevel) -> Self {
        self.risk_level = level;
        self
    }

    pub fn confidence(mut self, c: f32) -> Self {
        self.confidence = c.clamp(0.0, 1.0);
        self
    }

    pub fn summary(mut self, s: impl Into<String>) -> Self {
        self.summary = s.into();
        self
    }

    pub fn detail(mut self, key: impl Into<String>, value: impl Serialize) -> Self {
        let key = key.into();
        match serde_json::to_value(value) {
            Ok(v) => {
                self.technical_details.insert(key, v);
            }
            Err(e) => {
                self.technical_details
                    .insert(key, serde_json::Value::String(format!("<serialize error: {}>", e)));
            }
        }
        self
    }

    pub fn raw_bytes(mut self, bytes: Vec<u8>) -> Self {
        self.raw_bytes = Some(bytes);
        self
    }

    pub fn mitigation(mut self, m: impl Into<String>) -> Self {
        self.mitigations.push(m.into());
        self
    }

    pub fn build(self) -> Evidence {
        Evidence {
            probe_name: self.probe_name,
            timestamp: Utc::now(),
            risk_level: self.risk_level,
            confidence: self.confidence,
            summary: self.summary,
            technical_details: self.technical_details,
            raw_bytes: self.raw_bytes,
            mitigations: self.mitigations,
        }
    }
}

/// 探测器统一接口
#[async_trait::async_trait]
pub trait Probe: Send + Sync {
    fn name(&self) -> &'static str;
    fn category(&self) -> ProbeCategory;
    fn timeout(&self) -> Duration;

    async fn run(&self, ctx: &ProbeContext) -> Result<Evidence>;
}

/// 探测器套件
pub struct ProbeSuite {
    probes: Vec<Box<dyn Probe>>,
}

impl ProbeSuite {
    pub fn quick_suite() -> Self {
        Self {
            probes: vec![
                Box::new(exit_ip::ExitIPConsistencyProbe::new()),
                Box::new(dns_leak::DNSLeakProbe::new()),
                Box::new(ssl_baseline::SSLBaselineProbe::default()),
                Box::new(webrtc_leak::WebRTCLeakProbe::new()),
                Box::new(sys_config::SysConfigProbe::new()),
            ],
        }
    }

    pub fn deep_suite() -> Self {
        Self {
            probes: vec![
                Box::new(ja3_fingerprint::JA3FingerprintProbe::default()),
            ],
        }
    }

    pub fn add(&mut self, probe: Box<dyn Probe>) {
        self.probes.push(probe);
    }

    pub async fn execute(&self, ctx: &ProbeContext) -> Vec<Evidence> {
        use futures::future::join_all;

        let futures = self.probes.iter().map(|probe| {
            let name = probe.name();
            let timeout = probe.timeout();
            let probe_ctx = ProbeContext { timeout, ..ctx.clone() };

            async move {
                let result = tokio::time::timeout(timeout, probe.run(&probe_ctx)).await;

                match result {
                    Ok(Ok(evidence)) => {
                        tracing::info!(probe = name, risk = ?evidence.risk_level, "probe completed");
                        evidence
                    }
                    Ok(Err(e)) => {
                        tracing::error!(probe = name, error = %e, "probe failed");
                        Evidence::builder(name)
                            .risk_level(RiskLevel::Suspicious)
                            .confidence(0.5)
                            .summary(format!("探测器执行失败: {}", e))
                            .detail("error", e.to_string())
                            .mitigation("请检查网络连接并重新运行扫描")
                            .build()
                    }
                    Err(_) => {
                        tracing::warn!(probe = name, "probe timed out");
                        Evidence::builder(name)
                            .risk_level(RiskLevel::Suspicious)
                            .confidence(0.5)
                            .summary(format!("探测器超时 (>{:?})", timeout))
                            .mitigation("请检查网络连接或稍后重试")
                            .build()
                    }
                }
            }
        });

        join_all(futures).await
    }

    pub fn len(&self) -> usize {
        self.probes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.probes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_level_as_str() {
        assert_eq!(RiskLevel::Clean.as_str(), "Clean");
        assert_eq!(RiskLevel::Suspicious.as_str(), "Suspicious");
        assert_eq!(RiskLevel::Compromised.as_str(), "Compromised");
    }

    #[test]
    fn test_risk_level_emoji() {
        assert_eq!(RiskLevel::Clean.emoji(), "✓");
        assert_eq!(RiskLevel::Suspicious.emoji(), "⚠️");
        assert_eq!(RiskLevel::Compromised.emoji(), "✗");
    }

    #[test]
    fn test_evidence_builder_defaults() {
        let ev = Evidence::builder("test_probe").build();
        assert_eq!(ev.probe_name, "test_probe");
        assert_eq!(ev.risk_level, RiskLevel::Clean);
        assert_eq!(ev.confidence, 1.0);
        assert!(ev.summary.is_empty());
        assert!(ev.technical_details.is_empty());
        assert!(ev.raw_bytes.is_none());
        assert!(ev.mitigations.is_empty());
    }

    #[test]
    fn test_evidence_builder_chaining() {
        let ev = Evidence::builder("my_probe")
            .risk_level(RiskLevel::Compromised)
            .confidence(0.95)
            .summary("DNS leak detected")
            .detail("ip", "192.168.1.1")
            .detail("count", 3)
            .mitigation("Use DoH")
            .mitigation("Check VPN")
            .build();

        assert_eq!(ev.probe_name, "my_probe");
        assert_eq!(ev.risk_level, RiskLevel::Compromised);
        assert_eq!(ev.confidence, 0.95);
        assert_eq!(ev.summary, "DNS leak detected");
        assert_eq!(ev.technical_details.get("ip").unwrap(), "192.168.1.1");
        assert_eq!(ev.technical_details.get("count").unwrap(), 3);
        assert_eq!(ev.mitigations.len(), 2);
        assert_eq!(ev.mitigations[0], "Use DoH");
        assert_eq!(ev.mitigations[1], "Check VPN");
    }

    #[test]
    fn test_evidence_builder_confidence_clamping() {
        let ev_high = Evidence::builder("t").confidence(1.5).build();
        assert_eq!(ev_high.confidence, 1.0);

        let ev_low = Evidence::builder("t").confidence(-0.5).build();
        assert_eq!(ev_low.confidence, 0.0);
    }

    #[test]
    fn test_evidence_serialization() {
        let ev = Evidence::builder("ser_test")
            .risk_level(RiskLevel::Suspicious)
            .confidence(0.75)
            .summary("test")
            .detail("key", "value")
            .build();

        let json = serde_json::to_string(&ev).expect("serialize");
        assert!(json.contains("\"probe_name\":\"ser_test\""));
        assert!(json.contains("\"risk_level\":\"Suspicious\""));
        assert!(json.contains("\"confidence\":0.75"));
        assert!(json.contains("\"summary\":\"test\""));
    }

    #[test]
    fn test_probe_context_clone() {
        let ctx = ProbeContext {
            timeout: Duration::from_secs(5),
            proxy_url: Some("http://127.0.0.1:7890".to_string()),
            target_domain: "example.com".to_string(),
            target_port: 8443,
        };
        let cloned = ctx.clone();
        assert_eq!(cloned.timeout, ctx.timeout);
        assert_eq!(cloned.proxy_url, ctx.proxy_url);
        assert_eq!(cloned.target_domain, ctx.target_domain);
        assert_eq!(cloned.target_port, ctx.target_port);
    }

    #[test]
    fn test_probe_context_default() {
        let ctx = ProbeContext::default();
        assert_eq!(ctx.timeout, Duration::from_secs(10));
        assert!(ctx.proxy_url.is_none());
        assert_eq!(ctx.target_domain, "cloudflare.com");
        assert_eq!(ctx.target_port, 443);
    }

    #[test]
    fn test_probe_suite_quick_len() {
        let suite = ProbeSuite::quick_suite();
        assert_eq!(suite.len(), 5);
        assert!(!suite.is_empty());
    }

    #[test]
    fn test_probe_suite_deep_len() {
        let suite = ProbeSuite::deep_suite();
        assert_eq!(suite.len(), 1);
        assert!(!suite.is_empty());
    }

    #[test]
    fn test_probe_suite_add() {
        let mut suite = ProbeSuite::quick_suite();
        let original_len = suite.len();
        suite.add(Box::new(crate::probe::ja3_fingerprint::JA3FingerprintProbe::default()));
        assert_eq!(suite.len(), original_len + 1);
    }
}
