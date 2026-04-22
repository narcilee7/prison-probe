use crate::probe::{Evidence, EvidenceBuilder, Probe, ProbeCategory, ProbeContext, RiskLevel};
use crate::store::EvidenceStore;
use anyhow::{Context, Result};
use async_trait::async_trait;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// TLS 证书指纹基线探测器
///
/// 连接目标域名获取 TLS 证书，计算 SHA-256 指纹并与本地基线比对。
/// 如果指纹变化且非证书正常轮换（有效期变化 < 30 天），则告警。
pub struct SSLBaselineProbe {
    domain: String,
    port: u16,
}

impl SSLBaselineProbe {
    pub fn new(domain: impl Into<String>, port: u16) -> Self {
        Self {
            domain: domain.into(),
            port,
        }
    }

    /// 建立 TLS 连接并获取终端实体证书
    async fn fetch_cert(&self, timeout: Duration) -> Result<CertInfo> {
        let addr = format!("{}:{}", self.domain, self.port);

        let stream = tokio::time::timeout(timeout, TcpStream::connect(&addr))
            .await
            .context("TCP 连接超时")?
            .context("TCP 连接失败")?;

        // 确保 rustls crypto provider 已安装
        let _ = rustls::crypto::ring::default_provider().install_default();

        // 使用不验证证书的客户端配置（我们只需要获取证书，不需要信任它）
        let config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(config));
        let server_name = ServerName::try_from(self.domain.clone())
            .map_err(|e| anyhow::anyhow!("无效的服务器名称: {}", e))?;

        let mut tls_stream = tokio::time::timeout(
            timeout,
            connector.connect(server_name, stream),
        )
        .await
        .context("TLS 握手超时")?
        .context("TLS 握手失败")?;

        // 发送简单的 HTTP 请求以完成握手
        let request = format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            self.domain
        );
        tokio::time::timeout(timeout, tls_stream.write_all(request.as_bytes()))
            .await
            .context("发送请求超时")?
            .context("发送请求失败")?;

        let mut buf = [0u8; 1024];
        tokio::time::timeout(timeout, tls_stream.read(&mut buf))
            .await
            .context("读取响应超时")?
            .context("读取响应失败")?;

        // 获取对等证书
        let certs = tls_stream
            .get_ref()
            .1
            .peer_certificates()
            .context("服务器未提供证书")?;

        let end_entity = certs
            .first()
            .context("证书链为空")?;

        let der_bytes: &[u8] = end_entity.as_ref();

        // 计算 SHA-256 指纹
        let fingerprint = crate::report::sha256_hex(der_bytes);

        // 解析证书时间信息
        let (not_before, not_after) = parse_cert_times(der_bytes).unwrap_or((None, None));

        Ok(CertInfo {
            fingerprint,
            not_before,
            not_after,
            pem: cert_to_pem(der_bytes),
        })
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct CertInfo {
    fingerprint: String,
    not_before: Option<String>,
    not_after: Option<String>,
    pem: String,
}

#[async_trait]
impl Probe for SSLBaselineProbe {
    fn name(&self) -> &'static str {
        "ssl_baseline"
    }

    fn category(&self) -> ProbeCategory {
        ProbeCategory::Quick
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(15)
    }

    async fn run(&self, ctx: &ProbeContext) -> Result<Evidence> {
        let domain = if self.domain == "cloudflare.com" {
            &ctx.target_domain
        } else {
            &self.domain
        };
        let port = if self.port == 443 {
            ctx.target_port
        } else {
            self.port
        };

        // 构建临时 probe 用于获取证书
        let target = Self::new(domain, port);
        let cert_info = target.fetch_cert(ctx.timeout).await?;

        // 打开数据库查询基线
        let store = EvidenceStore::open("prison-probe.db").ok();

        let baseline = store.as_ref().and_then(|s| {
            s.get_cert_baseline(domain, port).ok().flatten()
        });

        let details = EvidenceBuilder::new(self.name())
            .detail("domain", domain)
            .detail("port", port)
            .detail("fingerprint", &cert_info.fingerprint)
            .detail("not_before", &cert_info.not_before)
            .detail("not_after", &cert_info.not_after)
            .detail("baseline_exists", baseline.is_some());

        match baseline {
            Some(prev) => {
                if prev.fingerprint == cert_info.fingerprint {
                    // 指纹一致，仅更新 last_seen
                    if let Some(ref s) = store {
                        s.touch_cert_baseline(domain, port).ok();
                    }
                    Ok(details
                        .risk_level(RiskLevel::Clean)
                        .confidence(0.95)
                        .summary(format!(
                            "证书指纹与基线一致 ({})",
                            &cert_info.fingerprint[..16]
                        ))
                        .mitigation("证书未发生变化，连接安全")
                        .build())
                } else {
                    let is_normal_rotation =
                        is_normal_cert_rotation(&prev.not_after, &cert_info.not_before);

                    if is_normal_rotation {
                        // 正常轮换：更新基线
                        if let Some(ref s) = store {
                            s.save_cert_baseline(
                                domain,
                                port,
                                &cert_info.fingerprint,
                                cert_info.not_before.as_deref(),
                                cert_info.not_after.as_deref(),
                            )
                            .ok();
                        }
                        Ok(details
                            .risk_level(RiskLevel::Clean)
                            .confidence(0.8)
                            .summary(format!(
                                "证书已正常轮换 (新指纹: {}...)",
                                &cert_info.fingerprint[..16]
                            ))
                            .detail("previous_fingerprint", &prev.fingerprint)
                            .detail("rotation_detected", true)
                            .mitigation("证书在正常轮换窗口内更新，属于预期行为")
                            .build())
                    } else {
                        // 异常漂移：不覆盖基线，保留原始基线供用户比对
                        Ok(details
                            .risk_level(RiskLevel::Compromised)
                            .confidence(0.92)
                            .summary(format!(
                                "证书基线漂移！指纹发生变化且非预期轮换 ({} -> {})",
                                &prev.fingerprint[..16],
                                &cert_info.fingerprint[..16]
                            ))
                            .detail("previous_fingerprint", &prev.fingerprint)
                            .detail("rotation_detected", false)
                            .detail("baseline_preserved", true)
                            .mitigation("证书指纹异常变化，可能存在中间人攻击或企业 SSL 解密")
                            .mitigation("基线未被覆盖，请手动确认后删除数据库中的旧基线以重新建立")
                            .build())
                    }
                }
            }
            None => {
                // 首次建立基线
                if let Some(ref s) = store {
                    s.save_cert_baseline(
                        domain,
                        port,
                        &cert_info.fingerprint,
                        cert_info.not_before.as_deref(),
                        cert_info.not_after.as_deref(),
                    )
                    .ok();
                }
                Ok(details
                    .risk_level(RiskLevel::Clean)
                    .confidence(0.85)
                    .summary(format!(
                        "首次建立证书基线 ({}...)",
                        &cert_info.fingerprint[..16]
                    ))
                    .mitigation("基线已保存，后续扫描将与此比对")
                    .build())
            }
        }
    }
}

impl Default for SSLBaselineProbe {
    fn default() -> Self {
        Self::new("cloudflare.com", 443)
    }
}

/// 不验证证书（仅用于获取证书本身）
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// 将 DER 证书转换为 PEM 格式
fn cert_to_pem(der: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

/// 从 DER 证书中提取有效时间
fn parse_cert_times(der: &[u8]) -> Result<(Option<String>, Option<String>)> {
    use x509_parser::prelude::*;
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| anyhow::anyhow!("解析 X.509 证书失败: {}", e))?;
    let validity = cert.validity();
    let nb = Some(validity.not_before.to_datetime().to_string());
    let na = Some(validity.not_after.to_datetime().to_string());
    Ok((nb, na))
}

/// 判断是否为正常证书轮换
fn is_normal_cert_rotation(
    prev_not_after: &Option<String>,
    curr_not_before: &Option<String>,
) -> bool {
    let (Some(prev), Some(curr)) = (prev_not_after, curr_not_before) else {
        return false;
    };

    let prev_dt = chrono::DateTime::parse_from_rfc3339(prev)
        .or_else(|_| chrono::DateTime::parse_from_str(prev, "%Y-%m-%d %H:%M:%S%.f %z"))
        .ok();
    let curr_dt = chrono::DateTime::parse_from_rfc3339(curr)
        .or_else(|_| chrono::DateTime::parse_from_str(curr, "%Y-%m-%d %H:%M:%S%.f %z"))
        .ok();

    match (prev_dt, curr_dt) {
        (Some(p), Some(c)) => {
            let diff = (c - p).num_days().abs();
            diff < 30
        }
        _ => false,
    }
}
