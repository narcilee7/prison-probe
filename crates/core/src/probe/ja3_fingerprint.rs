use crate::probe::{Evidence, EvidenceBuilder, Probe, ProbeCategory, ProbeContext, RiskLevel};
use anyhow::{Context, Result};
use async_trait::async_trait;
use rustls::pki_types::ServerName;
use std::sync::Arc;
use std::time::Duration;

/// JA3 TLS 指纹探测器
///
/// 通过 rustls 生成 ClientHello，手动解析并计算 JA3 指纹（MD5），
/// 与本地保存的基线比对，检测代理层是否修改了 TLS 握手参数。
pub struct JA3FingerprintProbe {
    domain: String,
    port: u16,
}

impl JA3FingerprintProbe {
    pub fn new(domain: impl Into<String>, port: u16) -> Self {
        Self {
            domain: domain.into(),
            port,
        }
    }

    async fn compute_ja3(&self) -> Result<(String, String)> {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let domain = self.domain.clone();
        let port = self.port;

        // 异步解析域名
        let addrs: Vec<_> = tokio::net::lookup_host(format!("{}:{}", domain, port))
            .await
            .with_context(|| format!("域名解析失败: {}", domain))?
            .collect();

        if addrs.is_empty() {
            anyhow::bail!("域名解析无结果: {}", domain);
        }

        tokio::task::spawn_blocking(move || {
            let stream = std::net::TcpStream::connect_timeout(&addrs[0], Duration::from_secs(10))
                .context("TCP 连接失败")?;

            // 使用不验证证书的配置（我们只需要 ClientHello 字节）
            let config = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth();

            let server_name = ServerName::try_from(domain)
                .map_err(|e| anyhow::anyhow!("无效的服务器名称: {}", e))?;

            let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name)
                .context("创建 TLS 连接失败")?;

            // 获取 ClientHello TLS 记录
            let mut buf = Vec::new();
            let n = conn.write_tls(&mut buf)
                .context("获取 TLS 记录失败")?;

            if n == 0 {
                anyhow::bail!("未能生成 ClientHello TLS 记录");
            }

            // 关闭连接（我们只需要 ClientHello，不需要完成握手）
            drop(stream);

            let ja3_str = parse_ja3_from_tls_records(&buf)?;
            let ja3_hash = md5_hex(&ja3_str);

            Ok((ja3_str, ja3_hash))
        }).await?
    }
}

#[async_trait]
impl Probe for JA3FingerprintProbe {
    fn name(&self) -> &'static str {
        "ja3_fingerprint"
    }

    fn category(&self) -> ProbeCategory {
        ProbeCategory::Deep
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(15)
    }

    async fn run(&self, _ctx: &ProbeContext) -> Result<Evidence> {
        let (ja3_str, ja3_hash) = self.compute_ja3().await?;

        let baseline = load_ja3_baseline(&self.domain, self.port);
        save_ja3_baseline(&self.domain, self.port, &ja3_str, &ja3_hash);

        let details = EvidenceBuilder::new(self.name())
            .detail("domain", &self.domain)
            .detail("port", self.port)
            .detail("ja3_hash", &ja3_hash)
            .detail("ja3_string", &ja3_str)
            .detail("baseline_exists", baseline.is_some());

        match baseline {
            Some(prev) if ja3_equivalent(&prev, &ja3_str) => {
                Ok(details
                    .risk_level(RiskLevel::Clean)
                    .confidence(0.92)
                    .summary(format!("JA3 指纹与基线一致 ({})", &ja3_hash[..16]))
                    .mitigation("TLS 握手参数未发生变化")
                    .build())
            }
            Some(prev) => {
                Ok(details
                    .risk_level(RiskLevel::Compromised)
                    .confidence(0.88)
                    .summary(format!(
                        "JA3 指纹基线漂移 ({} -> {})",
                        &md5_hex(&prev)[..16],
                        &ja3_hash[..16]
                    ))
                    .detail("previous_ja3", prev)
                    .mitigation("TLS 指纹变化可能是代理层修改了握手参数")
                    .mitigation("也可能是企业级中间盒在进行 SSL 解密")
                    .build())
            }
            None => {
                Ok(details
                    .risk_level(RiskLevel::Clean)
                    .confidence(0.85)
                    .summary(format!("首次建立 JA3 指纹基线 ({})", &ja3_hash[..16]))
                    .mitigation("基线已保存，后续扫描将与此比对")
                    .build())
            }
        }
    }
}

impl Default for JA3FingerprintProbe {
    fn default() -> Self {
        Self::new("cloudflare.com", 443)
    }
}

// ---------------------------------------------------------------------------
// TLS ClientHello 手动解析器
// ---------------------------------------------------------------------------

/// 从 TLS 记录序列中查找并解析 ClientHello，计算 JA3 字符串
fn parse_ja3_from_tls_records(records: &[u8]) -> Result<String> {
    let mut offset = 0;
    while offset + 5 <= records.len() {
        let content_type = records[offset];
        let record_len = u16::from_be_bytes([records[offset + 3], records[offset + 4]]) as usize;

        if content_type == 0x16 {
            // Handshake record
            let handshake_start = offset + 5;
            let handshake_end = handshake_start + record_len;
            if handshake_end <= records.len() && handshake_start + 4 <= records.len() {
                let handshake = &records[handshake_start..handshake_end];
                if handshake.len() >= 4 && handshake[0] == 0x01 {
                    let handshake_len = u32::from_be_bytes([0, handshake[1], handshake[2], handshake[3]]) as usize;
                    if 4 + handshake_len <= handshake.len() {
                        return parse_client_hello(&handshake[4..4 + handshake_len]);
                    }
                }
            }
        }

        offset += 5 + record_len;
    }

    anyhow::bail!("TLS 记录中未找到 ClientHello")
}

/// 解析 ClientHello 数据，生成 JA3 字符串
/// 格式: TLSVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats
fn parse_client_hello(ch: &[u8]) -> Result<String> {
    let mut offset = 0;

    // Client Version (2 bytes)
    if ch.len() < offset + 2 {
        anyhow::bail!("ClientHello 过短：version");
    }
    let version = u16::from_be_bytes([ch[offset], ch[offset + 1]]);
    offset += 2;

    // Random (32 bytes)
    if ch.len() < offset + 32 {
        anyhow::bail!("ClientHello 过短：random");
    }
    offset += 32;

    // Session ID Length (1 byte)
    if ch.len() < offset + 1 {
        anyhow::bail!("ClientHello 过短：session ID length");
    }
    let session_id_len = ch[offset] as usize;
    offset += 1;
    if ch.len() < offset + session_id_len {
        anyhow::bail!("ClientHello 过短：session ID");
    }
    offset += session_id_len;

    // Cipher Suites Length (2 bytes)
    if ch.len() < offset + 2 {
        anyhow::bail!("ClientHello 过短：cipher suites length");
    }
    let cipher_suites_len = u16::from_be_bytes([ch[offset], ch[offset + 1]]) as usize;
    offset += 2;
    if ch.len() < offset + cipher_suites_len || cipher_suites_len % 2 != 0 {
        anyhow::bail!("ClientHello 无效的 cipher suites 长度");
    }
    let mut ciphers = Vec::new();
    for i in (0..cipher_suites_len).step_by(2) {
        let cipher = u16::from_be_bytes([ch[offset + i], ch[offset + i + 1]]);
        if !is_grease(cipher) {
            ciphers.push(cipher);
        }
    }
    offset += cipher_suites_len;

    // Compression Methods Length (1 byte)
    if ch.len() < offset + 1 {
        anyhow::bail!("ClientHello 过短：compression length");
    }
    let compression_len = ch[offset] as usize;
    offset += 1;
    if ch.len() < offset + compression_len {
        anyhow::bail!("ClientHello 过短：compression methods");
    }
    offset += compression_len;

    // Extensions
    if ch.len() < offset + 2 {
        // 无扩展
        let ja3 = format!(
            "{},{}-,,,",
            version,
            ciphers.iter().map(|c| c.to_string()).collect::<Vec<_>>().join("-")
        );
        return Ok(ja3);
    }

    let extensions_len = u16::from_be_bytes([ch[offset], ch[offset + 1]]) as usize;
    offset += 2;
    if ch.len() < offset + extensions_len {
        anyhow::bail!("ClientHello 过短：extensions");
    }
    let extensions_data = &ch[offset..offset + extensions_len];

    let mut ext_types = Vec::new();
    let mut supported_groups = Vec::new();
    let mut ec_point_formats = Vec::new();

    let mut ext_offset = 0;
    while ext_offset + 4 <= extensions_data.len() {
        let ext_type =
            u16::from_be_bytes([extensions_data[ext_offset], extensions_data[ext_offset + 1]]);
        let ext_len = u16::from_be_bytes([
            extensions_data[ext_offset + 2],
            extensions_data[ext_offset + 3],
        ]) as usize;
        ext_offset += 4;

        if ext_offset + ext_len > extensions_data.len() {
            break;
        }

        let ext_data = &extensions_data[ext_offset..ext_offset + ext_len];

        if !is_grease(ext_type) {
            ext_types.push(ext_type);

            // Supported Groups (0x000a)
            if ext_type == 0x000a && ext_len >= 2 {
                let groups_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                for i in (0..groups_len).step_by(2) {
                    if 2 + i + 2 <= ext_data.len() {
                        let group = u16::from_be_bytes([ext_data[2 + i], ext_data[2 + i + 1]]);
                        if !is_grease(group) {
                            supported_groups.push(group);
                        }
                    }
                }
            }

            // EC Point Formats (0x000b)
            if ext_type == 0x000b && ext_len >= 1 {
                let formats_len = ext_data[0] as usize;
                for i in 0..formats_len {
                    if 1 + i < ext_data.len() {
                        ec_point_formats.push(ext_data[1 + i] as u16);
                    }
                }
            }
        }

        ext_offset += ext_len;
    }

    let ja3 = format!(
        "{},{},{},{},{}",
        version,
        ciphers.iter().map(|c| c.to_string()).collect::<Vec<_>>().join("-"),
        ext_types.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("-"),
        supported_groups.iter().map(|g| g.to_string()).collect::<Vec<_>>().join("-"),
        ec_point_formats.iter().map(|f| f.to_string()).collect::<Vec<_>>().join("-"),
    );

    Ok(ja3)
}

/// GREASE (Generate Random Extensions And Sustain Extensibility) 检测
/// GREASE 值：高字节 == 低字节，且低字节低 4 位 == 0x0A
fn is_grease(val: u16) -> bool {
    let high = (val >> 8) as u8;
    let low = (val & 0xFF) as u8;
    high == low && (low & 0x0F) == 0x0A
}

/// MD5 哈希，返回小写十六进制字符串
fn md5_hex(input: &str) -> String {
    use md5::{Digest, Md5};
    let mut hasher = Md5::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// 基线文件存储（简化版，使用本地文件替代数据库）
// ---------------------------------------------------------------------------

fn ja3_baseline_path(domain: &str, port: u16) -> String {
    format!(
        "ja3-baseline-{}-{}.txt",
        domain.replace('.', "_"),
        port
    )
}

fn load_ja3_baseline(domain: &str, port: u16) -> Option<String> {
    std::fs::read_to_string(ja3_baseline_path(domain, port)).ok()
}

fn save_ja3_baseline(domain: &str, port: u16, ja3_str: &str, _ja3_hash: &str) {
    let _ = std::fs::write(ja3_baseline_path(domain, port), ja3_str);
}

/// 解析 JA3 字符串为字段元组
fn parse_ja3_fields(ja3: &str) -> Option<(u16, Vec<u16>, Vec<u16>, Vec<u16>, Vec<u16>)> {
    let parts: Vec<&str> = ja3.split(',').collect();
    if parts.len() != 5 {
        return None;
    }
    let version = parts[0].parse().ok()?;
    let ciphers = parts[1].split('-').filter(|s| !s.is_empty()).filter_map(|s| s.parse().ok()).collect();
    let extensions = parts[2].split('-').filter(|s| !s.is_empty()).filter_map(|s| s.parse().ok()).collect();
    let groups = parts[3].split('-').filter(|s| !s.is_empty()).filter_map(|s| s.parse().ok()).collect();
    let formats = parts[4].split('-').filter(|s| !s.is_empty()).filter_map(|s| s.parse().ok()).collect();
    Some((version, ciphers, extensions, groups, formats))
}

/// 判断两个 JA3 字符串是否等价（忽略 Extensions 顺序差异）
fn ja3_equivalent(a: &str, b: &str) -> bool {
    let (va, ca, ea, ga, fa) = match parse_ja3_fields(a) {
        Some(x) => x,
        None => return false,
    };
    let (vb, cb, eb, gb, fb) = match parse_ja3_fields(b) {
        Some(x) => x,
        None => return false,
    };

    if va != vb || ca != cb || ga != gb || fa != fb {
        return false;
    }

    let mut ea_sorted = ea;
    ea_sorted.sort();
    let mut eb_sorted = eb;
    eb_sorted.sort();
    ea_sorted == eb_sorted
}

/// 不验证证书（仅用于获取 ClientHello 字节）
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
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
