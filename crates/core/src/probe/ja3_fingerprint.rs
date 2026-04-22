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

        // 使用系统根证书验证配置。
        // write_tls() 在此阶段只生成 ClientHello 字节，不会触发服务器证书验证，
        // 但使用正常配置可避免未来误用此 config 进行不安全连接。
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let server_name = ServerName::try_from(self.domain.clone())
            .map_err(|e| anyhow::anyhow!("无效的服务器名称: {}", e))?;

        let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name)
            .context("创建 TLS 连接失败")?;

        // 获取 ClientHello TLS 记录（纯内存操作，无需网络连接）
        let mut buf = Vec::new();
        let n = conn.write_tls(&mut buf)
            .context("获取 TLS 记录失败")?;

        if n == 0 {
            anyhow::bail!("未能生成 ClientHello TLS 记录");
        }

        let ja3_str = parse_ja3_from_tls_records(&buf)?;
        let ja3_hash = md5_hex(&ja3_str);

        Ok((ja3_str, ja3_hash))
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

    async fn run(&self, ctx: &ProbeContext) -> Result<Evidence> {
        let domain = if self.domain == "cloudflare.com" {
            ctx.target_domain.clone()
        } else {
            self.domain.clone()
        };
        let port = if self.port == 443 {
            ctx.target_port
        } else {
            self.port
        };

        let target = Self::new(&domain, port);
        let (ja3_str, ja3_hash) = target.compute_ja3().await?;

        let baseline = load_ja3_baseline(&domain, port);

        let details = EvidenceBuilder::new(self.name())
            .detail("domain", &domain)
            .detail("port", port)
            .detail("ja3_hash", &ja3_hash)
            .detail("ja3_string", &ja3_str)
            .detail("baseline_exists", baseline.is_some());

        match baseline {
            Some(prev) if ja3_equivalent(&prev, &ja3_str) => {
                // 指纹一致，无需更新
                Ok(details
                    .risk_level(RiskLevel::Clean)
                    .confidence(0.92)
                    .summary(format!("JA3 指纹与基线一致 ({})", &ja3_hash[..16]))
                    .mitigation("TLS 握手参数未发生变化")
                    .build())
            }
            Some(prev) => {
                // 指纹漂移：不覆盖基线，保留原始基线供用户比对
                Ok(details
                    .risk_level(RiskLevel::Compromised)
                    .confidence(0.88)
                    .summary(format!(
                        "JA3 指纹基线漂移 ({} -> {})",
                        &md5_hex(&prev)[..16],
                        &ja3_hash[..16]
                    ))
                    .detail("previous_ja3", prev)
                    .detail("baseline_preserved", true)
                    .mitigation("TLS 指纹变化可能是代理层修改了握手参数")
                    .mitigation("也可能是企业级中间盒在进行 SSL 解密")
                    .mitigation("基线未被覆盖，如需更新请手动删除 ja3-baseline 文件后重新扫描")
                    .build())
            }
            None => {
                // 首次建立基线
                save_ja3_baseline(&domain, port, &ja3_str, &ja3_hash);
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


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_grease() {
        assert!(is_grease(0x0a0a));
        assert!(is_grease(0x1a1a));
        assert!(is_grease(0x2a2a));
        assert!(!is_grease(0x0000));
        assert!(!is_grease(0x002f));
        assert!(!is_grease(0x1301));
        assert!(!is_grease(0xff01));
    }

    #[test]
    fn test_md5_hex() {
        let h1 = md5_hex("hello");
        assert_eq!(h1.len(), 32);
        let h2 = md5_hex("hello");
        assert_eq!(h1, h2);
        let h3 = md5_hex("world");
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_parse_ja3_fields() {
        let ja3 = "771,4866-4865-4867,43-51-0,29-23-24,0";
        let (version, ciphers, extensions, groups, formats) =
            parse_ja3_fields(ja3).expect("parse ok");
        assert_eq!(version, 771); // TLS 1.2
        assert_eq!(ciphers, vec![4866, 4865, 4867]);
        assert_eq!(extensions, vec![43, 51, 0]);
        assert_eq!(groups, vec![29, 23, 24]);
        assert_eq!(formats, vec![0]);
    }

    #[test]
    fn test_parse_ja3_fields_empty() {
        let ja3 = "771,,,,";
        let (version, ciphers, extensions, groups, formats) =
            parse_ja3_fields(ja3).expect("parse ok");
        assert_eq!(version, 771);
        assert!(ciphers.is_empty());
        assert!(extensions.is_empty());
        assert!(groups.is_empty());
        assert!(formats.is_empty());
    }

    #[test]
    fn test_ja3_equivalent_same() {
        let a = "771,4866-4865,43-51-0,29-23,0";
        let b = "771,4866-4865,43-51-0,29-23,0";
        assert!(ja3_equivalent(a, b));
    }

    #[test]
    fn test_ja3_equivalent_different_order() {
        let a = "771,4866-4865,43-51-0,29-23,0";
        let b = "771,4866-4865,51-0-43,29-23,0";
        assert!(ja3_equivalent(a, b));
    }

    #[test]
    fn test_ja3_not_equivalent_different_ciphers() {
        let a = "771,4866-4865,43-51-0,29-23,0";
        let b = "771,4866-4867,43-51-0,29-23,0";
        assert!(!ja3_equivalent(a, b));
    }

    #[test]
    fn test_ja3_not_equivalent_different_version() {
        let a = "771,4866-4865,43-51-0,29-23,0";
        let b = "772,4866-4865,43-51-0,29-23,0";
        assert!(!ja3_equivalent(a, b));
    }

    #[test]
    fn test_ja3_baseline_roundtrip() {
        let test_path = ja3_baseline_path("test.example.com", 443);
        let _ = std::fs::remove_file(&test_path);

        // 不存在时返回 None
        assert!(load_ja3_baseline("test.example.com", 443).is_none());

        // 保存并加载
        save_ja3_baseline("test.example.com", 443, "771,4866,43,29,0", "hash1");
        let loaded = load_ja3_baseline("test.example.com", 443);
        assert_eq!(loaded, Some("771,4866,43,29,0".to_string()));

        let _ = std::fs::remove_file(&test_path);
    }
}
