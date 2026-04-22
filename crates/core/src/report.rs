//! 报告生成与分数计算工具

use crate::probe::{Evidence, RiskLevel};

/// 根据探测器结果计算隐私健康度评分 (0-100)
pub fn calculate_health_score(results: &[Evidence]) -> u8 {
    if results.is_empty() {
        return 0;
    }

    let mut total_score = 0u32;
    for ev in results {
        let base = match ev.risk_level {
            RiskLevel::Clean => 100u32,
            RiskLevel::Suspicious => 50u32,
            RiskLevel::Compromised => 0u32,
        };
        let weighted = (base as f32 * ev.confidence) as u32;
        total_score += weighted;
    }

    let avg = total_score / results.len() as u32;
    avg.min(100) as u8
}

/// 计算 SHA-256 十六进制字符串
pub fn sha256_hex(data: &[u8]) -> String {
    use std::fmt::Write;
    let hash = ring::digest::digest(&ring::digest::SHA256, data);
    let mut hex = String::with_capacity(64);
    for byte in hash.as_ref() {
        write!(&mut hex, "{:02x}", byte).unwrap();
    }
    hex
}
