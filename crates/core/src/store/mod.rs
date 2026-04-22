use crate::probe::Evidence;
use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use std::path::Path;

/// 证据存储
pub struct EvidenceStore {
    conn: Connection,
}

impl EvidenceStore {
    /// 打开或创建存储数据库
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path).context("打开 SQLite 数据库失败")?;

        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS scan_history (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT NOT NULL DEFAULT (datetime('now')),
                probe_name  TEXT NOT NULL,
                risk_level  TEXT NOT NULL,
                confidence  REAL NOT NULL,
                summary     TEXT NOT NULL,
                details     TEXT,  -- JSON
                mitigations TEXT,  -- JSON array
                raw_bytes   BLOB   -- 原始证据（可选）
            );

            CREATE INDEX IF NOT EXISTS idx_scan_history_time 
                ON scan_history(timestamp);
            CREATE INDEX IF NOT EXISTS idx_scan_history_probe 
                ON scan_history(probe_name);
            CREATE INDEX IF NOT EXISTS idx_scan_history_risk 
                ON scan_history(risk_level);

            CREATE TABLE IF NOT EXISTS cert_baseline (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                domain      TEXT NOT NULL,
                port        INTEGER NOT NULL DEFAULT 443,
                fingerprint TEXT NOT NULL,
                not_before  TEXT,
                not_after   TEXT,
                first_seen  TEXT NOT NULL DEFAULT (datetime('now')),
                last_seen   TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(domain, port)
            );

            CREATE INDEX IF NOT EXISTS idx_cert_baseline_domain 
                ON cert_baseline(domain);
            "#,
        )
        .context("初始化数据库表失败")?;

        Ok(Self { conn })
    }

    /// 保存探测结果
    pub fn save_evidence(&self, evidence: &Evidence) -> Result<i64> {
        let details = serde_json::to_string(&evidence.technical_details)
            .unwrap_or_else(|_| "{}".to_string());
        let mitigations = serde_json::to_string(&evidence.mitigations)
            .unwrap_or_else(|_| "[]".to_string());
        let timestamp = evidence.timestamp.to_rfc3339();

        self.conn.execute(
            r#"
            INSERT INTO scan_history 
                (timestamp, probe_name, risk_level, confidence, summary, details, mitigations, raw_bytes)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                timestamp,
                evidence.probe_name,
                evidence.risk_level.as_str(),
                evidence.confidence,
                evidence.summary,
                details,
                mitigations,
                evidence.raw_bytes.as_ref(),
            ],
        ).context("保存证据到数据库失败")?;

        Ok(self.conn.last_insert_rowid())
    }

    /// 查询最近的扫描历史
    pub fn recent_scans(&self, limit: usize) -> Result<Vec<ScanRecord>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT timestamp, probe_name, risk_level, confidence, summary
            FROM scan_history
            ORDER BY timestamp DESC
            LIMIT ?1
            "#,
        )?;

        let rows = stmt.query_map([limit], |row| {
            Ok(ScanRecord {
                timestamp: row.get(0)?,
                probe_name: row.get(1)?,
                risk_level: row.get(2)?,
                confidence: row.get(3)?,
                summary: row.get(4)?,
            })
        })?;

        let mut records = Vec::new();
        for row in rows {
            records.push(row?);
        }

        Ok(records)
    }

    /// 获取统计数据
    pub fn stats(&self) -> Result<StoreStats> {
        let total: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM scan_history", [], |row| row.get(0))
            .unwrap_or(0);

        let clean: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM scan_history WHERE risk_level = 'Clean'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);

        let suspicious: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM scan_history WHERE risk_level = 'Suspicious'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);

        let compromised: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM scan_history WHERE risk_level = 'Compromised'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);

        Ok(StoreStats {
            total_scans: total,
            clean,
            suspicious,
            compromised,
        })
    }

    /// 查询证书基线
    pub fn get_cert_baseline(&self, domain: &str, port: u16) -> Result<Option<CertBaseline>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT fingerprint, not_before, not_after, first_seen, last_seen
            FROM cert_baseline
            WHERE domain = ?1 AND port = ?2
            "#,
        )?;

        let mut rows = stmt.query_map(params![domain, port], |row| {
            Ok(CertBaseline {
                fingerprint: row.get(0)?,
                not_before: row.get(1)?,
                not_after: row.get(2)?,
                first_seen: row.get(3)?,
                last_seen: row.get(4)?,
            })
        })?;

        Ok(rows.next().transpose()?)
    }

    /// 保存或更新证书基线（首次建立或正常轮换时调用）
    pub fn save_cert_baseline(
        &self,
        domain: &str,
        port: u16,
        fingerprint: &str,
        not_before: Option<&str>,
        not_after: Option<&str>,
    ) -> Result<()> {
        self.conn.execute(
            r#"
            INSERT INTO cert_baseline (domain, port, fingerprint, not_before, not_after, first_seen, last_seen)
            VALUES (?1, ?2, ?3, ?4, ?5, datetime('now'), datetime('now'))
            ON CONFLICT(domain, port) DO UPDATE SET
                fingerprint = excluded.fingerprint,
                not_before = excluded.not_before,
                not_after = excluded.not_after,
                last_seen = datetime('now')
            "#,
            params![domain, port, fingerprint, not_before, not_after],
        ).context("保存证书基线失败")?;

        Ok(())
    }

    /// 仅更新证书基线的 last_seen 时间（指纹未变化时调用）
    pub fn touch_cert_baseline(&self, domain: &str, port: u16) -> Result<()> {
        self.conn.execute(
            r#"
            UPDATE cert_baseline
            SET last_seen = datetime('now')
            WHERE domain = ?1 AND port = ?2
            "#,
            params![domain, port],
        ).context("更新证书基线时间失败")?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct ScanRecord {
    pub timestamp: String,
    pub probe_name: String,
    pub risk_level: String,
    pub confidence: f64,
    pub summary: String,
}

#[derive(Debug, Clone)]
pub struct CertBaseline {
    pub fingerprint: String,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub first_seen: String,
    pub last_seen: String,
}

#[derive(Debug)]
pub struct StoreStats {
    pub total_scans: i64,
    pub clean: i64,
    pub suspicious: i64,
    pub compromised: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::{Evidence, RiskLevel};
    use std::path::PathBuf;

    fn temp_db_path() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "prison-probe-test-{}-{}.db",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        path
    }

    fn cleanup(path: &Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
    }

    #[test]
    fn test_open_and_init() {
        let path = temp_db_path();
        let store = EvidenceStore::open(&path);
        assert!(store.is_ok());
        cleanup(&path);
    }

    #[test]
    fn test_save_and_recent_scans() {
        let path = temp_db_path();
        let store = EvidenceStore::open(&path).unwrap();

        let ev = Evidence::builder("test_probe")
            .risk_level(RiskLevel::Clean)
            .confidence(0.95)
            .summary("All good")
            .detail("ip", "1.1.1.1")
            .mitigation("None needed")
            .build();

        let id = store.save_evidence(&ev).unwrap();
        assert!(id > 0);

        let scans = store.recent_scans(10).unwrap();
        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0].probe_name, "test_probe");
        assert_eq!(scans[0].risk_level, "Clean");
        cleanup(&path);
    }

    #[test]
    fn test_stats() {
        let path = temp_db_path();
        let store = EvidenceStore::open(&path).unwrap();

        let ev1 = Evidence::builder("p1").risk_level(RiskLevel::Clean).confidence(1.0).summary("s1").build();
        let ev2 = Evidence::builder("p2").risk_level(RiskLevel::Suspicious).confidence(0.8).summary("s2").build();
        let ev3 = Evidence::builder("p3").risk_level(RiskLevel::Compromised).confidence(0.9).summary("s3").build();

        store.save_evidence(&ev1).unwrap();
        store.save_evidence(&ev2).unwrap();
        store.save_evidence(&ev3).unwrap();

        let stats = store.stats().unwrap();
        assert_eq!(stats.total_scans, 3);
        assert_eq!(stats.clean, 1);
        assert_eq!(stats.suspicious, 1);
        assert_eq!(stats.compromised, 1);
        cleanup(&path);
    }

    #[test]
    fn test_cert_baseline_crud() {
        let path = temp_db_path();
        let store = EvidenceStore::open(&path).unwrap();

        // 首次保存
        store.save_cert_baseline("example.com", 443, "abc123", Some("2024-01-01"), Some("2025-01-01")).unwrap();

        // 查询
        let baseline = store.get_cert_baseline("example.com", 443).unwrap();
        assert!(baseline.is_some());
        let b = baseline.unwrap();
        assert_eq!(b.fingerprint, "abc123");
        assert_eq!(b.not_before, Some("2024-01-01".to_string()));
        assert_eq!(b.not_after, Some("2025-01-01".to_string()));

        // 更新
        store.save_cert_baseline("example.com", 443, "def456", None, None).unwrap();
        let updated = store.get_cert_baseline("example.com", 443).unwrap().unwrap();
        assert_eq!(updated.fingerprint, "def456");

        // 不存在的记录
        let missing = store.get_cert_baseline("notexist.com", 443).unwrap();
        assert!(missing.is_none());
        cleanup(&path);
    }
}
