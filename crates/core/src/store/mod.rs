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

    /// 保存或更新证书基线
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
