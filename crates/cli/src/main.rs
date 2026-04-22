mod cli;

use anyhow::{Context, Result};
use clap::Parser;
use crate::cli::{Cli, Commands, OutputFormat};
use prison_probe_core::probe::{ProbeContext, ProbeSuite, RiskLevel};
use prison_probe_core::report::{calculate_health_score, sha256_hex};
use prison_probe_core::store::EvidenceStore;
use serde_json::json;
use std::io::{self, Write};
use std::time::Duration;
use tabled::{Table, Tabled, settings::Style};

#[derive(Tabled)]
struct EvidenceRow {
    #[tabled(rename = "状态")]
    status: String,
    #[tabled(rename = "探测器")]
    probe: String,
    #[tabled(rename = "风险等级")]
    risk: String,
    #[tabled(rename = "置信度")]
    confidence: String,
    #[tabled(rename = "摘要")]
    summary: String,
}

#[derive(Tabled)]
struct HistoryRow {
    #[tabled(rename = "时间")]
    timestamp: String,
    #[tabled(rename = "探测器")]
    probe: String,
    #[tabled(rename = "风险")]
    risk: String,
    #[tabled(rename = "摘要")]
    summary: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    // 初始化日志
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_target(false)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Quick => run_quick_scan(&cli).await,
        Commands::Deep => run_deep_scan(&cli).await,
        Commands::Export { ref output } => run_export(&cli, output).await,
        Commands::History { limit } => show_history(&cli, limit).await,
        Commands::Stats => show_stats(&cli).await,
    }
}

async fn run_quick_scan(cli: &Cli) -> Result<()> {
    println!("🔍 启动快速体征扫描...\n");

    let ctx = ProbeContext {
        timeout: Duration::from_secs(15),
        proxy_url: std::env::var("HTTP_PROXY").ok(),
        target_domain: cli.target_domain.clone(),
        target_port: cli.target_port,
    };

    let suite = ProbeSuite::quick_suite();
    let start = std::time::Instant::now();
    let results = suite.execute(&ctx).await;
    let elapsed = start.elapsed();

    // 保存结果
    let store = EvidenceStore::open(&cli.db)
        .with_context(|| format!("打开数据库 {} 失败", cli.db))?;

    for evidence in &results {
        store.save_evidence(evidence).ok();
    }

    // 计算健康度评分
    let score = calculate_health_score(&results);

    // 输出结果
    match cli.format {
        OutputFormat::Json => {
            let output = json!({
                "elapsed_ms": elapsed.as_millis(),
                "health_score": score,
                "results": results,
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        OutputFormat::Table => {
            println!("⏱️  扫描耗时: {:.2}s\n", elapsed.as_secs_f64());
            println!("隐私健康度: {}/100", score);
            print_health_bar(score);
            println!();

            let mut rows = Vec::new();
            let mut issue_count = 0;

            for ev in &results {
                let status = match ev.risk_level {
                    RiskLevel::Clean => "✓".to_string(),
                    RiskLevel::Suspicious => "⚠️ ".to_string(),
                    RiskLevel::Compromised => "✗".to_string(),
                };

                if ev.risk_level != RiskLevel::Clean {
                    issue_count += 1;
                }

                rows.push(EvidenceRow {
                    status,
                    probe: ev.probe_name.clone(),
                    risk: ev.risk_level.as_str().to_string(),
                    confidence: format!("{:.0}%", ev.confidence * 100.0),
                    summary: ev.summary.clone(),
                });
            }

            if !rows.is_empty() {
                let table = Table::new(rows).with(Style::modern_rounded()).to_string();
                println!("{}", table);
            }

            println!();
            if issue_count > 0 {
                println!("⚠️  发现 {} 项异常", issue_count);
                for ev in &results {
                    if ev.risk_level != RiskLevel::Clean {
                        println!("  • {}: {}", ev.probe_name, ev.summary);
                        for m in &ev.mitigations {
                            println!("    ↳ {}", m);
                        }
                    }
                }
            } else {
                println!("✓ 所有指标正常，网络隐私状态良好");
            }
        }
    }

    Ok(())
}

async fn run_deep_scan(cli: &Cli) -> Result<()> {
    println!("🔬 启动深度信道审计...\n");

    let ctx = ProbeContext {
        timeout: Duration::from_secs(20),
        proxy_url: std::env::var("HTTP_PROXY").ok(),
        target_domain: cli.target_domain.clone(),
        target_port: cli.target_port,
    };

    let suite = ProbeSuite::deep_suite();
    let start = std::time::Instant::now();
    let results = suite.execute(&ctx).await;
    let elapsed = start.elapsed();

    let store = EvidenceStore::open(&cli.db)
        .with_context(|| format!("打开数据库 {} 失败", cli.db))?;

    for evidence in &results {
        store.save_evidence(evidence).ok();
    }

    let score = calculate_health_score(&results);

    match cli.format {
        OutputFormat::Json => {
            let output = json!({
                "scan_type": "deep",
                "elapsed_ms": elapsed.as_millis(),
                "health_score": score,
                "results": results,
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        OutputFormat::Table => {
            println!("⏱️  深度审计耗时: {:.2}s\n", elapsed.as_secs_f64());
            println!("隐私健康度: {}/100", score);
            print_health_bar(score);
            println!();

            let mut rows = Vec::new();
            let mut issue_count = 0;

            for ev in &results {
                let status = match ev.risk_level {
                    RiskLevel::Clean => "✓".to_string(),
                    RiskLevel::Suspicious => "⚠️ ".to_string(),
                    RiskLevel::Compromised => "✗".to_string(),
                };

                if ev.risk_level != RiskLevel::Clean {
                    issue_count += 1;
                }

                rows.push(EvidenceRow {
                    status,
                    probe: ev.probe_name.clone(),
                    risk: ev.risk_level.as_str().to_string(),
                    confidence: format!("{:.0}%", ev.confidence * 100.0),
                    summary: ev.summary.clone(),
                });
            }

            if !rows.is_empty() {
                let table = Table::new(rows).with(Style::modern_rounded()).to_string();
                println!("{}", table);
            }

            println!();
            if issue_count > 0 {
                println!("⚠️  深度审计发现 {} 项异常", issue_count);
                for ev in &results {
                    if ev.risk_level != RiskLevel::Clean {
                        println!("  • {}: {}", ev.probe_name, ev.summary);
                        for m in &ev.mitigations {
                            println!("    ↳ {}", m);
                        }
                    }
                }
            } else {
                println!("✓ 深度审计完成，未发现异常");
            }
        }
    }

    Ok(())
}

async fn run_export(cli: &Cli, output_path: &str) -> Result<()> {
    let store = EvidenceStore::open(&cli.db)
        .with_context(|| format!("打开数据库 {} 失败", cli.db))?;

    let records = store.recent_scans(1000)?;

    if records.is_empty() {
        println!("暂无扫描记录可导出");
        return Ok(());
    }

    let report = json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "tool": "prison-probe",
        "version": env!("CARGO_PKG_VERSION"),
        "record_count": records.len(),
        "records": records.iter().map(|r| json!({
            "timestamp": r.timestamp,
            "probe": r.probe_name,
            "risk": r.risk_level,
            "confidence": r.confidence,
            "summary": r.summary,
        })).collect::<Vec<_>>(),
    });

    let json_bytes = serde_json::to_vec_pretty(&report)?;

    // 计算 SHA-256 校验
    let hash = sha256_hex(&json_bytes);

    // 写入文件：JSON + 换行 + SHA-256 校验行
    let mut content = String::from_utf8(json_bytes)?;
    content.push('\n');
    content.push_str(&format!("// SHA-256: {}\n", hash));

    std::fs::write(output_path, content)
        .with_context(|| format!("写入报告文件 {} 失败", output_path))?;

    println!("✓ 报告已导出: {}", output_path);
    println!("  记录数: {}", records.len());
    println!("  SHA-256: {}", hash);

    Ok(())
}

async fn show_history(cli: &Cli, limit: usize) -> Result<()> {
    let store = EvidenceStore::open(&cli.db)
        .with_context(|| format!("打开数据库 {} 失败", cli.db))?;

    let records = store.recent_scans(limit)?;

    if records.is_empty() {
        println!("暂无扫描历史记录");
        return Ok(());
    }

    match cli.format {
        OutputFormat::Json => {
            let output = json!({
                "records": records.iter().map(|r| json!({
                    "timestamp": r.timestamp,
                    "probe": r.probe_name,
                    "risk": r.risk_level,
                    "confidence": r.confidence,
                    "summary": r.summary,
                })).collect::<Vec<_>>(),
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        OutputFormat::Table => {
            let rows: Vec<_> = records
                .iter()
                .map(|r| HistoryRow {
                    timestamp: r.timestamp.clone(),
                    probe: r.probe_name.clone(),
                    risk: r.risk_level.clone(),
                    summary: r.summary.clone(),
                })
                .collect();

            let table = Table::new(rows).with(Style::modern_rounded()).to_string();
            println!("{}", table);
        }
    }

    Ok(())
}

async fn show_stats(cli: &Cli) -> Result<()> {
    let store = EvidenceStore::open(&cli.db)
        .with_context(|| format!("打开数据库 {} 失败", cli.db))?;

    let stats = store.stats()?;

    match cli.format {
        OutputFormat::Json => {
            let output = json!({
                "total_scans": stats.total_scans,
                "clean": stats.clean,
                "suspicious": stats.suspicious,
                "compromised": stats.compromised,
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        OutputFormat::Table => {
            println!("扫描统计");
            println!("  总扫描次数: {}", stats.total_scans);
            println!("  正常:       {}", stats.clean);
            println!("  可疑:       {}", stats.suspicious);
            println!("  危险:       {}", stats.compromised);
        }
    }

    Ok(())
}

fn print_health_bar(score: u8) {
    let bar_width = 40usize;
    let filled = (score as usize * bar_width / 100).max(1).min(bar_width);
    let empty = bar_width - filled;

    let bar: String = std::iter::repeat('█')
        .take(filled)
        .chain(std::iter::repeat('░').take(empty))
        .collect();

    let color = if score >= 80 {
        "\x1b[32m" // green
    } else if score >= 50 {
        "\x1b[33m" // yellow
    } else {
        "\x1b[31m" // red
    };
    let reset = "\x1b[0m";

    print!("  {}{}{}{}\n", color, bar, reset, reset);
    io::stdout().flush().ok();
}
