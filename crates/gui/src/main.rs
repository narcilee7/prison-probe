// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use prison_probe_core::probe::{ProbeContext, ProbeSuite, RiskLevel};
use prison_probe_core::store::EvidenceStore;
use serde::Serialize;
use std::time::Duration;

#[derive(Serialize)]
struct ScanResult {
    elapsed_ms: u64,
    health_score: u8,
    results: Vec<serde_json::Value>,
}

#[tauri::command]
async fn run_quick_scan() -> Result<ScanResult, String> {
    let ctx = ProbeContext {
        timeout: Duration::from_secs(15),
        proxy_url: std::env::var("HTTP_PROXY").ok(),
    };

    let suite = ProbeSuite::quick_suite();
    let start = std::time::Instant::now();
    let results = suite.execute(&ctx).await;
    let elapsed = start.elapsed();

    // 保存结果
    let store = EvidenceStore::open("prison-probe.db").map_err(|e| e.to_string())?;
    for evidence in &results {
        store.save_evidence(evidence).ok();
    }

    let score = calculate_health_score(&results);

    let json_results: Vec<serde_json::Value> = results
        .into_iter()
        .map(|e| serde_json::to_value(e).unwrap_or_default())
        .collect();

    Ok(ScanResult {
        elapsed_ms: elapsed.as_millis() as u64,
        health_score: score,
        results: json_results,
    })
}

#[tauri::command]
async fn get_history(limit: usize) -> Result<Vec<serde_json::Value>, String> {
    let store = EvidenceStore::open("prison-probe.db").map_err(|e| e.to_string())?;
    let records = store.recent_scans(limit).map_err(|e| e.to_string())?;

    Ok(records
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "timestamp": r.timestamp,
                "probe_name": r.probe_name,
                "risk_level": r.risk_level,
                "confidence": r.confidence,
                "summary": r.summary,
            })
        })
        .collect())
}

#[tauri::command]
async fn get_stats() -> Result<serde_json::Value, String> {
    let store = EvidenceStore::open("prison-probe.db").map_err(|e| e.to_string())?;
    let stats = store.stats().map_err(|e| e.to_string())?;

    Ok(serde_json::json!({
        "total_scans": stats.total_scans,
        "clean": stats.clean,
        "suspicious": stats.suspicious,
        "compromised": stats.compromised,
    }))
}

fn calculate_health_score(results: &[prison_probe_core::probe::Evidence]) -> u8 {
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

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_target(false)
        .init();

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![run_quick_scan, get_history, get_stats])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
