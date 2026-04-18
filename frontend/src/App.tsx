import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./App.css";

interface ScanResult {
  elapsed_ms: number;
  health_score: number;
  results: Evidence[];
}

interface Evidence {
  probe_name: string;
  risk_level: "Clean" | "Suspicious" | "Compromised";
  confidence: number;
  summary: string;
  mitigations: string[];
  timestamp: string;
}

interface Stats {
  total_scans: number;
  clean: number;
  suspicious: number;
  compromised: number;
}

function RiskBadge({ level }: { level: Evidence["risk_level"] }) {
  const map = {
    Clean: { cls: "badge-clean", text: "正常" },
    Suspicious: { cls: "badge-suspicious", text: "可疑" },
    Compromised: { cls: "badge-compromised", text: "危险" },
  };
  const m = map[level];
  return <span className={`badge ${m.cls}`}>{m.text}</span>;
}

function HealthBar({ score }: { score: number }) {
  const color = score >= 80 ? "#00e676" : score >= 50 ? "#ffea00" : "#ff1744";
  return (
    <div className="health-bar">
      <div
        className="health-bar-fill"
        style={{ width: `${score}%`, backgroundColor: color }}
      />
    </div>
  );
}

function App() {
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [stats, setStats] = useState<Stats | null>(null);
  const [history, setHistory] = useState<Evidence[]>([]);
  const [activeTab, setActiveTab] = useState<"dashboard" | "history">("dashboard");

  const loadStats = async () => {
    try {
      const s = await invoke<Stats>("get_stats");
      setStats(s);
    } catch (e) {
      console.error(e);
    }
  };

  const loadHistory = async () => {
    try {
      const h = await invoke<Evidence[]>("get_history", { limit: 50 });
      setHistory(h);
    } catch (e) {
      console.error(e);
    }
  };

  const runScan = async () => {
    setScanning(true);
    try {
      const res = await invoke<ScanResult>("run_quick_scan");
      setResult(res);
      await loadStats();
      await loadHistory();
    } catch (e) {
      alert("扫描失败: " + e);
    } finally {
      setScanning(false);
    }
  };

  useEffect(() => {
    loadStats();
    loadHistory();
  }, []);

  return (
    <div className="app">
      <header className="header">
        <h1>🔴 prison-probe</h1>
        <nav className="nav">
          <button
            className={activeTab === "dashboard" ? "active" : ""}
            onClick={() => setActiveTab("dashboard")}
          >
            仪表盘
          </button>
          <button
            className={activeTab === "history" ? "active" : ""}
            onClick={() => setActiveTab("history")}
          >
            历史记录
          </button>
        </nav>
      </header>

      <main className="main">
        {activeTab === "dashboard" && (
          <>
            <section className="card">
              <div className="score-section">
                <div className="score-value">
                  {result ? result.health_score : "--"}/100
                </div>
                {result && <HealthBar score={result.health_score} />}
                <p className="score-hint">
                  {result
                    ? `扫描耗时 ${(result.elapsed_ms / 1000).toFixed(2)}s`
                    : "点击按钮开始快速扫描"}
                </p>
              </div>
              <button
                className="scan-btn"
                onClick={runScan}
                disabled={scanning}
              >
                {scanning ? "扫描中..." : "🔍 快速扫描"}
              </button>
            </section>

            {result && (
              <section className="card">
                <h2>扫描结果</h2>
                <div className="results">
                  {result.results.map((ev, idx) => (
                    <div key={idx} className="result-item">
                      <div className="result-header">
                        <RiskBadge level={ev.risk_level} />
                        <span className="probe-name">{ev.probe_name}</span>
                        <span className="confidence">
                          置信度 {(ev.confidence * 100).toFixed(0)}%
                        </span>
                      </div>
                      <p className="summary">{ev.summary}</p>
                      {ev.mitigations.length > 0 && (
                        <ul className="mitigations">
                          {ev.mitigations.map((m, i) => (
                            <li key={i}>↳ {m}</li>
                          ))}
                        </ul>
                      )}
                    </div>
                  ))}
                </div>
              </section>
            )}

            {stats && (
              <section className="card">
                <h2>统计概览</h2>
                <div className="stats-grid">
                  <div className="stat-item">
                    <div className="stat-num">{stats.total_scans}</div>
                    <div className="stat-label">总扫描</div>
                  </div>
                  <div className="stat-item clean">
                    <div className="stat-num">{stats.clean}</div>
                    <div className="stat-label">正常</div>
                  </div>
                  <div className="stat-item suspicious">
                    <div className="stat-num">{stats.suspicious}</div>
                    <div className="stat-label">可疑</div>
                  </div>
                  <div className="stat-item compromised">
                    <div className="stat-num">{stats.compromised}</div>
                    <div className="stat-label">危险</div>
                  </div>
                </div>
              </section>
            )}
          </>
        )}

        {activeTab === "history" && (
          <section className="card">
            <h2>扫描历史</h2>
            {history.length === 0 ? (
              <p className="empty">暂无历史记录</p>
            ) : (
              <table className="history-table">
                <thead>
                  <tr>
                    <th>时间</th>
                    <th>探测器</th>
                    <th>风险</th>
                    <th>摘要</th>
                  </tr>
                </thead>
                <tbody>
                  {history.map((h, idx) => (
                    <tr key={idx}>
                      <td>{new Date(h.timestamp).toLocaleString()}</td>
                      <td>{h.probe_name}</td>
                      <td>
                        <RiskBadge level={h.risk_level} />
                      </td>
                      <td>{h.summary}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>
        )}
      </main>
    </div>
  );
}

export default App;
