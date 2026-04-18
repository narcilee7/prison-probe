# prison-probe

> 从内部攻破监狱的探针 —— 本地优先网络隐私审计工具

## 简介

**prison-probe** 是一个基于 Rust 构建的本地优先网络隐私审计工具。它通过多维度探针检测代理透明度、DNS 泄漏、TLS 证书完整性、JA3 指纹漂移、WebRTC 内网 IP 暴露与系统级代理配置，帮助用户在不可信网络环境中验证自身数字隐私边界。

**核心原则：**
- 🛡️ **Zero-Trust Self-Validation** — 不信任任何网络层，包括你自己配置的代理
- 🔒 **Air-Gapped Operation** — 完全离线运行，检测数据本地 SQLite 存储，零网络遥测
- 🧾 **Forensic-Level Evidence** — 每个告警附带可验证的原始证据链

## 快速开始

### CLI

```bash
# 快速体征扫描（3 秒内完成）
cargo run --bin prison-probe -- quick

# 深度信道审计（JA3 指纹等）
cargo run --bin prison-probe -- deep

# 导出扫描报告（JSON + SHA-256）
cargo run --bin prison-probe -- export --output report.pp-evidence

# JSON 输出
cargo run --bin prison-probe -- --format json quick

# 查看扫描历史
cargo run --bin prison-probe -- history

# 查看统计数据
cargo run --bin prison-probe -- stats
```

### GUI (Tauri)

```bash
# 构建前端
cd frontend && npm install && npm run build

# 运行桌面应用
cargo run --bin prison-probe-gui
```

## 已实现功能

### Milestone 1: Core Probe ✅
- `ExitIPConsistencyProbe` — 三信道（HTTPS / STUN / DNS）出口 IP 一致性校验
- `DNSLeakProbe` — 通过 whoami 服务检测 DNS 泄漏
- SQLite 本地存储（scan_history + cert_baseline）
- CLI 输出（人类友好表格 + JSON）

### Milestone 2: GUI & System Audit ✅
- **Tauri + React 桌面应用** — 暗色主题仪表盘
- `SSLBaselineProbe` — TLS 证书指纹基线比对与漂移检测
- `SysConfigProbe` — macOS 系统代理配置审计（networksetup 封装）
- 隐私健康度评分 + 可视化进度条
- 扫描历史时间线 + 技术详情面板

### Milestone 3: Deep Inspection ✅
- `WebRTCLeakProbe` — 本地内网 IP 暴露检测（接口枚举 + STUN 映射）
- `JA3FingerprintProbe` — 从 rustls ClientHello 提取 JA3 指纹，基线漂移检测
- **Deep Scan CLI** — `prison-probe deep` 运行深度探测器
- **报告导出** — `.pp-evidence` 格式（JSON + SHA-256 校验）
- GUI 支持快速扫描 / 深度审计 / 导出报告三按钮

## 探测器一览

| 探测器 | 类别 | 功能 |
|--------|------|------|
| `exit_ip_consistency` | Quick | HTTPS + STUN + DNS 三信道出口 IP 一致性 |
| `dns_leak` | Quick | whoami DNS 泄漏检测 |
| `ssl_baseline` | Quick | TLS 证书指纹基线比对 |
| `webrtc_leak` | Quick | 内网 IP 暴露风险检测 |
| `sys_config_audit` | Quick | macOS 系统代理配置审计 |
| `ja3_fingerprint` | Deep | JA3 TLS 指纹计算与漂移检测 |

## 项目结构

```
prison-probe/
├── Cargo.toml                  # Workspace 配置
├── crates/
│   ├── core/                   # 核心探测库
│   │   └── src/probe/          # 探测器实现
│   ├── cli/                    # CLI 二进制
│   └── gui/                    # Tauri 桌面应用
├── frontend/                   # React + Vite 前端
└── docs/PRD.md                 # 产品需求文档
```

## 技术栈

| 领域 | 依赖 |
|------|------|
| 异步运行时 | `tokio` |
| HTTP / TLS | `reqwest` + `rustls` + `tokio-rustls` |
| DNS | `hickory-resolver` |
| 存储 | `rusqlite` (bundled) |
| CLI | `clap` + `tabled` |
| GUI | `Tauri 2` + `React` + `Vite` |
| 序列化 | `serde` + `serde_json` |
| 日志 | `tracing` |

## Roadmap

- [x] **Milestone 1**: Core Probe — CLI 可用，基本代理检测
- [x] **Milestone 2**: GUI & System Audit — Tauri + 证书基线 + 系统代理审计
- [x] **Milestone 3**: Deep Inspection — JA3、WebRTC ICE、Deep Scan、报告导出
- [ ] **Milestone 4**: Hardening & Release — cargo-vet、渗透测试、开源发布

## License

MIT
