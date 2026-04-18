# prison-probe

> 从内部攻破监狱的探针 —— 本地优先网络隐私审计工具

## 简介

**prison-probe** 是一个基于 Rust 构建的本地优先网络隐私审计工具。它通过多维度探针检测代理透明度、DNS 泄漏、TLS 证书完整性与系统级代理配置，帮助用户在不可信网络环境中验证自身数字隐私边界。

**核心原则：**
- 🛡️ **Zero-Trust Self-Validation** — 不信任任何网络层，包括你自己配置的代理
- 🔒 **Air-Gapped Operation** — 完全离线运行，检测数据本地 SQLite 存储，零网络遥测
- 🧾 **Forensic-Level Evidence** — 每个告警附带可验证的原始证据链

## 快速开始

### CLI

```bash
# 快速体征扫描（3 秒内完成）
cargo run --bin prison-probe -- quick

# JSON 输出
cargo run --bin prison-probe -- --format json quick

# 查看扫描历史
cargo run --bin prison-probe -- history

# 查看统计数据
cargo run --bin prison-probe -- stats
```

### GUI (Tauri)

```bash
# 开发模式
cd frontend && npm install
cargo run --bin prison-probe-gui

# 构建前端
cd frontend && npm run build
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

## 项目结构

```
prison-probe/
├── Cargo.toml                  # Workspace 配置
├── crates/
│   ├── core/                   # 核心探测库
│   │   └── src/
│   │       ├── probe/          # 探测器实现
│   │       │   ├── exit_ip.rs
│   │       │   ├── dns_leak.rs
│   │       │   ├── ssl_baseline.rs
│   │       │   └── sys_config.rs
│   │       └── store/          # SQLite 存储
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
- [ ] **Milestone 3**: Deep Inspection — JA3/JA4、MTU/TTL、WebRTC ICE
- [ ] **Milestone 4**: Hardening & Release — cargo-vet、渗透测试、开源发布

## License

MIT
