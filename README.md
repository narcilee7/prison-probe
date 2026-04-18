# prison-probe

> 从内部攻破监狱的探针 —— 本地优先网络隐私审计工具

## 简介

**prison-probe** 是一个基于 Rust 构建的本地优先网络隐私审计工具。它通过多维度探针检测代理透明度、DNS 泄漏与系统级代理配置，帮助用户在不可信网络环境中验证自身数字隐私边界。

**核心原则：**
- 🛡️ **Zero-Trust Self-Validation** — 不信任任何网络层，包括你自己配置的代理
- 🔒 **Air-Gapped Operation** — 完全离线运行，检测数据本地 SQLite 存储，零网络遥测
- 🧾 **Forensic-Level Evidence** — 每个告警附带可验证的原始证据链

## 快速开始

```bash
# 快速体征扫描（3 秒内完成）
cargo run -- quick

# JSON 输出
./prison-probe --format json quick

# 查看扫描历史
./prison-probe history

# 查看统计数据
./prison-probe stats
```

## Milestone 1 已实现

- ✅ Rust 项目脚手架 + 核心模块架构
- ✅ `ExitIPConsistencyProbe` — 三信道（HTTPS / STUN / DNS）出口 IP 一致性校验
- ✅ `DNSLeakProbe` — 通过 whoami 服务检测 DNS 泄漏
- ✅ SQLite 本地存储（scan_history + cert_baseline）
- ✅ CLI 输出（人类友好表格 + JSON）

## 项目结构

```
.
├── Cargo.toml
├── docs/PRD.md              # 产品需求文档
├── src/
│   ├── main.rs              # CLI 入口
│   ├── cli.rs               # 命令行参数
│   ├── lib.rs               # 库入口
│   ├── probe/
│   │   ├── mod.rs           # Probe trait + Evidence 结构
│   │   ├── exit_ip.rs       # 出口 IP 一致性探测器
│   │   └── dns_leak.rs      # DNS 泄漏探测器
│   └── store/
│       └── mod.rs           # SQLite 证据存储
└── README.md
```

## 技术栈

| 领域 | 依赖 |
|------|------|
| 异步运行时 | `tokio` |
| HTTP / TLS | `reqwest` + `rustls` |
| DNS | `hickory-resolver` |
| 存储 | `rusqlite` (bundled) |
| CLI | `clap` + `tabled` |
| 序列化 | `serde` + `serde_json` |
| 日志 | `tracing` |

## Roadmap

- [x] **Milestone 1**: Core Probe — CLI 可用，基本代理检测
- [ ] **Milestone 2**: GUI & System Audit — Tauri + macOS 代理配置审计
- [ ] **Milestone 3**: Deep Inspection — JA3/JA4、MTU/TTL、WebRTC ICE
- [ ] **Milestone 4**: Hardening & Release — cargo-vet、渗透测试、开源发布

## License

MIT
