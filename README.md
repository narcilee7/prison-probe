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
cargo run --bin pp -- quick

# 深度信道审计（JA3 指纹等）
cargo run --bin pp -- deep

# 导出扫描报告（JSON + SHA-256）
cargo run --bin pp -- export --output report.pp-evidence

# JSON 输出
cargo run --bin pp -- --format json quick

# 查看扫描历史
cargo run --bin pp -- history

# 查看统计数据
cargo run --bin pp -- stats
```

### GUI (Tauri)

```bash
# 构建前端
cd frontend && npm install && npm run build

# 运行桌面应用
cargo run --bin pp-gui
```

### Homebrew

```bash
brew tap narcilee7/prison-probe
brew install prison-probe
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
- **Deep Scan CLI** — `pp deep` 运行深度探测器
- **报告导出** — `.pp-evidence` 格式（JSON + SHA-256 校验）
- GUI 支持快速扫描 / 深度审计 / 导出报告三按钮

### Milestone 4: Hardening & Release ✅
- **24 个单元测试** 覆盖核心模块
- **cargo-vet** 供应链审计（608 依赖已豁免审计）
- **GitHub Actions CI** — 三平台测试 + clippy + fmt + cargo-vet
- **GitHub Actions Release** — 自动构建 macOS/Intel、macOS/ARM、Linux、Windows
- **Homebrew Formula** 模板
- **release.sh** 发布自动化脚本

## 探测器一览

| 探测器 | 类别 | 功能 |
|--------|------|------|
| `exit_ip_consistency` | Quick | HTTPS + STUN + DNS 三信道出口 IP 一致性 |
| `dns_leak` | Quick | whoami DNS 泄漏检测 |
| `ssl_baseline` | Quick | TLS 证书指纹基线比对 |
| `webrtc_leak` | Quick | 内网 IP 暴露风险检测 |
| `sys_config_audit` | Quick | macOS 系统代理配置审计 |
| `ja3_fingerprint` | Deep | JA3 TLS 指纹漂移检测 |

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
├── supply-chain/               # cargo-vet 审计配置
├── .github/workflows/          # CI/CD
├── scripts/                    # 发布脚本 + Homebrew
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
| 测试 | 内置 `cargo test` |
| 供应链 | `cargo-vet` |

## 开发

```bash
# 运行测试
cargo test --workspace --exclude pp-gui

# 代码检查
cargo clippy --workspace --exclude pp-gui -- -D warnings
cargo fmt -- --check

# 供应链审计
cargo vet

# 发布（需先配置 GitHub token）
./scripts/release.sh v0.1.0
```

## License

MIT
