use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "prison-probe")]
#[command(about = "本地优先网络隐私审计工具")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// 输出格式
    #[arg(short, long, value_enum, default_value = "table")]
    pub format: OutputFormat,

    /// 数据库路径
    #[arg(short, long, default_value = "prison-probe.db")]
    pub db: String,
}

#[derive(Subcommand)]
pub enum Commands {
    /// 快速体征扫描（3 秒内完成）
    Quick,
    /// 查看扫描历史
    History {
        /// 显示条数
        #[arg(short, long, default_value = "20")]
        limit: usize,
    },
    /// 查看统计数据
    Stats,
}

#[derive(Clone, Copy, Debug, Default, clap::ValueEnum)]
pub enum OutputFormat {
    /// 人类友好的表格
    #[default]
    Table,
    /// JSON 格式
    Json,
}
