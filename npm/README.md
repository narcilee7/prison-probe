# @prison-probe/cli

> Local-first network privacy auditing tool — distributed via npm

## Install

```bash
# Global install (recommended)
npm install -g @prison-probe/cli

# Or use npx (no install)
npx @prison-probe/cli quick
```

## Usage

```bash
# Quick scan (3 seconds)
pp quick

# Deep channel audit
pp deep

# Export evidence report
pp export --output report.pp-evidence

# View history
pp history

# View stats
pp stats

# JSON output
pp --format json quick
```

## Supported Platforms

| OS | Architecture |
|----|-------------|
| macOS | Intel (x64), Apple Silicon (arm64) |
| Linux | x64 |
| Windows | x64 |

The correct binary is automatically downloaded during `npm install` based on your platform.

## How It Works

This npm package is a thin wrapper that:

1. Detects your OS and architecture during `postinstall`
2. Downloads the matching native binary from [GitHub Releases](https://github.com/narcilee7/prison-probe/releases)
3. Places it in `vendor/` and exposes the `pp` command

No compilation required — just install and run.

## License

MIT
