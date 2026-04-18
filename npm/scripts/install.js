#!/usr/bin/env node
/**
 * prison-probe CLI — postinstall script
 *
 * Automatically downloads the correct platform binary from GitHub Releases
 * and places it in the vendor/ directory.
 */

const fs = require("fs");
const path = require("path");
const https = require("https");
const { execSync } = require("child_process");

const VERSION = "0.1.0";
const REPO = "narcilee7/prison-probe";
const BASE_URL = `https://github.com/${REPO}/releases/download/v${VERSION}`;

const PLATFORM_MAP = {
  darwin: {
    x64: "pp-x86_64-apple-darwin.tar.gz",
    arm64: "pp-aarch64-apple-darwin.tar.gz",
  },
  linux: {
    x64: "pp-x86_64-unknown-linux-gnu.tar.gz",
  },
  win32: {
    x64: "pp-x86_64-pc-windows-msvc.zip",
  },
};

function getAssetName() {
  const platform = process.platform;
  const arch = process.arch;

  const platformAssets = PLATFORM_MAP[platform];
  if (!platformAssets) {
    throw new Error(`Unsupported platform: ${platform}`);
  }

  const asset = platformAssets[arch];
  if (!asset) {
    throw new Error(`Unsupported architecture: ${arch} on ${platform}`);
  }

  return asset;
}

function download(url, dest) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest);
    https
      .get(url, { headers: { "User-Agent": "prison-probe-installer" } }, (res) => {
        if (res.statusCode === 302 || res.statusCode === 301) {
          // Follow redirect
          download(res.headers.location, dest).then(resolve).catch(reject);
          return;
        }
        if (res.statusCode !== 200) {
          reject(new Error(`Download failed: HTTP ${res.statusCode}`));
          return;
        }
        res.pipe(file);
        file.on("finish", () => {
          file.close();
          resolve();
        });
      })
      .on("error", (err) => {
        fs.unlink(dest, () => {});
        reject(err);
      });
  });
}

function extract(archivePath, extractDir) {
  if (archivePath.endsWith(".tar.gz")) {
    execSync(`tar -xzf "${archivePath}" -C "${extractDir}"`, { stdio: "inherit" });
  } else if (archivePath.endsWith(".zip")) {
    if (process.platform === "win32") {
      execSync(`powershell -Command "Expand-Archive -Path '${archivePath}' -DestinationPath '${extractDir}' -Force"`, {
        stdio: "inherit",
      });
    } else {
      execSync(`unzip -o "${archivePath}" -d "${extractDir}"`, { stdio: "inherit" });
    }
  } else {
    throw new Error(`Unknown archive format: ${archivePath}`);
  }
}

async function main() {
  const rootDir = path.resolve(__dirname, "..");
  const vendorDir = path.join(rootDir, "vendor");

  if (!fs.existsSync(vendorDir)) {
    fs.mkdirSync(vendorDir, { recursive: true });
  }

  const assetName = getAssetName();
  const binaryName = process.platform === "win32" ? "pp.exe" : "pp";
  const binaryPath = path.join(vendorDir, binaryName);

  // Skip if already installed
  if (fs.existsSync(binaryPath)) {
    console.log(`✓ pp binary already installed at ${binaryPath}`);
    return;
  }

  const url = `${BASE_URL}/${assetName}`;
  const archivePath = path.join(vendorDir, assetName);

  console.log(`Downloading pp ${VERSION} for ${process.platform}-${process.arch}...`);
  console.log(`URL: ${url}`);

  try {
    await download(url, archivePath);
    console.log(`Extracting ${assetName}...`);
    extract(archivePath, vendorDir);
    fs.unlinkSync(archivePath);

    // Set executable permission on Unix
    if (process.platform !== "win32") {
      fs.chmodSync(binaryPath, 0o755);
    }

    console.log(`✓ pp ${VERSION} installed successfully!`);
    console.log(`  Binary: ${binaryPath}`);
  } catch (err) {
    console.error(`✗ Installation failed: ${err.message}`);
    process.exit(1);
  }
}

main();
