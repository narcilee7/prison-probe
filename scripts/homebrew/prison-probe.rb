class PrisonProbe < Formula
  desc "Local-first network privacy auditing tool"
  homepage "https://github.com/narcilee7/prison-probe"
  license "MIT"

  version "0.1.0"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/narcilee7/prison-probe/releases/download/v#{version}/prison-probe-x86_64-apple-darwin.tar.gz"
    sha256 "PLACEHOLDER_SHA256_INTEL"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/narcilee7/prison-probe/releases/download/v#{version}/prison-probe-aarch64-apple-darwin.tar.gz"
    sha256 "PLACEHOLDER_SHA256_ARM"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/narcilee7/prison-probe/releases/download/v#{version}/prison-probe-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "PLACEHOLDER_SHA256_LINUX"
  end

  def install
    bin.install "prison-probe"
  end

  test do
    system "#{bin}/prison-probe", "--version"
  end
end
