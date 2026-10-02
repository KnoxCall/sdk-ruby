# Security misconfiguration warnings (PARITY §15) — mirrors knoxcall-python's
# tests/test_warnings.py and the node warn.ts guards.
#
#   1. Plaintext http:// to a NON-loopback host (management base OR data-plane
#      proxy) warns once at construction — http://localhost stays silent.
#   2. A group/other-readable credentials file warns once on read (POSIX only).
#
# Warnings are non-blocking: they go to $stderr via Kernel#warn and never
# change behavior, so every example just captures $stderr.

require "tmpdir"
require "stringio"

RSpec.describe "KnoxCall security warnings (PARITY §15)" do
  around do |example|
    vars = %w[KNOXCALL_TENANT KNOXCALL_ENVIRONMENT KNOXCALL_ACCESS_TOKEN
              KNOXCALL_API_KEY KNOXCALL_CLIENT_ID KNOXCALL_CLIENT_SECRET
              KNOXCALL_BASE_URL KNOXCALL_API_BASE_URL KNOXCALL_PROXY_BASE_URL
              KNOXCALL_PROFILE]
    vars.each { |k| ENV.delete(k) }
    example.run
  ensure
    vars.each { |k| ENV.delete(k) }
  end

  # The dedup is per-process; reset it before each example so a warning
  # emitted by an earlier spec (random order) never masks the assertion here.
  before { KnoxCall::Warnings._reset_for_tests }

  def capture_stderr
    original = $stderr
    $stderr = StringIO.new
    yield
    $stderr.string
  ensure
    $stderr = original
  end

  # -- insecure_remote_url? predicate -------------------------------------------

  describe "KnoxCall::Warnings.insecure_remote_url?" do
    it "is true only for plaintext http:// to a non-loopback host" do
      w = KnoxCall::Warnings
      expect(w.insecure_remote_url?("http://api.example.com")).to be(true)
      expect(w.insecure_remote_url?("http://10.0.0.5:3000")).to be(true)
      expect(w.insecure_remote_url?("http://[fe80::1]:8080")).to be(true) # link-local, not loopback

      # https is always fine
      expect(w.insecure_remote_url?("https://api.example.com")).to be(false)
      # loopback forms are the normal dev case — never warn
      expect(w.insecure_remote_url?("http://localhost:3000")).to be(false)
      expect(w.insecure_remote_url?("http://foo.localhost")).to be(false)
      expect(w.insecure_remote_url?("http://127.0.0.1:3000")).to be(false)
      expect(w.insecure_remote_url?("http://127.5.6.7")).to be(false)
      expect(w.insecure_remote_url?("http://0.0.0.0:3000")).to be(false)
      expect(w.insecure_remote_url?("http://[::1]:3000")).to be(false)
      # non-strings / junk
      expect(w.insecure_remote_url?(nil)).to be(false)
      expect(w.insecure_remote_url?("")).to be(false)
      expect(w.insecure_remote_url?("not a url")).to be(false)
    end
  end

  # -- Plaintext transport at construction --------------------------------------

  describe "plaintext transport warning at construction" do
    it "warns when the management base URL is http:// to a non-loopback host" do
      err = capture_stderr do
        KnoxCall::Client.new(
          tenant: "acme", access_token: "kc_live_x",
          base_url: "http://api.insecure.test",
          proxy_base_url: "https://acme.knoxcall.com" # keep the proxy check quiet
        )
      end
      expect(err).to include("api.insecure.test")
      expect(err).to include("unencrypted")
    end

    it "warns when the data-plane proxy URL is http:// to a non-loopback host" do
      err = capture_stderr do
        KnoxCall::Client.new(
          tenant: "acme", access_token: "kc_live_x",
          base_url: "https://api.example.test",
          proxy_base_url: "http://proxy.insecure.test"
        )
      end
      expect(err).to include("proxy.insecure.test")
      expect(err).to include("unencrypted")
    end

    it "does NOT warn for http://localhost (the normal dev case)" do
      err = capture_stderr do
        KnoxCall::Client.new(
          tenant: "acme", access_token: "kc_live_x",
          base_url: "http://localhost:3000",
          proxy_base_url: "http://localhost:3000"
        )
      end
      expect(err).to eq("")
    end

    it "does NOT warn for an https base and proxy" do
      err = capture_stderr do
        KnoxCall::Client.new(
          tenant: "acme", access_token: "kc_live_x",
          base_url: "https://api.example.test",
          proxy_base_url: "https://acme.example.test"
        )
      end
      expect(err).to eq("")
    end

    it "fires each distinct warning at most once per process" do
      err = capture_stderr do
        2.times do
          KnoxCall::Client.new(
            tenant: "acme", access_token: "kc_live_x",
            base_url: "http://api.insecure.test",
            proxy_base_url: "https://acme.knoxcall.com"
          )
        end
      end
      expect(err.scan("api.insecure.test").length).to eq(1)
    end
  end

  # -- World-readable credentials file ------------------------------------------

  describe "world-readable credentials file warning (POSIX only)" do
    def write_file(path, mode)
      KnoxCall::CredentialsFile.write_profile(
        path, "default",
        { "tenant" => "acme", "access_token" => "kc_x",
          "access_token_expires_at" =>
            KnoxCall::CredentialsFile.format_expiry(Time.now + 3600) }
      )
      File.chmod(mode, path)
    end

    it "warns (chmod 600) for a group/other-accessible file" do
      skip "POSIX file modes only" if Gem.win_platform?
      Dir.mktmpdir("knoxcall-perms") do |dir|
        path = File.join(dir, "credentials.json")
        write_file(path, 0o644)
        err = capture_stderr { KnoxCall::CredentialsFile.read_document(path) }
        expect(err).to include("chmod 600")
        expect(err).to include(path)
      end
    end

    it "stays silent for a 0600 file" do
      skip "POSIX file modes only" if Gem.win_platform?
      Dir.mktmpdir("knoxcall-perms") do |dir|
        path = File.join(dir, "credentials.json")
        write_file(path, 0o600)
        err = capture_stderr { KnoxCall::CredentialsFile.read_document(path) }
        expect(err).to eq("")
      end
    end

    it "is a no-op for a missing file (nothing to warn about)" do
      skip "POSIX file modes only" if Gem.win_platform?
      Dir.mktmpdir("knoxcall-perms") do |dir|
        path = File.join(dir, "does-not-exist.json")
        err = capture_stderr { KnoxCall::CredentialsFile.read_document(path) }
        expect(err).to eq("")
      end
    end
  end
end
