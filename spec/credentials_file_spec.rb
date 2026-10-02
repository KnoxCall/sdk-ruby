# Credentials-file provider tests — StoredCredentials bootstrap (PARITY §2/§10).
# Mirrors knoxcall-python's tests/test_credentials_file.py.
#
# Every example points KNOXCALL_CREDENTIALS_FILE at a Dir.mktmpdir so the real
# ~/.knoxcall is never touched (or even read).

require "tmpdir"

RSpec.describe "KnoxCall credentials file (StoredCredentials)" do
  let(:api)       { "https://api.example.test" }
  let(:token_url) { "#{api}/oauth/token" }

  around do |example|
    vars = %w[KNOXCALL_TENANT KNOXCALL_ENVIRONMENT KNOXCALL_ACCESS_TOKEN
              KNOXCALL_API_KEY KNOXCALL_CLIENT_ID KNOXCALL_CLIENT_SECRET
              KNOXCALL_BASE_URL KNOXCALL_API_BASE_URL KNOXCALL_PROXY_BASE_URL
              KNOXCALL_PROFILE]
    vars.each { |k| ENV.delete(k) }
    Dir.mktmpdir("knoxcall-creds") do |dir|
      @dir = dir
      @creds_path = File.join(dir, "credentials.json")
      # spec_helper's outer around restores the pre-suite value afterwards.
      ENV["KNOXCALL_CREDENTIALS_FILE"] = @creds_path
      example.run
    end
  ensure
    vars.each { |k| ENV.delete(k) }
  end

  def write_creds(path: nil, profile: "default", tenant: "acme",
                  base_url: "https://api.example.test",
                  access_token: "kc_stored_fresh", refresh_token: "rt_1",
                  expires_in: 3600, client_id: "kc_cli_real", scope: "routes:read")
    KnoxCall::CredentialsFile.write_profile(
      path || @creds_path, profile,
      {
        "tenant" => tenant,
        "base_url" => base_url,
        "client_id" => client_id,
        "refresh_token" => refresh_token,
        "access_token" => access_token,
        "access_token_expires_at" =>
          KnoxCall::CredentialsFile.format_expiry(Time.now + expires_in),
        "scope" => scope
      }
    )
  end

  def read_creds(profile: "default")
    KnoxCall::CredentialsFile.read_profile(@creds_path, profile)
  end

  def headers_of(req)
    req.headers.transform_keys(&:downcase)
  end

  def refresh_response(access_token: "kc_new", refresh_token: "rt_new", extra: {})
    {
      status: 200,
      body: JSON.generate({ access_token: access_token, refresh_token: refresh_token,
                            token_type: "Bearer", expires_in: 3600 }.merge(extra)),
      headers: { "Content-Type" => "application/json" }
    }
  end

  # -- Auto-detect chain position (slot 2) -----------------------------------------

  describe "zero-arg chain position" do
    it "picks up the credentials file for zero-arg construction" do
      write_creds
      client = KnoxCall::Client.new
      expect(client.instance_variable_get(:@bootstrap)).to be_a(KnoxCall::StoredCredentials)
    end

    it "lets an env access token beat the file" do
      write_creds
      ENV["KNOXCALL_ACCESS_TOKEN"] = "kc_env_token"
      seen = {}
      stub_request(:get, "https://api.knoxcall.com/v1/routes")
        .with { |req| seen.merge!(headers_of(req)); true }
        .to_return(status: 200, body: "{}")

      client = KnoxCall::Client.new
      client.request("GET", "/v1/routes")

      expect(seen["authorization"]).to eq("Bearer kc_env_token")
      # env token also means no file seeding — the default base stays
      expect(a_request(:post, token_url)).not_to have_been_made
    end

    it "lets the file beat env client-credentials" do
      write_creds
      ENV["KNOXCALL_CLIENT_ID"] = "tk_env"
      ENV["KNOXCALL_CLIENT_SECRET"] = "sec"
      seen = {}
      stub_request(:get, "#{api}/v1/routes")
        .with { |req| seen.merge!(headers_of(req)); true }
        .to_return(status: 200, body: "{}")

      client = KnoxCall::Client.new
      client.request("GET", "/v1/routes")

      expect(seen["authorization"]).to eq("Bearer kc_stored_fresh")
      expect(a_request(:post, token_url)).not_to have_been_made
    end

    it "skips the provider when the file is missing (chain continues to env creds)" do
      ENV["KNOXCALL_CLIENT_ID"] = "tk_env"
      ENV["KNOXCALL_CLIENT_SECRET"] = "sec"
      minted = stub_request(:post, token_url).to_return(
        status: 200,
        body: JSON.generate(access_token: "kc_live_minted", token_type: "Bearer", expires_in: 3600),
        headers: { "Content-Type" => "application/json" }
      )
      stub_request(:get, "#{api}/v1/routes").to_return(status: 200, body: "{}")

      client = KnoxCall::Client.new(tenant: "acme", base_url: api, retry_base_delay: 0.001)
      client.request("GET", "/v1/routes")

      expect(minted).to have_been_requested.once
    end

    it "skips the provider when the selected profile is missing" do
      write_creds # only "default" exists
      ENV["KNOXCALL_PROFILE"] = "work"
      ENV["KNOXCALL_CLIENT_ID"] = "tk_env"
      ENV["KNOXCALL_CLIENT_SECRET"] = "sec"

      client = KnoxCall::Client.new(tenant: "acme", base_url: api)
      expect(client.instance_variable_get(:@bootstrap)).to be_nil
      expect(client.instance_variable_get(:@client_id)).to eq("tk_env")
    end

    it "skips a malformed file without crashing (chain continues)" do
      File.write(@creds_path, "{this is not json")
      ENV["KNOXCALL_CLIENT_ID"] = "tk_env"
      ENV["KNOXCALL_CLIENT_SECRET"] = "sec"

      client = KnoxCall::Client.new(tenant: "acme", base_url: api)
      expect(client.instance_variable_get(:@bootstrap)).to be_nil
      expect(client.instance_variable_get(:@client_id)).to eq("tk_env")
    end
  end

  # -- Fresh-token fast path ---------------------------------------------------------

  describe "fresh-token fast path" do
    it "uses a fresh stored access token without any token request" do
      write_creds(expires_in: 3600)
      seen = {}
      stub_request(:get, "#{api}/v1/routes")
        .with { |req| seen.merge!(headers_of(req)); true }
        .to_return(status: 200, body: "{}")

      client = KnoxCall::Client.new
      client.request("GET", "/v1/routes")

      expect(seen["authorization"]).to eq("Bearer kc_stored_fresh")
      expect(a_request(:post, token_url)).not_to have_been_made
      # the token response's tenant travels into the client (adopt_tenant)
      expect(client.tenant).to eq("acme")
    end
  end

  # -- Refresh + rotated write-back ----------------------------------------------------

  describe "refresh and rotated write-back" do
    it "refreshes an expired token and atomically writes back the rotated refresh token" do
      write_creds(access_token: "kc_old", refresh_token: "rt_old",
                  expires_in: 10) # inside the 60s freshness window → must refresh
      form = nil
      stub_request(:post, token_url)
        .with { |req| form = req.body; true }
        .to_return(refresh_response(extra: { scope: "routes:read secrets:read",
                                             tenant: "acme", client_id: "kc_cli_real" }))

      tok = KnoxCall::Client.new.token

      expect(tok[:access_token]).to eq("kc_new")
      expect(form).to include("grant_type=refresh_token")
      expect(form).to include("refresh_token=rt_old")
      expect(form).to include("client_id=kc_cli_real") # the REAL client id, not the alias
      expect(form).not_to include("client_secret")     # public client — no secret

      on_disk = read_creds
      expect(on_disk["refresh_token"]).to eq("rt_new") # rotation persisted
      expect(on_disk["access_token"]).to eq("kc_new")
      expect(on_disk["scope"]).to eq("routes:read secrets:read")
      # atomic write: no temp-file or lock litter left behind
      expect(Dir.children(@dir).sort).to eq(["credentials.json"])
    end

    it "raises AuthenticationError with the re-login hint on invalid_grant" do
      write_creds(expires_in: 0)
      stub_request(:post, token_url).to_return(
        status: 400,
        body: JSON.generate(error: "invalid_grant", error_description: "family revoked"),
        headers: { "Content-Type" => "application/json" }
      )

      expect { KnoxCall::Client.new.token }.to raise_error(KnoxCall::AuthenticationError) { |e|
        expect(e.message).to include("knoxcall login")
        expect(e.message).not_to include("rt_1") # never echo the refresh token
        expect(e.status_code).to eq(400)
      }
    end

    it "raises the re-login hint when the profile has no refresh token to use" do
      KnoxCall::CredentialsFile.write_profile(
        @creds_path, "default",
        {
          "tenant" => "acme",
          "base_url" => api,
          "client_id" => "kc_cli_real",
          "access_token" => "kc_dead",
          "access_token_expires_at" =>
            KnoxCall::CredentialsFile.format_expiry(Time.now - 10)
        }
      )
      expect { KnoxCall::Client.new.token }
        .to raise_error(KnoxCall::AuthenticationError, /knoxcall login/)
    end
  end

  # -- Lock: cross-process serialization + hygiene --------------------------------------

  describe "file lock" do
    it "serializes a thread-raced double refresh into exactly one token POST" do
      # Two clients (own token mutexes — the FILE lock is what serializes)
      # race an expired token: the loser re-reads under the lock and adopts
      # the rotated token (single-use refresh tokens make a second POST a
      # family revocation).
      write_creds(access_token: "kc_old", refresh_token: "rt_only", expires_in: 0)
      posts = Queue.new
      stub_request(:post, token_url).to_return do |request|
        posts << request.body
        sleep 0.3 # hold the refresh so the other thread queues on the file lock
        refresh_response(refresh_token: "rt_rotated")
      end

      results = Array.new(2)
      threads = 2.times.map do |i|
        Thread.new { results[i] = KnoxCall::Client.new.token }
      end
      threads.each { |t| expect(t.join(15)).to eq(t) }

      expect(posts.size).to eq(1)
      expect(posts.pop).to include("refresh_token=rt_only")
      expect(results.map { |t| t[:access_token] }).to eq(%w[kc_new kc_new])
      expect(read_creds["refresh_token"]).to eq("rt_rotated")
      expect(File.exist?("#{@creds_path}.lock")).to be(false)
    end

    it "breaks a genuinely stale lock (atomic rename) and re-acquires it" do
      lock_path = "#{@creds_path}.lock"
      File.write(lock_path, "999 0 deadbeefdeadbeef\n")
      old = Time.now - 120 # well past the 60s staleness threshold
      File.utime(old, old, lock_path)

      lock = KnoxCall::CredentialsFile::Lock.new(@creds_path)
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      lock.acquire
      begin
        expect(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).to be < 5
        # We now own the lock — the on-disk tag is ours, not the stale one.
        expect(File.read(lock_path)).not_to include("deadbeef")
      ensure
        lock.release
      end
      expect(File.exist?(lock_path)).to be(false)
      # No graveyard litter left behind by the atomic-rename break.
      expect(Dir.children(@dir).grep(/\.stale-/)).to be_empty
    end

    it "does NOT break a lock still within the stale window" do
      lock_path = "#{@creds_path}.lock"
      File.write(lock_path, "999 0 cafecafecafecafe\n")
      recent = Time.now - 30 # under the 60s threshold → still live
      File.utime(recent, recent, lock_path)

      lock = KnoxCall::CredentialsFile::Lock.new(@creds_path, timeout: 0.3, retry_interval: 0.05)
      expect { lock.acquire }.to raise_error(KnoxCall::Error, /credentials file lock/)
      # The live lock is untouched — neither broken nor overwritten.
      expect(File.exist?(lock_path)).to be(true)
      expect(File.read(lock_path)).to include("cafecafecafecafe")
    end

    it "release never deletes a lock now owned by a peer" do
      # Our lock gets broken as stale and re-taken by another process while we
      # were suspended: a blind unlink-by-path would delete the peer's LIVE
      # lock. Ownership-aware release must leave it alone.
      lock_path = "#{@creds_path}.lock"
      lock = KnoxCall::CredentialsFile::Lock.new(@creds_path)
      lock.acquire
      peer_content = "424242 #{Time.now.to_f.round(3)} #{'f' * 16}\n"
      File.write(lock_path, peer_content) # peer now holds it
      lock.release
      expect(File.exist?(lock_path)).to be(true)
      expect(File.read(lock_path)).to eq(peer_content)
      # Clean up the peer's lock so the tmpdir teardown is tidy.
      File.unlink(lock_path)
    end

    it "times out on a live (fresh) lock" do
      File.write("#{@creds_path}.lock", "123 #{Time.now.to_f.round(3)} beefbeefbeefbeef\n") # fresh mtime
      lock = KnoxCall::CredentialsFile::Lock.new(@creds_path, timeout: 0.3, retry_interval: 0.05)
      expect { lock.acquire }.to raise_error(KnoxCall::Error, /credentials file lock/)
    end
  end

  # -- Client seeding: file tenant/base_url, explicit always wins ------------------------

  describe "tenant/base_url seeding" do
    it "seeds tenant and base_url from the file when not set explicitly" do
      write_creds # tenant acme, api.example.test
      hit = stub_request(:get, "#{api}/v1/ping").to_return(status: 200, body: "{}")

      client = KnoxCall::Client.new # zero-config
      client.request("GET", "/v1/ping")

      expect(client.tenant).to eq("acme")
      expect(client.instance_variable_get(:@base_url)).to eq(api)
      expect(hit).to have_been_requested.once
    end

    it "lets explicit tenant and base_url beat the file" do
      write_creds
      client = KnoxCall::Client.new(tenant: "zeta", base_url: "https://explicit.example.test")
      client.token # fast path — stored token is fresh, no HTTP
      expect(client.tenant).to eq("zeta")
      expect(client.instance_variable_get(:@base_url)).to eq("https://explicit.example.test")
    end

    it "lets env tenant and base_url beat the file" do
      write_creds
      ENV["KNOXCALL_TENANT"] = "envcorp"
      ENV["KNOXCALL_BASE_URL"] = "https://env.example.test"

      client = KnoxCall::Client.new
      client.token
      expect(client.tenant).to eq("envcorp")
      expect(client.instance_variable_get(:@base_url)).to eq("https://env.example.test")
    end

    it "lets sandbox: true beat the file's base_url" do
      write_creds
      client = KnoxCall::Client.new(sandbox: true)
      expect(client.instance_variable_get(:@base_url)).to eq("https://sandbox.knoxcall.com")
      expect(client.tenant).to eq("acme") # tenant still seeds — sandbox says nothing about it
    end
  end

  # -- Env overrides for path + profile ---------------------------------------------------

  describe "path and profile overrides" do
    it "honors KNOXCALL_CREDENTIALS_FILE" do
      custom = File.join(@dir, "elsewhere", "creds.json")
      write_creds(path: custom, access_token: "kc_custom_path")
      ENV["KNOXCALL_CREDENTIALS_FILE"] = custom

      tok = KnoxCall::Client.new.token
      expect(tok[:access_token]).to eq("kc_custom_path")
    end

    it "honors KNOXCALL_PROFILE" do
      write_creds(profile: "default", tenant: "acme", access_token: "kc_default")
      write_creds(profile: "work", tenant: "globex", access_token: "kc_work")
      ENV["KNOXCALL_PROFILE"] = "work"

      client = KnoxCall::Client.new
      tok = client.token
      expect(tok[:access_token]).to eq("kc_work")
      expect(client.tenant).to eq("globex")
    end

    it "honors an explicit bootstrap with its own path and profile" do
      custom = File.join(@dir, "explicit.json")
      write_creds(path: custom, profile: "ci", tenant: "buildcorp", access_token: "kc_ci")
      ENV.delete("KNOXCALL_CREDENTIALS_FILE")

      client = KnoxCall::Client.new(
        bootstrap: KnoxCall::StoredCredentials.new(path: custom, profile: "ci")
      )
      expect(client.token[:access_token]).to eq("kc_ci")
      expect(client.tenant).to eq("buildcorp")
    end
  end

  # -- Secret hygiene -----------------------------------------------------------------

  describe "redaction" do
    it "keeps stored tokens out of #inspect output" do
      write_creds
      client = KnoxCall::Client.new
      client.token

      bootstrap = client.instance_variable_get(:@bootstrap)
      expect(bootstrap.inspect).to match(/StoredCredentials/) # holds only path/profile
      expect(bootstrap.inspect).not_to include("kc_stored_fresh")
      expect(bootstrap.inspect).not_to include("rt_1")
      expect(client.inspect).not_to include("kc_stored_fresh")
      expect(client.inspect).not_to include("rt_1")
    end
  end
end
