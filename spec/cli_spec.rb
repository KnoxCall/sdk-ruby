# CLI tests — `knoxcall login/logout/whoami` (PKCE, loopback, device flow).
# Mirrors knoxcall-python's tests/test_cli.py (PARITY §13).
#
# Remote HTTP is stubbed with webmock; the loopback callback server binds
# 127.0.0.1:0 and is hit for real with Net::HTTP from a thread (webmock is
# told to allow localhost). Credentials files live under Dir.mktmpdir only.

require "tmpdir"
require "stringio"
require "net/http"
require "knoxcall/cli"

RSpec.describe "KnoxCall CLI" do
  let(:api)       { "https://api.example.test" }
  let(:token_url) { "#{api}/oauth/token" }

  around do |example|
    vars = %w[KNOXCALL_TENANT KNOXCALL_ENVIRONMENT KNOXCALL_ACCESS_TOKEN
              KNOXCALL_API_KEY KNOXCALL_CLIENT_ID KNOXCALL_CLIENT_SECRET
              KNOXCALL_BASE_URL KNOXCALL_API_BASE_URL KNOXCALL_PROXY_BASE_URL
              KNOXCALL_PROFILE KNOXCALL_WRAP_SECRET]
    vars.each { |k| ENV.delete(k) }
    WebMock.disable_net_connect!(allow_localhost: true) # the loopback receiver is real
    Dir.mktmpdir("knoxcall-cli") do |dir|
      @dir = dir
      @creds_path = File.join(dir, "credentials.json")
      # spec_helper's outer around restores the pre-suite value afterwards.
      ENV["KNOXCALL_CREDENTIALS_FILE"] = @creds_path
      example.run
    end
  ensure
    WebMock.disable_net_connect!
    vars.each { |k| ENV.delete(k) }
  end

  # Run a block with captured stdout/stderr; returns [result, out, err].
  def capture_io
    old_out, old_err = $stdout, $stderr
    out, err = StringIO.new, StringIO.new
    $stdout, $stderr = out, err
    result = yield
    [result, out.string, err.string]
  ensure
    $stdout, $stderr = old_out, old_err
  end

  def parse!(argv)
    parsed = KnoxCall::CLI.parse(argv)
    raise "expected #{argv.inspect} to parse, got exit #{parsed}" unless parsed.is_a?(Array)
    parsed[1]
  end

  def hit(url)
    Net::HTTP.get_response(URI.parse(url))
  end

  def read_creds(profile: "default")
    KnoxCall::CredentialsFile.read_profile(@creds_path, profile)
  end

  def token_response(overrides = {})
    {
      status: 200,
      body: JSON.generate({ access_token: "kc_tok", refresh_token: "rt_tok",
                            token_type: "Bearer", expires_in: 3600, scope: "routes:read",
                            tenant: "acme", client_id: "kc_cli_real" }.merge(overrides)),
      headers: { "Content-Type" => "application/json" }
    }
  end

  def oauth_error(error, description = nil)
    body = { error: error }
    body[:error_description] = description if description
    { status: 400, body: JSON.generate(body), headers: { "Content-Type" => "application/json" } }
  end

  # -- PKCE (RFC 7636, S256) ---------------------------------------------------------

  describe "PKCE pair" do
    it "is S256 over an urlsafe verifier with fresh entropy per call" do
      verifier, challenge = KnoxCall::CLI::Login.generate_pkce_pair
      expect(verifier.length).to be_between(43, 128) # RFC 7636 §4.1
      expect(verifier).to match(/\A[A-Za-z0-9\-_]+\z/)
      digest = OpenSSL::Digest::SHA256.digest(verifier)
      expected = [digest].pack("m0").tr("+/", "-_").delete("=")
      expect(challenge).to eq(expected)
      expect(challenge).not_to include("=")
      expect(KnoxCall::CLI::Login.generate_pkce_pair[0]).not_to eq(verifier)
    end
  end

  describe "authorize URL" do
    it "uses the knoxcall-cli alias and S256" do
      url = KnoxCall::CLI::Login.build_authorize_url(
        api, redirect_uri: "http://127.0.0.1:51234/callback",
             state: "st_1", code_challenge: "chal", tenant: "acme"
      )
      expect(url).to start_with("#{api}/oauth/authorize?")
      query = URI.decode_www_form(URI.parse(url).query).to_h
      expect(query["client_id"]).to eq("knoxcall-cli")
      expect(query["response_type"]).to eq("code")
      expect(query["code_challenge_method"]).to eq("S256")
      expect(query["redirect_uri"]).to eq("http://127.0.0.1:51234/callback")
      expect(query["state"]).to eq("st_1")
      expect(query["tenant"]).to eq("acme")
    end
  end

  # -- Loopback callback server ---------------------------------------------------------

  describe "loopback callback server" do
    it "returns the code on a valid callback" do
      server = KnoxCall::CLI::Login::LoopbackServer.new
      begin
        t = Thread.new { hit("http://127.0.0.1:#{server.port}/callback?code=abc123&state=st1") }
        code = server.wait_for_code(expected_state: "st1", timeout: 5)
        expect(t.value.body).to include("Signed in")
        expect(code).to eq("abc123")
      ensure
        server.close
      end
    end

    it "raises on an error parameter" do
      server = KnoxCall::CLI::Login::LoopbackServer.new
      begin
        t = Thread.new do
          hit("http://127.0.0.1:#{server.port}/callback" \
              "?error=access_denied&error_description=nope&state=st1")
        end
        expect { server.wait_for_code(expected_state: "st1", timeout: 5) }
          .to raise_error(KnoxCall::CLI::Error, /nope/)
        expect(t.value.body).to include("Sign-in failed")
      ensure
        server.close
      end
    end

    it "raises on a state mismatch" do
      server = KnoxCall::CLI::Login::LoopbackServer.new
      begin
        t = Thread.new { hit("http://127.0.0.1:#{server.port}/callback?code=abc123&state=EVIL") }
        expect { server.wait_for_code(expected_state: "st1", timeout: 5) }
          .to raise_error(KnoxCall::CLI::Error, /state/i)
        t.join
      ensure
        server.close
      end
    end

    it "404s other paths and keeps listening for the callback" do
      server = KnoxCall::CLI::Login::LoopbackServer.new
      begin
        expect(hit("http://127.0.0.1:#{server.port}/favicon.ico").code).to eq("404")
        t = Thread.new { hit("http://127.0.0.1:#{server.port}/callback?code=ok&state=st1") }
        expect(server.wait_for_code(expected_state: "st1", timeout: 5)).to eq("ok")
        t.join
      ensure
        server.close
      end
    end
  end

  # -- Auth-code flow end-to-end (fake browser, stubbed token endpoint) ------------------

  describe "auth-code flow" do
    it "exchanges the code with the PKCE verifier and never prints the token" do
      form = nil
      stub_request(:post, token_url)
        .with { |req| form = req.body; true }
        .to_return(token_response(access_token: "kc_ac", refresh_token: "rt_ac"))

      fake_browser = lambda do |url|
        query = URI.decode_www_form(URI.parse(url).query).to_h
        expect(query["client_id"]).to eq("knoxcall-cli")
        Thread.new { hit("#{query['redirect_uri']}?code=authcode1&state=#{query['state']}") }
      end

      body, out, = capture_io do
        KnoxCall::CLI::Login.auth_code_flow(api, open_browser: fake_browser, timeout: 10)
      end

      expect(body["access_token"]).to eq("kc_ac")
      expect(form).to include("grant_type=authorization_code")
      expect(form).to include("code=authcode1")
      expect(form).to include("code_verifier=")
      expect(form).to include("client_id=knoxcall-cli")
      expect(out).to include("/oauth/authorize?") # the URL is always printed
      expect(out).not_to include("kc_ac")         # the token never hits stdout
      expect(out).not_to include("rt_ac")
    end
  end

  # -- Device flow polling -----------------------------------------------------------

  describe "device flow polling" do
    it "honors interval and slow_down sleeps, sleeping before the first poll" do
      calls = []
      stub_request(:post, token_url)
        .with { |req| calls << req.body; true }
        .to_return(
          oauth_error("authorization_pending"),
          oauth_error("slow_down"),
          oauth_error("authorization_pending"),
          token_response(access_token: "kc_dev")
        )

      sleeps = []
      body = KnoxCall::CLI::Login.poll_device_token(
        api, "dev_code_1", interval: 5, expires_in: 900, sleeper: ->(s) { sleeps << s }
      )

      expect(body["access_token"]).to eq("kc_dev")
      # 5s until slow_down, then bumped by +5 per RFC 8628 §3.5
      expect(sleeps).to eq([5, 5, 10, 10])
      expect(calls).to all(include("device_code=dev_code_1"))
      expect(calls[0]).to include("urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code")
    end

    it "stops on access_denied" do
      stub_request(:post, token_url).to_return(oauth_error("access_denied"))
      expect do
        KnoxCall::CLI::Login.poll_device_token(api, "dev_code_1", sleeper: ->(_s) {})
      end.to raise_error(KnoxCall::CLI::Error, /denied/)
    end

    it "stops on expired_token with the re-login hint" do
      stub_request(:post, token_url).to_return(oauth_error("expired_token"))
      expect do
        KnoxCall::CLI::Login.poll_device_token(api, "dev_code_1", sleeper: ->(_s) {})
      end.to raise_error(KnoxCall::CLI::Error, /knoxcall login/)
    end
  end

  # -- Profile write / merge / persist ---------------------------------------------------

  describe "profile write and merge" do
    it "merges profiles without clobbering the others" do
      KnoxCall::CredentialsFile.write_profile(@creds_path, "default",
                                              { "tenant" => "acme", "refresh_token" => "rt1" })
      KnoxCall::CredentialsFile.write_profile(@creds_path, "work",
                                              { "tenant" => "globex", "refresh_token" => "rt2" })

      doc = JSON.parse(File.read(@creds_path))
      expect(doc["version"]).to eq(1)
      expect(doc["profiles"].keys.sort).to eq(%w[default work])

      # overwriting one profile leaves the other intact
      KnoxCall::CredentialsFile.write_profile(@creds_path, "default",
                                              { "tenant" => "acme", "refresh_token" => "rt3" })
      expect(read_creds["refresh_token"]).to eq("rt3")
      expect(read_creds(profile: "work")["refresh_token"]).to eq("rt2")
    end

    it "persist_login records the tenant and real client_id extension members under the lock" do
      record = KnoxCall::CLI::Common.persist_login(
        path: @creds_path, profile: "default", base_url: api,
        token_body: {
          "access_token" => "kc_a", "refresh_token" => "rt_a", "expires_in" => 3600,
          "scope" => "routes:read", "tenant" => "acme",
          "client_id" => "kc_cli_real" # extension member: real per-tenant client
        }
      )

      on_disk = read_creds
      expect(on_disk["client_id"]).to eq("kc_cli_real")
      expect(on_disk["tenant"]).to eq("acme")
      expect(on_disk["base_url"]).to eq(api)
      expect(on_disk["refresh_token"]).to eq("rt_a")
      expect(on_disk["access_token_expires_at"]).to end_with("Z")
      expect(record["client_id"]).to eq("kc_cli_real")
      # the lock is released and no temp litter is left behind
      expect(Dir.children(@dir).sort).to eq(["credentials.json"])
    end

    it "persist_login creates the credentials directory on first login" do
      fresh = File.join(@dir, "brand", "new", "credentials.json")
      KnoxCall::CLI::Common.persist_login(
        path: fresh, profile: "default", base_url: api,
        token_body: { "access_token" => "kc_a", "expires_in" => 3600 }
      )
      expect(KnoxCall::CredentialsFile.read_profile(fresh, "default")["access_token"]).to eq("kc_a")
    end
  end

  # -- login command (device path, fully stubbed) ---------------------------------------

  describe "knoxcall login (device path)" do
    def stub_device_endpoints
      stub_request(:post, "#{api}/oauth/device_authorization")
        .with { |req| expect(req.body).to include("client_id=knoxcall-cli"); true }
        .to_return(
          status: 200,
          body: JSON.generate(
            device_code: "dc1", user_code: "ABCD-EFGH",
            verification_uri: "#{api}/oauth/activate",
            verification_uri_complete: "#{api}/oauth/activate?user_code=ABCD-EFGH",
            expires_in: 900, interval: 5
          ),
          headers: { "Content-Type" => "application/json" }
        )
      stub_request(:post, token_url)
        .to_return(token_response(access_token: "kc_dev", refresh_token: "rt_dev"))
    end

    %w[--device --no-browser].each do |flag|
      it "writes the profile with #{flag}" do
        stub_device_endpoints
        options = parse!(["login", flag, "--base-url", api])

        rc, out, = capture_io { KnoxCall::CLI::Login.run(options, sleeper: ->(_s) {}) }
        expect(rc).to eq(0)

        record = read_creds
        expect(record["client_id"]).to eq("kc_cli_real")
        expect(record["refresh_token"]).to eq("rt_dev")
        expect(record["tenant"]).to eq("acme")
        expect(record["base_url"]).to eq(api)

        expect(out).to include("ABCD-EFGH") # user code shown prominently
        expect(out).to include("acme")
        expect(out).to include(@creds_path)
        expect(out).not_to include("kc_dev") # tokens never printed
        expect(out).not_to include("rt_dev")
      end
    end

    it "respects --profile" do
      stub_device_endpoints
      options = parse!(["login", "--device", "--base-url", api, "--profile", "staging"])

      rc, = capture_io { KnoxCall::CLI::Login.run(options, sleeper: ->(_s) {}) }
      expect(rc).to eq(0)
      expect(read_creds(profile: "staging")["access_token"]).to eq("kc_dev")
      expect(read_creds).to be_nil
    end

    it "targets the sandbox host with --sandbox" do
      stub_request(:post, "https://sandbox.knoxcall.com/oauth/device_authorization")
        .to_return(status: 200,
                   body: JSON.generate(device_code: "dc1", user_code: "X", verification_uri: "u"),
                   headers: { "Content-Type" => "application/json" })
      stub_request(:post, "https://sandbox.knoxcall.com/oauth/token").to_return(token_response)

      options = parse!(["login", "--device", "--sandbox"])
      rc, = capture_io { KnoxCall::CLI::Login.run(options, sleeper: ->(_s) {}) }
      expect(rc).to eq(0)
      expect(read_creds["base_url"]).to eq("https://sandbox.knoxcall.com")
    end
  end

  # -- logout -----------------------------------------------------------------------

  describe "knoxcall logout" do
    def seed_profiles
      { "default" => "rt_default", "work" => "rt_work" }.each do |name, rt|
        KnoxCall::CredentialsFile.write_profile(
          @creds_path, name,
          {
            "tenant" => "acme", "base_url" => api, "client_id" => "kc_cli_real",
            "refresh_token" => rt, "access_token" => "kc_x",
            "access_token_expires_at" => KnoxCall::CredentialsFile.format_expiry(Time.now + 3600)
          }
        )
      end
    end

    it "revokes the refresh token and removes the profile (file deleted with the last one)" do
      seed_profiles
      revocations = []
      stub_request(:post, "#{api}/oauth/revoke")
        .with { |req| revocations << req.body; true }
        .to_return(status: 200, body: "{}")

      rc, out, = capture_io { KnoxCall::CLI.run(["logout", "--profile", "work"]) }
      expect(rc).to eq(0)
      expect(revocations.length).to eq(1)
      expect(revocations[0]).to include("token=rt_work")
      expect(revocations[0]).to include("token_type_hint=refresh_token")
      expect(revocations[0]).to include("client_id=kc_cli_real")
      expect(read_creds(profile: "work")).to be_nil
      expect(read_creds).not_to be_nil # other profile kept
      expect(out).to include("Logged out")
      expect(out).not_to include("rt_work") # the token never appears in output

      # removing the last profile deletes the file
      rc, = capture_io { KnoxCall::CLI.run(["logout"]) }
      expect(rc).to eq(0)
      expect(File.exist?(@creds_path)).to be(false)
    end

    it "removes the profile even when revocation is unreachable" do
      seed_profiles
      stub_request(:post, "#{api}/oauth/revoke").to_raise(Errno::ECONNREFUSED)

      rc, = capture_io { KnoxCall::CLI.run(["logout", "--profile", "work"]) }
      expect(rc).to eq(0)
      expect(read_creds(profile: "work")).to be_nil
    end

    it "is a no-op without stored credentials" do
      rc, out, = capture_io { KnoxCall::CLI.run(["logout"]) }
      expect(rc).to eq(0)
      expect(out).to include("nothing to do")
    end
  end

  # -- whoami ------------------------------------------------------------------------

  describe "knoxcall whoami" do
    it "prints tenant, slug, and plan from /v1/account via StoredCredentials" do
      KnoxCall::CredentialsFile.write_profile(
        @creds_path, "default",
        {
          "tenant" => "acme", "base_url" => api, "client_id" => "kc_cli_real",
          "refresh_token" => "rt_1", "access_token" => "kc_fresh",
          "access_token_expires_at" => KnoxCall::CredentialsFile.format_expiry(Time.now + 3600)
        }
      )
      stub_request(:get, "#{api}/v1/account")
        .with(headers: { "Authorization" => "Bearer kc_fresh" })
        .to_return(status: 200,
                   body: JSON.generate(data: { slug: "acme", name: "Acme Inc", plan: "pro" },
                                       meta: {}),
                   headers: { "Content-Type" => "application/json" })

      rc, out, = capture_io { KnoxCall::CLI.run(["whoami"]) }
      expect(rc).to eq(0)
      expect(out).to include("Tenant: Acme Inc")
      expect(out).to include("Slug:   acme")
      expect(out).to include("Plan:   pro")
      expect(out).to include("Profile: default (#{@creds_path})")
      expect(out).not_to include("kc_fresh")
      expect(out).not_to include("rt_1")
    end
  end

  # -- init --------------------------------------------------------------------------

  describe "knoxcall init" do
    # A fresh stored login so the SDK client uses the seeded access token
    # directly (no token-endpoint round trip), mirroring the whoami setup.
    def seed_login(profile: "default")
      KnoxCall::CredentialsFile.write_profile(
        @creds_path, profile,
        {
          "tenant" => "acme", "base_url" => api, "client_id" => "kc_cli_real",
          "refresh_token" => "rt_1", "access_token" => "kc_fresh",
          "access_token_expires_at" => KnoxCall::CredentialsFile.format_expiry(Time.now + 3600)
        }
      )
    end

    def stub_account
      stub_request(:get, "#{api}/v1/account")
        .to_return(status: 200,
                   body: JSON.generate(data: { slug: "acme", name: "Acme Inc", plan: "pro" }, meta: {}),
                   headers: { "Content-Type" => "application/json" })
    end

    it "scaffold mode confirms the tenant and prints the quickstart with no writes" do
      seed_login
      stub_account

      rc, out, = capture_io { KnoxCall::CLI.run(["init"]) }
      expect(rc).to eq(0)
      expect(out).to include("Signed in as Acme Inc.")
      expect(out).to include("Wrap a provider SDK through KnoxCall in two steps")
      expect(out).to include("--provider stripe")
      expect(out).to include("KNOXCALL_WRAP_SECRET")
      # SAFE: scaffold mode does NOT escrow or mint a token.
      expect(a_request(:post, "#{api}/v1/wrap/credentials")).not_to have_been_made
      expect(a_request(:post, "#{api}/v1/wrap/tokens")).not_to have_been_made
      # No files written beyond the seeded credentials file.
      expect(Dir.children(@dir).sort).to eq(["credentials.json"])
    end

    it "escrow mode escrows the key, mints a gateway URL, and never prints the raw key" do
      seed_login
      stub_account
      ENV["KNOXCALL_WRAP_SECRET"] = "sk_live_raw_secret"

      escrow_body = nil
      stub_request(:post, "#{api}/v1/wrap/credentials")
        .with { |req| escrow_body = JSON.parse(req.body); true }
        .to_return(status: 201,
                   body: JSON.generate(data: { secret_id: "sec_1", name: "wrap-stripe",
                                               provider: "stripe", allowed_hosts: ["api.stripe.com"],
                                               sandbox: false }, meta: {}),
                   headers: { "Content-Type" => "application/json" })
      token_body = nil
      stub_request(:post, "#{api}/v1/wrap/tokens")
        .with { |req| token_body = JSON.parse(req.body); true }
        .to_return(status: 201,
                   body: JSON.generate(data: { id: "wgt_1", token: "wgt_secret",
                                               base_url: "https://api.example.test/wg/wgt_secret/api.stripe.com",
                                               base_url_style: "path", host: "api.stripe.com",
                                               secret_id: "sec_1", sandbox: false, expires_at: nil }, meta: {}),
                   headers: { "Content-Type" => "application/json" })

      rc, out, = capture_io do
        KnoxCall::CLI.run(["init", "--provider", "stripe", "--secret-name", "wrap-stripe",
                           "--host", "API.Stripe.com"])
      end

      expect(rc).to eq(0)
      # The raw key travels ONCE in the escrow body, pinned to the lowercased host.
      expect(escrow_body).to eq("provider" => "stripe", "name" => "wrap-stripe",
                                "value" => "sk_live_raw_secret", "hosts" => ["api.stripe.com"])
      expect(token_body).to eq("secret" => "wrap-stripe", "host" => "api.stripe.com")
      expect(out).to include("Escrowed 'wrap-stripe' for api.stripe.com")
      expect(out).to include("https://api.example.test/wg/wgt_secret/api.stripe.com")
      # The raw provider key is NEVER printed.
      expect(out).not_to include("sk_live_raw_secret")
    end

    it "errors clearly when --provider is set but KNOXCALL_WRAP_SECRET is missing" do
      seed_login
      stub_account

      rc, _out, err = capture_io do
        KnoxCall::CLI.run(["init", "--provider", "stripe", "--secret-name", "wrap-stripe",
                           "--host", "api.stripe.com"])
      end
      expect(rc).to eq(1)
      expect(err).to include("error:")
      expect(err).to include("KNOXCALL_WRAP_SECRET")
      # The key is read only from the env var, never a flag — so nothing was escrowed.
      expect(a_request(:post, "#{api}/v1/wrap/credentials")).not_to have_been_made
    end

    it "errors when --provider is given without --secret-name" do
      seed_login
      stub_account
      ENV["KNOXCALL_WRAP_SECRET"] = "sk_live_raw_secret"

      rc, _out, err = capture_io do
        KnoxCall::CLI.run(["init", "--provider", "stripe", "--host", "api.stripe.com"])
      end
      expect(rc).to eq(1)
      expect(err).to include("--secret-name is required with --provider")
    end

    it "errors with a login hint when not logged in (never provisions)" do
      rc, _out, err = capture_io { KnoxCall::CLI.run(["init"]) }
      expect(rc).to eq(1)
      expect(err).to include("error: not logged in")
      expect(err).to include("knoxcall login")
      expect(err).not_to match(/\.rb:\d+/) # no backtrace
    end

    it "prints init help listing the escrow flags on --help" do
      rc, out, = capture_io { KnoxCall::CLI.run(["init", "--help"]) }
      expect(rc).to eq(0)
      expect(out).to include("--provider")
      expect(out).to include("--secret-name")
      expect(out).to include("--host")
    end

    it "appears in the root command list" do
      rc, out, = capture_io { KnoxCall::CLI.run(["--help"]) }
      expect(rc).to eq(0)
      expect(out).to include("init")
    end
  end

  # -- run() dispatch: exit codes + human-first errors --------------------------------

  describe "CLI.run dispatch" do
    it "prints a human error and exits 1 when not logged in" do
      rc, _out, err = capture_io { KnoxCall::CLI.run(["whoami"]) }
      expect(rc).to eq(1)
      expect(err).to include("error: not logged in")
      expect(err).to include("knoxcall login")
      expect(err).not_to match(/\.rb:\d+/) # no backtrace
    end

    it "exits 0 for logout with nothing stored" do
      rc, = capture_io { KnoxCall::CLI.run(["logout"]) }
      expect(rc).to eq(0)
    end

    it "prints help on --help and exits 0" do
      rc, out, = capture_io { KnoxCall::CLI.run(["--help"]) }
      expect(rc).to eq(0)
      expect(out).to include("login")
      expect(out).to include("logout")
      expect(out).to include("whoami")
    end

    it "prints subcommand help on `login --help` and exits 0" do
      rc, out, = capture_io { KnoxCall::CLI.run(["login", "--help"]) }
      expect(rc).to eq(0)
      expect(out).to include("--device")
      expect(out).to include("--no-browser")
      expect(out).to include("--sandbox")
    end

    it "exits 2 on an unknown command" do
      rc, _out, err = capture_io { KnoxCall::CLI.run(["frobnicate"]) }
      expect(rc).to eq(2)
      expect(err).to include("invalid choice")
    end

    it "exits 2 on a missing command" do
      rc, _out, err = capture_io { KnoxCall::CLI.run([]) }
      expect(rc).to eq(2)
      expect(err).to include("usage:")
    end

    it "exits 2 on an unknown flag" do
      rc, _out, err = capture_io { KnoxCall::CLI.run(["logout", "--bogus"]) }
      expect(rc).to eq(2)
      expect(err).to include("--bogus")
    end

    it "prints `aborted` and exits 1 on interrupt" do
      allow(KnoxCall::CLI::Whoami).to receive(:run).and_raise(Interrupt)
      KnoxCall::CredentialsFile.write_profile(@creds_path, "default", { "tenant" => "acme" })
      rc, _out, err = capture_io { KnoxCall::CLI.run(["whoami"]) }
      expect(rc).to eq(1)
      expect(err.strip).to eq("aborted")
    end
  end
end
