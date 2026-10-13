# Tests for the hardened request pipeline — mirrors knoxcall-python's
# tests/test_hardening.py (the SDK parity reference suite).

RSpec.describe "KnoxCall hardening" do
  API = "https://api.example.test".freeze
  PROXY = "https://acme.example.test".freeze
  TOKEN_URL = "#{API}/oauth/token".freeze

  before do
    %w[KNOXCALL_TENANT KNOXCALL_ENVIRONMENT KNOXCALL_ACCESS_TOKEN KNOXCALL_API_KEY
       KNOXCALL_CLIENT_ID KNOXCALL_CLIENT_SECRET KNOXCALL_BASE_URL
       KNOXCALL_API_BASE_URL KNOXCALL_PROXY_BASE_URL].each { |k| ENV.delete(k) }
  end

  def new_client(**opts)
    KnoxCall::Client.new(
      tenant: "acme",
      base_url: API,
      proxy_base_url: PROXY,
      client_id: "tk_x",
      client_secret: "sec",
      retry_base_delay: 0.001,
      **opts
    )
  end

  def token_body(token = "kc_live_aaaa", expires_in: 3600, token_type: "Bearer")
    {
      status: 200,
      body: JSON.generate(access_token: token, token_type: token_type, expires_in: expires_in),
      headers: { "Content-Type" => "application/json" }
    }
  end

  def stub_token(token = "kc_live_aaaa", expires_in: 3600)
    stub_request(:post, TOKEN_URL).to_return(token_body(token, expires_in: expires_in))
  end

  def headers_of(req)
    req.headers.transform_keys(&:downcase)
  end

  # The REAL server envelope (src/client-api/helpers.ts): every mock below
  # uses it — never a bare object, never a cursor.
  def empty_page_body
    JSON.generate(
      data: [],
      meta: { total: 0, page: 1, per_page: 20, total_pages: 0, request_id: "req-0" }
    )
  end

  # -- call() hardening --------------------------------------------------------

  describe "call() 401 purge + re-mint" do
    it "purges the token and retries once on 401, returning the second response" do
      stub_request(:post, TOKEN_URL)
        .to_return(token_body("kc_live_revoked"), token_body("kc_live_fresh"))
      stub_request(:get, "#{PROXY}/x")
        .with(headers: { "Authorization" => "Bearer kc_live_revoked" })
        .to_return(status: 401, body: '{"error":"Unauthorized"}')
      ok = stub_request(:get, "#{PROXY}/x")
           .with(headers: { "Authorization" => "Bearer kc_live_fresh" })
           .to_return(status: 200, body: '{"ok":true}')

      res = new_client.call("r_1", path: "/x")
      expect(res.code).to eq("200")
      expect(ok).to have_been_requested.once
      expect(a_request(:post, TOKEN_URL)).to have_been_made.twice
    end

    it "returns the second 401 instead of looping" do
      stub_token("kc_live_bad")
      proxy = stub_request(:get, "#{PROXY}/x").to_return(status: 401, body: '{"error":"Unauthorized"}')

      res = new_client.call("r_1", path: "/x")
      expect(res.code).to eq("401")
      expect(proxy).to have_been_requested.twice                  # original + single re-mint
      expect(a_request(:post, TOKEN_URL)).to have_been_made.twice # no infinite loop
    end
  end

  describe "call() transport retry safety" do
    it "retries an idle disconnect / read timeout for GET" do
      stub_token
      stub_request(:get, "#{PROXY}/x")
        .to_raise(Net::ReadTimeout).then
        .to_return(status: 200, body: '{"ok":true}')

      expect(new_client.call("r_1", path: "/x").code).to eq("200")
    end

    it "never replays a POST after a read timeout" do
      stub_token
      proxy = stub_request(:post, "#{PROXY}/x").to_raise(Net::ReadTimeout)

      expect {
        new_client.call("r_1", method: "POST", path: "/x", body: { a: 1 })
      }.to raise_error(KnoxCall::ConnectionTimeoutError)
      expect(proxy).to have_been_requested.once # mutating request NOT replayed
    end

    it "never replays a POST after a connection reset" do
      stub_token
      proxy = stub_request(:post, "#{PROXY}/x").to_raise(Errno::ECONNRESET)

      expect {
        new_client.call("r_1", method: "POST", path: "/x", body: { a: 1 })
      }.to raise_error(KnoxCall::NetworkError)
      expect(proxy).to have_been_requested.once
    end

    it "retries connection-refused even for POST (request never left the machine)" do
      stub_token
      proxy = stub_request(:post, "#{PROXY}/x")
              .to_raise(Errno::ECONNREFUSED).then
              .to_return(status: 200, body: '{"ok":true}')

      res = new_client.call("r_1", method: "POST", path: "/x", body: { a: 1 })
      expect(res.code).to eq("200")
      expect(proxy).to have_been_requested.twice
    end

    it "wraps exhausted transport failures in SDK error classes" do
      stub_token
      stub_request(:get, "#{PROXY}/x").to_raise(Errno::ECONNREFUSED)

      expect {
        new_client.call("r_1", path: "/x")
      }.to raise_error(KnoxCall::NetworkError)
    end
  end

  describe "call() header and argument handling" do
    it "lets explicit route/environment beat the caller's headers and preserves custom headers" do
      stub_token
      seen = {}
      stub_request(:get, "#{PROXY}/x?page=2")
        .with { |req| seen.merge!(headers_of(req)); true }
        .to_return(status: 200)

      new_client.call(
        "r_1",
        path: "/x",
        environment: "production",
        query: { page: 2 },
        headers: { "x-knoxcall-route" => "spoofed", "X-Custom" => "1" }
      )
      expect(seen["x-knoxcall-route"]).to eq("r_1")
      expect(seen["x-knoxcall-environment"]).to eq("production")
      expect(seen["x-custom"]).to eq("1")
    end

    it "accepts a per-call timeout override" do
      stub_token
      stub_request(:get, "#{PROXY}/x").to_return(status: 200)
      expect(new_client.call("r_1", path: "/x", timeout: 5).code).to eq("200")
    end
  end

  # -- SDK auth is the sole data-plane authority (PARITY §5) -------------------

  describe "call() strips caller-supplied proxy-auth headers" do
    it "drops caller Authorization / DPoP / x-knoxcall-key / agent identity, keeps the SDK credential and non-auth headers" do
      stub_token("kc_live_sdk")
      seen = {}
      stub_request(:get, "#{PROXY}/x")
        .with { |req| seen.merge!(headers_of(req)); true }
        .to_return(status: 200)

      new_client.call(
        "r_1", path: "/x",
        headers: {
          "Authorization" => "Bearer kc_attacker",     # caller-forged bearer
          "X-Knoxcall-Key" => "tk_attacker",           # mixed casing on purpose
          "x-knoxcall-agent-id" => "agent-evil",
          "X-KnoxCall-Agent-Token" => "tok-evil",
          "DPoP" => "forged-proof",
          # The interceptors' reroute marker (PARITY §21.2) is SDK-owned too: an
          # app must not relabel its own direct calls as intercepted.
          "X-KnoxCall-Origin" => "sdk-intercept",
          "X-Custom" => "keep-me"                       # non-auth: must survive
        }
      )

      # The SDK credential is the sole authority; every injected identity is gone.
      expect(seen["authorization"]).to eq("Bearer kc_live_sdk")
      expect(seen["x-knoxcall-key"]).to be_nil
      expect(seen["x-knoxcall-agent-id"]).to be_nil
      expect(seen["x-knoxcall-agent-token"]).to be_nil
      expect(seen["dpop"]).to be_nil
      expect(seen["x-knoxcall-origin"]).to be_nil
      # non-auth caller headers still pass through untouched
      expect(seen["x-custom"]).to eq("keep-me")
      # SDK-set route header is unaffected by the strip
      expect(seen["x-knoxcall-route"]).to eq("r_1")
    end

    it "a direct call carries no x-knoxcall-origin (absence is direct on the server), and rejects an unknown marker" do
      stub_token("kc_live_sdk")
      seen = {}
      stub_request(:get, "#{PROXY}/x")
        .with { |req| seen.merge!(headers_of(req)); true }
        .to_return(status: 200)

      new_client.call("r_1", path: "/x")
      expect(seen["x-knoxcall-route"]).to eq("r_1")
      expect(seen["x-knoxcall-origin"]).to be_nil

      seen.clear
      new_client.route("r_1").get("/x")
      expect(seen["x-knoxcall-origin"]).to be_nil

      expect { new_client.call("r_1", path: "/x", _origin: "something-else") }
        .to raise_error(ArgumentError, /unknown call origin/)
    end

    it "on the legacy-key path, strips a caller Authorization the proxy would otherwise honor over x-knoxcall-key" do
      # A legacy tk_ credential travels as x-knoxcall-key and the SDK sets NO
      # Authorization — so a surviving caller Bearer would be honored by the
      # proxy over our key. It must be stripped.
      stub_token("tk_live_legacy")
      seen = {}
      stub_request(:get, "#{PROXY}/x")
        .with { |req| seen.merge!(headers_of(req)); true }
        .to_return(status: 200)

      new_client.call(
        "r_1", path: "/x",
        headers: { "Authorization" => "Bearer kc_attacker", "x-knoxcall-key" => "tk_attacker" }
      )

      expect(seen["x-knoxcall-key"]).to eq("tk_live_legacy") # SDK's own key
      expect(seen["authorization"]).to be_nil                # caller bearer stripped, SDK sets none
    end

    it "strips caller proxy-auth headers on bound-route delegation" do
      stub_token("kc_live_sdk")
      seen = {}
      stub_request(:get, "#{PROXY}/x")
        .with { |req| seen.merge!(headers_of(req)); true }
        .to_return(status: 200)

      new_client.route("r_1").get("/x", headers: { "x-knoxcall-agent-id" => "agent-evil", "X-Keep" => "1" })

      expect(seen["x-knoxcall-agent-id"]).to be_nil
      expect(seen["authorization"]).to eq("Bearer kc_live_sdk")
      expect(seen["x-keep"]).to eq("1")
    end

    it "strips caller proxy-auth headers on ephemeral() too" do
      stub_token("kc_live_sdk")
      seen = {}
      stub_request(:post, "#{API}/v1/proxy")
        .with { |req| seen.merge!(headers_of(req)); true }
        .to_return(status: 200)

      new_client.ephemeral(
        "https://upstream.example/charge", method: "POST",
        headers: {
          "Authorization" => "Bearer kc_attacker",
          "x-knoxcall-agent-id" => "agent-evil",
          "X-Keep" => "1"
        }
      )

      expect(seen["authorization"]).to eq("Bearer kc_live_sdk")
      expect(seen["x-knoxcall-agent-id"]).to be_nil
      expect(seen["x-keep"]).to eq("1")
    end
  end

  # -- ephemeral() wrap-support options (PR2) ----------------------------------

  describe "ephemeral() wrap-support headers" do
    it "sends X-Knox-Proxy-Mode: transparent when mode: \"transparent\"" do
      stub_token("kc_live_sdk")
      seen = {}
      stub_request(:post, "#{API}/v1/proxy")
        .with { |req| seen.merge!(headers_of(req)); true }
        .to_return(status: 200)

      new_client.ephemeral(
        "https://upstream.example/charge", method: "POST",
        mode: "transparent"
      )

      expect(seen["x-knox-proxy-mode"]).to eq("transparent")
    end

    it "maps upstream_authorization to X-Knox-Upstream-Authorization verbatim" do
      stub_token("kc_live_sdk")
      seen = {}
      stub_request(:post, "#{API}/v1/proxy")
        .with { |req| seen.merge!(headers_of(req)); true }
        .to_return(status: 200)

      new_client.ephemeral(
        "https://upstream.example/charge", method: "POST",
        upstream_authorization: "Bearer sk_live_provider_secret"
      )

      expect(seen["x-knox-upstream-authorization"]).to eq("Bearer sk_live_provider_secret")
      # The SDK's own KnoxCall auth is unaffected.
      expect(seen["authorization"]).to eq("Bearer kc_live_sdk")
    end

    it "maps upstream_auth_secret and upstream_auth_scheme to their escrow headers" do
      stub_token("kc_live_sdk")
      seen = {}
      stub_request(:post, "#{API}/v1/proxy")
        .with { |req| seen.merge!(headers_of(req)); true }
        .to_return(status: 200)

      new_client.ephemeral(
        "https://upstream.example/charge", method: "POST",
        upstream_auth_secret: "stripe-live-key", upstream_auth_scheme: "Bearer"
      )

      expect(seen["x-knox-upstream-auth-secret"]).to eq("stripe-live-key")
      expect(seen["x-knox-upstream-auth-scheme"]).to eq("Bearer")
      # The SDK's own KnoxCall auth is unaffected.
      expect(seen["authorization"]).to eq("Bearer kc_live_sdk")
    end

    it "omits both headers by default (purely additive)" do
      stub_token("kc_live_sdk")
      seen = {}
      stub_request(:post, "#{API}/v1/proxy")
        .with { |req| seen.merge!(headers_of(req)); true }
        .to_return(status: 200)

      new_client.ephemeral("https://upstream.example/charge", method: "POST")

      expect(seen).not_to have_key("x-knox-proxy-mode")
      expect(seen).not_to have_key("x-knox-upstream-authorization")
      expect(seen).not_to have_key("x-knox-upstream-auth-secret")
      expect(seen).not_to have_key("x-knox-upstream-auth-scheme")
    end
  end

  # -- Body encoding -----------------------------------------------------------

  describe "request body encoding" do
    it "encodes Time/Date/DateTime/BigDecimal and symbols" do
      stub_token
      seen = {}
      stub_request(:post, "#{PROXY}/x")
        .with { |req| seen[:body] = req.body; seen[:ct] = headers_of(req)["content-type"]; true }
        .to_return(status: 200)

      new_client.call(
        "r_1", method: "POST", path: "/x",
        body: {
          when: Time.utc(2026, 6, 10, 12, 30),
          stamp: DateTime.new(2026, 6, 10, 12, 30, 0),
          day: Date.new(2026, 6, 10),
          amount: BigDecimal("19.99"),
          tags: [:a, "b"]
        }
      )
      parsed = JSON.parse(seen[:body])
      expect(seen[:ct]).to eq("application/json")
      expect(parsed["when"]).to eq("2026-06-10T12:30:00Z")
      expect(parsed["stamp"]).to start_with("2026-06-10T12:30:00")
      expect(parsed["day"]).to eq("2026-06-10")
      expect(parsed["amount"]).to be_within(0.001).of(19.99)
      expect(parsed["tags"]).to eq(%w[a b])
    end

    it "passes raw String bodies through untouched with the caller's Content-Type" do
      stub_token
      seen = {}
      stub_request(:post, "#{PROXY}/x")
        .with { |req| seen[:body] = req.body; seen[:ct] = headers_of(req)["content-type"]; true }
        .to_return(status: 200)

      new_client.call(
        "r_1", method: "POST", path: "/x",
        body: "%PDF-1.4 raw", headers: { "Content-Type" => "application/pdf" }
      )
      expect(seen[:body]).to eq("%PDF-1.4 raw")
      expect(seen[:ct]).to eq("application/pdf")
    end

    it "uses the json_encoder hook for unknown types" do
      stub_token
      seen = {}
      stub_request(:post, "#{PROXY}/x")
        .with { |req| seen[:body] = req.body; true }
        .to_return(status: 200)

      money = Struct.new(:cents)
      client = new_client(json_encoder: ->(v) { v.is_a?(money) ? v.cents / 100.0 : v })
      client.call("r_1", method: "POST", path: "/x", body: { total: money.new(1999) })
      expect(JSON.parse(seen[:body])["total"]).to be_within(0.001).of(19.99)
    end
  end

  # -- Token lifecycle ---------------------------------------------------------

  describe "token lifecycle" do
    it "does not refetch short-lived tokens on every request (refresh-ahead = min(300, lifetime/2))" do
      stub_token("kc_live_short", expires_in: 60)
      stub_request(:get, "#{PROXY}/x").to_return(status: 200)

      client = new_client
      5.times { client.call("r_1", path: "/x") }
      expect(a_request(:post, TOKEN_URL)).to have_been_made.once
    end

    it "falls back to a stale-but-valid token when the token endpoint is down" do
      stub_request(:post, TOKEN_URL).to_return(status: 503, body: '{"error":"unavailable"}')
      seen = {}
      stub_request(:get, "#{PROXY}/x")
        .with { |req| seen.merge!(headers_of(req)); true }
        .to_return(status: 200)

      client = new_client
      # Inside the 5-minute refresh-ahead window, but still genuinely valid.
      client.instance_variable_set(:@token_cache, {
        access_token: "kc_live_stale", token_type: "Bearer",
        expires_at: Time.now + 60, lifetime: 3600.0
      })
      expect(client.call("r_1", path: "/x").code).to eq("200")
      expect(seen["authorization"]).to eq("Bearer kc_live_stale")
    end

    it "tolerates a string expires_in" do
      stub_request(:post, TOKEN_URL).to_return(
        status: 200,
        body: JSON.generate(access_token: "kc_live_str", token_type: "Bearer", expires_in: "3600")
      )
      stub_request(:get, "#{PROXY}/x").to_return(status: 200)

      client = new_client
      2.times { client.call("r_1", path: "/x") }
      expect(a_request(:post, TOKEN_URL)).to have_been_made.once
    end

    it "raises a typed error on a non-JSON 200 token response (edge-proxy HTML)" do
      stub_request(:post, TOKEN_URL).to_return(status: 200, body: "<html>maintenance</html>")
      expect { new_client.call("r_1", path: "/x") }.to raise_error(KnoxCall::TokenError, /unexpected response/)
    end

    it "raises a typed error when access_token is missing" do
      stub_request(:post, TOKEN_URL).to_return(status: 200, body: '{"token_type":"Bearer"}')
      expect { new_client.call("r_1", path: "/x") }.to raise_error(KnoxCall::TokenError)
    end

  end

  # -- DPoP (PARITY §7) ---------------------------------------------------------

  describe "DPoP" do
    # Stdlib-only base64url — the suite must run with the base64 gem absent
    # from the bundle, so lib/ can never silently re-acquire the dependency
    # (the README promises stdlib only; base64 left the default set in 3.4).
    def b64url_encode(bytes)
      [bytes].pack("m0").tr("+/", "-_").delete("=")
    end

    def b64url_decode(part)
      (part.tr("-_", "+/") + "=" * ((4 - part.length % 4) % 4)).unpack1("m0")
    end

    def decode_jwt_part(part)
      JSON.parse(b64url_decode(part))
    end

    it "raises a clear error for a DPoP-bound token when no keypair is held" do
      # The server hands back a DPoP-bound token without ever challenging
      # (no invalid_dpop_proof), so no keypair exists in either mode — the
      # SDK must fail loudly, never send "Authorization: DPoP" proofless.
      %w[never auto].each do |mode|
        WebMock.reset!
        stub_request(:post, TOKEN_URL).to_return(
          status: 200,
          body: JSON.generate(access_token: "kc_live_dpop", token_type: "DPoP", expires_in: 3600)
        )
        expect { new_client(dpop: mode).call("r_1", path: "/x") }
          .to raise_error(KnoxCall::TokenError, /DPoP/)
      end
    end

    it "rejects unknown dpop modes at construction" do
      expect { new_client(dpop: "sometimes") }.to raise_error(ArgumentError, /dpop/)
    end

    it "surfaces a DPoP-required server as a typed error in never mode, without a proof retry" do
      stub_request(:post, TOKEN_URL).to_return(
        status: 400, headers: { "Content-Type" => "application/json" },
        body: JSON.generate(error: "invalid_dpop_proof", error_description: "DPoP proof required")
      )
      expect { new_client(dpop: "never").call("r_1", path: "/x") }
        .to raise_error(KnoxCall::APIError) { |e| expect(e.body["error"]).to eq("invalid_dpop_proof") }
      # The auto-upgrade retry belongs to "auto" only — never mode must not
      # quietly generate a keypair behind the caller's explicit opt-out.
      expect(a_request(:post, TOKEN_URL)).to have_been_made.once
    end

    it "auto-upgrades to DPoP when the client record requires it, and stays DPoP thereafter" do
      token_proofs = []
      stub_request(:post, TOKEN_URL).to_return do |req|
        token_proofs << req.headers.transform_keys(&:downcase)["dpop"]
        if token_proofs.length == 1
          { status: 400, headers: { "Content-Type" => "application/json" },
            body: JSON.generate(error: "invalid_dpop_proof", error_description: "DPoP proof required") }
        else
          { status: 200, headers: { "Content-Type" => "application/json" },
            body: JSON.generate(access_token: "kc_live_dpop", token_type: "DPoP", expires_in: 3600) }
        end
      end
      call_headers = []
      stub_request(:get, "#{PROXY}/x").to_return do |req|
        call_headers << req.headers.transform_keys(&:downcase)
        { status: 200, body: "{}" }
      end

      client = new_client # default mode: auto
      2.times { client.call("r_1", path: "/x") }

      # Bearer first, one proof-carrying retry after invalid_dpop_proof.
      expect(token_proofs.length).to eq(2)
      expect(token_proofs[0]).to be_nil
      expect(token_proofs[1].split(".").length).to eq(3)

      # Thereafter every call runs as DPoP off the cached token, with a
      # FRESH proof per request (new jti each time — proofs never reused).
      expect(call_headers.length).to eq(2)
      jtis = call_headers.map do |h|
        expect(h["authorization"]).to eq("DPoP kc_live_dpop")
        decode_jwt_part(h["dpop"].to_s.split(".")[1])["jti"]
      end
      expect(jtis.uniq.length).to eq(2)
    end

    it "sends a proof on the token request and the call in always mode" do
      stub_request(:post, TOKEN_URL).to_return(
        status: 200, headers: { "Content-Type" => "application/json" },
        body: JSON.generate(access_token: "kc_live_dpop", token_type: "DPoP", expires_in: 3600)
      )
      stub_request(:get, "#{PROXY}/x?a=1").to_return(status: 200, body: "{}")

      new_client(dpop: "always").call("r_1", path: "/x", query: { a: "1" })

      # Token request itself carries a proof (POST, no ath — no token yet),
      # with the public JWK in the header (and ONLY the public part).
      expect(a_request(:post, TOKEN_URL).with { |req|
        parts = headers_of(req)["dpop"].to_s.split(".")
        next false unless parts.length == 3
        header = decode_jwt_part(parts[0])
        claims = decode_jwt_part(parts[1])
        header["alg"] == "ES256" && header["typ"] == "dpop+jwt" &&
          header["jwk"].is_a?(Hash) && header["jwk"]["kty"] == "EC" &&
          header["jwk"]["crv"] == "P-256" &&
          !header["jwk"]["x"].to_s.empty? && !header["jwk"]["y"].to_s.empty? &&
          !header["jwk"].key?("d") && # never leak the private scalar
          claims["htm"] == "POST" && claims["htu"] == TOKEN_URL && !claims.key?("ath")
      }).to have_been_made.once

      # Data-plane request: DPoP scheme + fresh proof bound to the token
      # (ath = base64url(SHA-256(access_token))), htu stripped of the query.
      expected_ath = b64url_encode(OpenSSL::Digest::SHA256.digest("kc_live_dpop"))
      expect(a_request(:get, "#{PROXY}/x?a=1").with { |req|
        h = headers_of(req)
        claims = decode_jwt_part(h["dpop"].to_s.split(".")[1])
        h["authorization"] == "DPoP kc_live_dpop" &&
          claims["htm"] == "GET" && claims["htu"] == "#{PROXY}/x" && claims["ath"] == expected_ath
      }).to have_been_made.once
    end

    it "signs proofs on management requests too" do
      stub_request(:post, TOKEN_URL).to_return(
        status: 200, headers: { "Content-Type" => "application/json" },
        body: JSON.generate(access_token: "kc_live_dpop", token_type: "DPoP", expires_in: 3600)
      )
      stub_request(:get, "#{API}/v1/routes?page=2")
        .to_return(status: 200, body: empty_page_body, headers: { "Content-Type" => "application/json" })

      new_client(dpop: "always").request("GET", "/v1/routes", query: { page: 2 })

      expected_ath = b64url_encode(OpenSSL::Digest::SHA256.digest("kc_live_dpop"))
      expect(a_request(:get, "#{API}/v1/routes?page=2").with { |req|
        h = headers_of(req)
        claims = decode_jwt_part(h["dpop"].to_s.split(".")[1])
        h["authorization"] == "DPoP kc_live_dpop" &&
          claims["htm"] == "GET" && claims["htu"] == "#{API}/v1/routes" && # query stripped
          claims["ath"] == expected_ath
      }).to have_been_made.once
    end

    it "produces stable thumbprints and well-formed proofs" do
      kp = KnoxCall::DpopKeyPair.generate
      expect(kp.thumbprint).to eq(kp.thumbprint)
      expect(kp.thumbprint).not_to be_empty

      proof = kp.sign("get", "https://x.example/path?q=1#frag", access_token: "kc_live_tok")
      parts = proof.split(".")
      expect(parts.length).to eq(3)
      claims = decode_jwt_part(parts[1])
      expect(claims["htm"]).to eq("GET")
      expect(claims["htu"]).to eq("https://x.example/path")
      expected_ath = b64url_encode(OpenSSL::Digest::SHA256.digest("kc_live_tok"))
      expect(claims["ath"]).to eq(expected_ath)
      claims2 = decode_jwt_part(
        kp.sign("get", "https://x.example/path", access_token: "kc_live_tok").split(".")[1]
      )
      expect(claims2["jti"]).not_to eq(claims["jti"])
    end

    it "signs proofs that verify against the JWK they carry (raw r||s, not DER)" do
      proof = KnoxCall::DpopKeyPair.generate.sign("POST", "https://x.example/oauth/token")
      h_b64, p_b64, s_b64 = proof.split(".")

      # JOSE ES256 signatures are the fixed-width 64-byte P1363 form.
      sig = b64url_decode(s_b64)
      expect(sig.bytesize).to eq(64)

      # Rebuild the public key from the proof's own JWK and verify the
      # signature over the signing input — round-trips both the JWK export
      # and the DER→P1363 conversion against OpenSSL's verifier.
      jwk = decode_jwt_part(h_b64)["jwk"]
      point = "\x04".b + b64url_decode(jwk["x"]) + b64url_decode(jwk["y"])
      spki = OpenSSL::ASN1::Sequence([
        OpenSSL::ASN1::Sequence([OpenSSL::ASN1::ObjectId("id-ecPublicKey"),
                                 OpenSSL::ASN1::ObjectId("prime256v1")]),
        OpenSSL::ASN1::BitString(point)
      ])
      pub = OpenSSL::PKey.read(spki.to_der)
      der = OpenSSL::ASN1::Sequence([
        OpenSSL::ASN1::Integer(OpenSSL::BN.new(sig[0, 32], 2)),
        OpenSSL::ASN1::Integer(OpenSSL::BN.new(sig[32, 32], 2))
      ]).to_der
      expect(pub.verify(OpenSSL::Digest.new("SHA256"), der, "#{h_b64}.#{p_b64}")).to be(true)
    end
  end

  # -- Thread safety -----------------------------------------------------------

  describe "thread safety" do
    it "serves many threads from one client with a single token fetch" do
      stub_token
      stub_request(:get, "#{PROXY}/x").to_return(status: 200, body: '{"ok":true}')

      client = new_client
      codes = Queue.new
      threads = Array.new(16) do
        Thread.new { 2.times { codes << client.call("r_1", path: "/x").code } }
      end
      threads.each(&:join)

      expect(codes.size).to eq(32)
      expect(Array.new(32) { codes.pop }).to all(eq("200"))
      expect(a_request(:post, TOKEN_URL)).to have_been_made.once # single-flight held across threads
    end
  end

  # -- Management path (request()) ---------------------------------------------

  describe "management request retries" do
    it "transparently re-auths once on 401" do
      stub_request(:post, TOKEN_URL)
        .to_return(token_body("kc_live_old"), token_body("kc_live_new"))
      stub_request(:get, "#{API}/v1/routes")
        .with(headers: { "Authorization" => "Bearer kc_live_old" })
        .to_return(status: 401, body: '{"error":"Unauthorized"}')
      stub_request(:get, "#{API}/v1/routes")
        .with(headers: { "Authorization" => "Bearer kc_live_new" })
        .to_return(status: 200, body: empty_page_body)

      expect(new_client.routes.list["data"]).to eq([])
    end

    it "retries 503 and succeeds" do
      stub_token
      stub_request(:get, "#{API}/v1/routes")
        .to_return({ status: 503, body: '{"error":"unavailable"}' }, { status: 200, body: empty_page_body })

      expect(new_client.routes.list["data"]).to eq([])
    end

    it "does NOT retry 409 (a real conflict does not resolve by replaying)" do
      stub_token
      conflict = stub_request(:post, "#{API}/v1/routes").to_return(status: 409, body: '{"error":"conflict"}')

      expect { new_client.routes.create(name: "dup") }.to raise_error(KnoxCall::APIError)
      expect(conflict).to have_been_requested.once
    end

    it "keeps the idempotency key stable across retries of one logical request" do
      stub_token
      keys = []
      ok = { status: 200, body: '{"data":{"id":"r_1"},"meta":{"request_id":"req-1"}}' }
      stub_request(:post, "#{API}/v1/routes")
        .with { |req| keys << headers_of(req)["x-idempotency-key"]; true }
        .to_return({ status: 503, body: '{"error":{"type":"server_error","message":"unavailable"}}' }, ok)

      expect(new_client.routes.create(name: "r")).to eq("id" => "r_1")
      expect(keys.length).to eq(2)
      expect(keys.uniq.length).to eq(1)
      expect(keys.first).to match(/\A[0-9A-HJKMNP-TV-Z]{26}\z/)
    end

    it "retries transport failures (idempotency key makes replay safe)" do
      stub_token
      stub_request(:get, "#{API}/v1/routes")
        .to_raise(Errno::ECONNRESET).then
        .to_return(status: 200, body: empty_page_body)

      expect(new_client.routes.list["data"]).to eq([])
    end

    it "caps a server Retry-After at 30 seconds" do
      client = new_client
      short = KnoxCall::RateLimitError.new("rate_limited", 429, headers: { "retry-after" => "2" })
      long = KnoxCall::RateLimitError.new("rate_limited", 429, headers: { "retry-after" => "600" })
      expect(client.send(:retry_delay, short, 1)).to eq(2.0)
      expect(client.send(:retry_delay, long, 1)).to eq(30.0)
    end

    it "maps a 503 dependency_unavailable to ServerError — never AuthenticationError — with code, request id and Retry-After, honoured like a 429's" do
      # KnoxCall could not reach one of its own dependencies: a retryable
      # server fault carrying Retry-After (it used to be an opaque 401 on the
      # data plane).
      stub_token
      stub_request(:get, "#{API}/v1/routes").to_return(
        status: 503,
        headers: { "Retry-After" => "5", "X-Request-Id" => "req-dep-1", "Content-Type" => "application/json" },
        body: '{"error":{"type":"dependency_unavailable","message":"KnoxCall could not reach its control plane in time.","request_id":"req-dep-1","dependency":"control_plane","retry_after":5}}'
      )
      client = new_client(retry_max_attempts: 1)
      err = begin
        client.routes.list
        nil
      rescue KnoxCall::ServerError => e
        e
      end
      expect(err).to be_a(KnoxCall::ServerError)
      expect(err).not_to be_a(KnoxCall::AuthenticationError)
      expect(err.status_code).to eq(503)
      expect(err.code).to eq("dependency_unavailable")
      expect(err.request_id).to eq("req-dep-1")
      expect(err.retry_after).to eq(5.0)
      expect(client.send(:retry_delay, err, 1)).to eq(5.0)
      long = KnoxCall::ServerError.new("dependency_unavailable", 503, headers: { "retry-after" => "600" })
      expect(client.send(:retry_delay, long, 1)).to eq(30.0)
      # A plain 5xx with no header keeps the jittered backoff.
      plain = KnoxCall::ServerError.new("internal_error", 500)
      expect(plain.retry_after).to be_nil
      expect(client.send(:retry_delay, plain, 1)).to be <= 30.0
    end

    it "maps 403 to PermissionDeniedError and extracts the server's error message" do
      stub_token
      stub_request(:get, "#{API}/v1/routes").to_return(
        status: 403,
        body: '{"error":{"type":"forbidden","message":"missing scope routes:read","request_id":"req-9"}}'
      )

      expect { new_client.routes.list }
        .to raise_error(KnoxCall::PermissionDeniedError, /missing scope routes:read/)
    end

    it "maps 402 to PaymentRequiredError (plan/billing limit)" do
      stub_token
      stub_request(:get, "#{API}/v1/routes").to_return(
        status: 402,
        body: '{"error":{"type":"plan_limit","message":"route quota exhausted — upgrade","request_id":"req-402"}}'
      )

      expect { new_client.routes.list }
        .to raise_error(KnoxCall::PaymentRequiredError, /upgrade/) { |e| expect(e.code).to eq("plan_limit") }
    end
  end

  # -- API version pinning (KnoxCall-Version header) ---------------------------

  describe "KnoxCall-Version header" do
    it "defaults the pinned version to the only server-known value" do
      expect(KnoxCall::Client::DEFAULT_API_VERSION).to eq("2026-08-05")
    end

    it "sends KnoxCall-Version pinned to the SDK default on management requests" do
      stub_token
      seen = {}
      stub_request(:get, "#{API}/v1/routes")
        .with { |req| seen.merge!(headers_of(req)); true }
        .to_return(status: 200, body: empty_page_body, headers: { "Content-Type" => "application/json" })

      new_client.routes.list
      expect(seen["knoxcall-version"]).to eq("2026-08-05")
      expect(new_client.api_version).to eq("2026-08-05")
    end

    it "lets an explicit api_version override the pinned default" do
      stub_token
      seen = {}
      stub_request(:get, "#{API}/v1/routes")
        .with { |req| seen.merge!(headers_of(req)); true }
        .to_return(status: 200, body: empty_page_body, headers: { "Content-Type" => "application/json" })

      new_client(api_version: "2026-09-30").routes.list
      expect(seen["knoxcall-version"]).to eq("2026-09-30")
    end
  end

  # -- Naming + deprecated aliases ----------------------------------------------

  describe "naming parity and deprecated aliases" do
    it "keeps the pre-release *Bootstrap names as aliases" do
      expect(KnoxCall::ClientCredentialsBootstrap).to equal(KnoxCall::ClientCredentials)
      expect(KnoxCall::AccessTokenBootstrap).to equal(KnoxCall::AccessToken)
      expect(KnoxCall::OidcTokenExchangeBootstrap).to equal(KnoxCall::OIDCTokenExchange)
    end

    it "defaults the type discriminator" do
      expect(KnoxCall::ClientCredentials.new(client_id: "tk_x", client_secret: "sec").type)
        .to eq("client_credentials")
      expect(KnoxCall::AccessToken.new(access_token: "kc_live_x").type).to eq("access_token")
      expect(KnoxCall::OIDCTokenExchange.new(subject_token: "jwt", issuer: "https://oidc.vercel.com").type)
        .to eq("oidc_token_exchange")
    end

    it "keeps PermissionError as a deprecated alias of PermissionDeniedError" do
      expect(KnoxCall::PermissionError).to equal(KnoxCall::PermissionDeniedError)
    end
  end

  # -- Secret hygiene ------------------------------------------------------------

  describe "secret redaction" do
    it "redacts bootstrap secrets in #inspect" do
      cc = KnoxCall::ClientCredentials.new(client_id: "tk_x", client_secret: "sec-xyz")
      expect(cc.inspect).not_to include("sec-xyz")
      expect(cc.inspect).to include("tk_x") # client_id is not sensitive

      at = KnoxCall::AccessToken.new(access_token: "kc_live_secret")
      expect(at.inspect).not_to include("kc_live_secret")

      oidc = KnoxCall::OIDCTokenExchange.new(subject_token: "jwt-secret", issuer: "https://oidc.vercel.com")
      expect(oidc.inspect).not_to include("jwt-secret")
      expect(oidc.inspect).to include("vercel")
    end

    it "redacts credentials and cached tokens in Client#inspect" do
      stub_token("kc_live_cached")
      stub_request(:get, "#{PROXY}/x").to_return(status: 200)

      client = new_client(api_key: nil)
      client.call("r_1", path: "/x")
      expect(client.inspect).not_to include("sec")
      expect(client.inspect).not_to include("kc_live_cached")
      expect(client.inspect).to include("acme")
    end
  end

  # -- ULID -----------------------------------------------------------------------

  describe "ULID" do
    it "generates 26-char Crockford base32, timestamp-prefix sortable" do
      a = KnoxCall::ULID.generate(Time.at(1))
      b = KnoxCall::ULID.generate(Time.at(2))
      expect(a).to match(/\A[0-9A-HJKMNP-TV-Z]{26}\z/)
      expect(b).to match(/\A[0-9A-HJKMNP-TV-Z]{26}\z/)
      expect(a[0, 10]).to be < b[0, 10]
    end
  end
end
