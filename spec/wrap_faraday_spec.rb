# End-to-end tests for the wrap Faraday transport
# (KnoxCall::Resources::Wrap#faraday_connection). Capture is at the SDK's HTTP
# boundary (WebMock on the /v1/proxy or direct-upstream request) — the same
# discipline the Node wrap-transport tests use — never by mocking the adapter.
# This exercises the full stack: a real Faraday connection -> our terminal
# adapter -> KnoxCall::Client#ephemeral / #call -> Net::HTTP -> WebMock.
#
# Requires the optional `faraday` gem (dev/test dependency only; the shipped
# gemspec declares no runtime dependency on it — see wrap.faraday_connection).

require "faraday"

RSpec.describe "KnoxCall wrap Faraday transport" do
  WRAP_API = "https://api.example.test".freeze
  WRAP_PROXY = "https://acme.example.test".freeze
  STRIPE_FORM = "amount=2000&currency=usd&source=tok_visa".freeze
  JSON_CT = { "Content-Type" => "application/json" }.freeze

  # Pre-acquired kc_ token: no token-endpoint round trip, so the proxy request
  # is the first (and only) wire call.
  def new_client(**opts)
    KnoxCall::Client.new(
      tenant: "acme", base_url: WRAP_API, proxy_base_url: WRAP_PROXY,
      api_key: "kc_live_x", retry_base_delay: 0.001, **opts
    )
  end

  # Case-insensitive read of a captured WebMock request header.
  def header(req, name)
    return nil if req.nil?

    pair = req.headers.to_a.find { |k, _| k.to_s.casecmp(name).zero? }
    v = pair&.last
    v.is_a?(Array) ? v.first : v
  end

  # The URL a captured WebMock request actually went to, minus the port.
  # WebMock normalizes every request signature to an explicit port, so
  # `req.uri.to_s` is "https://host:443/path" and never string-equals the
  # scheme-relative base_url these specs are written against. Comparing the
  # port-less form keeps the assertion about ROUTING (which host and path the
  # SDK chose) rather than about WebMock's normalizer.
  def request_url(req)
    req&.uri&.omit(:port)&.to_s
  end

  it "is reachable via wrap.faraday_connection and returns a Faraday::Connection" do
    expect(new_client.wrap.faraday_connection).to be_a(Faraday::Connection)
  end

  # -- Transit mode (lift the SDK Authorization) ------------------------------

  describe "transit mode" do
    it "re-targets to /v1/proxy in transparent mode, lifts Authorization, preserves the body" do
      captured = nil
      stub_request(:post, "#{WRAP_API}/v1/proxy")
        .with { |req| captured = req; true }
        .to_return(status: 200, body: JSON.generate({ ok: true }), headers: JSON_CT)

      conn = new_client.wrap.faraday_connection
      resp = conn.post("https://api.stripe.com/v1/charges", STRIPE_FORM,
                       "Authorization" => "Bearer sk_live_provider",
                       "Content-Type" => "application/x-www-form-urlencoded",
                       "Idempotency-Key" => "idem-1")

      # Goes to KnoxCall's proxy, not Stripe.
      expect(request_url(captured)).to eq("#{WRAP_API}/v1/proxy")
      expect(header(captured, "x-knox-proxy-url")).to eq("https://api.stripe.com/v1/charges")
      expect(header(captured, "x-knox-proxy-mode")).to eq("transparent")
      # Provider credential lifted out-of-band; NOT forwarded raw.
      expect(header(captured, "x-knox-upstream-authorization")).to eq("Bearer sk_live_provider")
      # KnoxCall's own credential authenticates the proxy call.
      expect(header(captured, "authorization")).to eq("Bearer kc_live_x")
      # SDK headers preserved; body byte-identical.
      expect(header(captured, "idempotency-key")).to eq("idem-1")
      expect(captured.body).to eq(STRIPE_FORM)
      # The upstream response is surfaced back through Faraday.
      expect(resp.status).to eq(200)
      expect(JSON.parse(resp.body)["ok"]).to be(true)
    end

    it "enforces both-must-agree: a test key on a live client raises" do
      conn = new_client.wrap.faraday_connection
      expect do
        conn.post("https://api.stripe.com/v1/charges", "", "Authorization" => "Bearer sk_test_x")
      end.to raise_error(KnoxCall::WrapSandboxMismatchError)
    end

    it "enforces both-must-agree: a live key on a sandbox client raises" do
      conn = new_client(sandbox: true).wrap.faraday_connection
      expect do
        conn.post("https://api.stripe.com/v1/charges", "", "Authorization" => "Bearer sk_live_x")
      end.to raise_error(KnoxCall::WrapSandboxMismatchError)
    end

    it "rejects a publishable key outright" do
      conn = new_client.wrap.faraday_connection
      expect do
        conn.post("https://api.stripe.com/v1/charges", "", "Authorization" => "Bearer pk_live_x")
      end.to raise_error(KnoxCall::WrapSandboxMismatchError)
    end

    it "accepts a restricted key matching the sandbox flag and lifts it" do
      captured = nil
      stub_request(:post, "#{WRAP_API}/v1/proxy")
        .with { |req| captured = req; true }
        .to_return(status: 200, body: "{}", headers: JSON_CT)

      new_client.wrap.faraday_connection.post(
        "https://api.stripe.com/v1/charges", "", "Authorization" => "Bearer rk_live_x"
      )
      expect(header(captured, "x-knox-upstream-authorization")).to eq("Bearer rk_live_x")
    end

    it "is not bypassed by a leading space before Bearer (regression #1)" do
      conn = new_client(sandbox: true).wrap.faraday_connection
      expect do
        conn.post("https://api.stripe.com/v1/charges", "", "Authorization" => " Bearer sk_live_x")
      end.to raise_error(KnoxCall::WrapSandboxMismatchError)
    end
  end

  # -- Escrow mode ------------------------------------------------------------

  describe "escrow mode" do
    it "sends X-Knox-Upstream-Auth-Secret and never a raw key" do
      captured = nil
      stub_request(:post, "#{WRAP_API}/v1/proxy")
        .with { |req| captured = req; true }
        .to_return(status: 200, body: "{}", headers: JSON_CT)

      conn = new_client.wrap.faraday_connection(credential: { secret: "wrap-stripe-live" })
      conn.post("https://api.stripe.com/v1/charges", STRIPE_FORM,
                "Authorization" => "Bearer sk_managed_by_knoxcall",
                "Content-Type" => "application/x-www-form-urlencoded")

      expect(header(captured, "x-knox-upstream-auth-secret")).to eq("wrap-stripe-live")
      # The placeholder key the SDK set is NOT forwarded out-of-band.
      expect(header(captured, "x-knox-upstream-authorization")).to be_nil
      # No both-must-agree check in escrow mode (placeholder key ignored).
      expect(captured.body).to eq(STRIPE_FORM)
    end

    it "passes a custom scheme through" do
      captured = nil
      stub_request(:post, "#{WRAP_API}/v1/proxy")
        .with { |req| captured = req; true }
        .to_return(status: 200, body: "{}", headers: JSON_CT)

      new_client.wrap.faraday_connection(credential: { secret: "wrap-x", scheme: "none" })
                .post("https://api.example.com/x", "")
      expect(header(captured, "x-knox-upstream-auth-scheme")).to eq("none")
    end

    it "raises on a malformed escrow credential rather than falling through to transit" do
      knox = new_client
      expect { knox.wrap.faraday_connection(credential: {}) }.to raise_error(TypeError)
      expect { knox.wrap.faraday_connection(credential: { secret: "" }) }.to raise_error(TypeError)
    end
  end

  # -- Client-side route-around -----------------------------------------------

  describe "route-around" do
    it "sends a raw-card endpoint DIRECTLY to the provider, not through KnoxCall" do
      proxy = stub_request(:post, "#{WRAP_API}/v1/proxy").to_return(status: 200, body: "{}", headers: JSON_CT)
      direct = stub_request(:post, "https://api.stripe.com/v1/tokens")
               .to_return(status: 200, body: JSON.generate({ id: "tok_1" }), headers: JSON_CT)

      info = nil
      conn = new_client.wrap.faraday_connection(on_route_around: ->(i) { info = i })
      resp = conn.post("https://api.stripe.com/v1/tokens", "card[number]=4242424242424242",
                       "Authorization" => "Bearer sk_live_x")

      expect(direct).to have_been_requested.once
      expect(proxy).not_to have_been_requested
      expect(info[:host]).to eq("api.stripe.com")
      # Direct response converted back into a Faraday response. The headers
      # matter as much as the status: route-around shipped calling
      # `Faraday::Response#response_headers`, which does not exist (it is an
      # Env method), so every direct call raised NoMethodError *after* the
      # provider had already answered. Assert the provider's headers actually
      # surface, not just that the call returned.
      expect(resp.status).to eq(200)
      expect(JSON.parse(resp.body)["id"]).to eq("tok_1")
      expect(resp.headers["content-type"]).to include("application/json")
    end

    it "does NOT route around a normal endpoint" do
      proxy = stub_request(:post, "#{WRAP_API}/v1/proxy").to_return(status: 200, body: "{}", headers: JSON_CT)
      direct = stub_request(:post, "https://api.stripe.com/v1/charges").to_return(status: 200, body: "{}")

      new_client.wrap.faraday_connection.post(
        "https://api.stripe.com/v1/charges", STRIPE_FORM, "Authorization" => "Bearer sk_live_x"
      )
      expect(proxy).to have_been_requested.once
      expect(direct).not_to have_been_requested
    end

    it "honours a caller-supplied extra route-around rule" do
      proxy = stub_request(:post, "#{WRAP_API}/v1/proxy").to_return(status: 200, body: "{}", headers: JSON_CT)
      direct = stub_request(:post, "https://files.stripe.com/v1/files").to_return(status: 200, body: "{}")

      conn = new_client.wrap.faraday_connection(
        route_around: [{ host: "files.stripe.com", reason: "multipart upload" }]
      )
      conn.post("https://files.stripe.com/v1/files", "x", "Authorization" => "Bearer sk_live_x")

      expect(direct).to have_been_requested.once
      expect(proxy).not_to have_been_requested
    end

    it "raises on a non-bare route_around host rather than silently never matching" do
      expect do
        new_client.wrap.faraday_connection(route_around: [{ host: "https://api.stripe.com", reason: "x" }])
      end.to raise_error(KnoxCall::WrapSandboxMismatchError)
    end
  end

  # -- Route mode + promoted-route hint (PR6 parity) --------------------------

  describe "route mode" do
    it "sends via the durable route (x-knoxcall-route, no upstream credential)" do
      captured = nil
      stub_request(:post, "#{WRAP_PROXY}/v1/charges?limit=3")
        .with { |req| captured = req; true }
        .to_return(status: 200, body: "{}", headers: JSON_CT)

      conn = new_client.wrap.faraday_connection(route: "stripe-api")
      conn.post("https://api.stripe.com/v1/charges?limit=3", STRIPE_FORM,
                "Authorization" => "Bearer sk_live_x",
                "Content-Type" => "application/x-www-form-urlencoded")

      # Goes to the route data plane with the route header — NOT /v1/proxy.
      expect(request_url(captured)).to eq("#{WRAP_PROXY}/v1/charges?limit=3")
      expect(header(captured, "x-knoxcall-route")).to eq("stripe-api")
      # The route injects the stored secret: no provider credential travels.
      expect(header(captured, "x-knox-upstream-authorization")).to be_nil
      expect(header(captured, "x-knox-proxy-url")).to be_nil
      # KnoxCall's own credential still authenticates.
      expect(header(captured, "authorization")).to eq("Bearer kc_live_x")
      expect(captured.body).to eq(STRIPE_FORM)
    end
  end

  describe "promoted-route hint" do
    it "fires on_promoted when a response advertises a promoted route" do
      stub_request(:post, "#{WRAP_API}/v1/proxy")
        .to_return(status: 200, body: "{}", headers: JSON_CT.merge("X-Knox-Promoted-Route" => "stripe-api"))

      promoted = nil
      conn = new_client.wrap.faraday_connection(on_promoted: ->(i) { promoted = i })
      conn.post("https://api.stripe.com/v1/charges", "", "Authorization" => "Bearer sk_live_x")

      expect(promoted).to eq(host: "api.stripe.com", slug: "stripe-api")
    end

    it "does NOT auto-switch by default (stays on the ephemeral path)" do
      proxy = stub_request(:post, "#{WRAP_API}/v1/proxy")
              .to_return(status: 200, body: "{}", headers: JSON_CT.merge("X-Knox-Promoted-Route" => "stripe-api"))

      conn = new_client.wrap.faraday_connection
      conn.post("https://api.stripe.com/v1/charges", "", "Authorization" => "Bearer sk_live_x")
      conn.post("https://api.stripe.com/v1/charges", "", "Authorization" => "Bearer sk_live_x")

      expect(proxy).to have_been_requested.twice
    end

    it "auto-switches subsequent calls to the route when auto_switch is on" do
      proxy = stub_request(:post, "#{WRAP_API}/v1/proxy")
              .to_return(status: 200, body: "{}", headers: JSON_CT.merge("X-Knox-Promoted-Route" => "stripe-api"))
      captured = nil
      route = stub_request(:post, "#{WRAP_PROXY}/v1/charges")
              .with { |req| captured = req; true }
              .to_return(status: 200, body: "{}", headers: JSON_CT)

      conn = new_client.wrap.faraday_connection(auto_switch: true)
      conn.post("https://api.stripe.com/v1/charges", "", "Authorization" => "Bearer sk_live_x")
      conn.post("https://api.stripe.com/v1/charges", "", "Authorization" => "Bearer sk_live_x")

      # First call ephemeral (learns the hint); second switched to the route.
      expect(proxy).to have_been_requested.once
      expect(route).to have_been_requested.once
      expect(header(captured, "x-knoxcall-route")).to eq("stripe-api")
      expect(header(captured, "x-knox-upstream-authorization")).to be_nil
    end
  end
end
