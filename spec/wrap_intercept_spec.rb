# Route-aware interception at the SDK's HTTP boundary
# (route-aware-interception-plan.md §2, PARITY §21.1) for every Ruby seam: the
# Faraday adapter (wrap.faraday_connection(routes: :auto)), the Faraday
# middleware (wrap.faraday_middleware) and the opt-in Net::HTTP seam
# (wrap.intercept!). Capture is WebMock on the wire — the manifest poll, the
# /v1/proxy request, the route data-plane request, or the direct upstream —
# never a mocked adapter. The decision table itself is pinned by the shared
# fixtures (intercept_resolver_spec.rb); these specs prove what LEAVES the
# process, with which headers, and when.

require "faraday"
require "json"

RSpec.describe "KnoxCall route-aware interception (Ruby seams)" do
  let(:api) { "https://api.example.test" }
  let(:proxy) { "https://acme.example.test" }
  let(:json_ct) { { "Content-Type" => "application/json" } }

  def new_client(**opts)
    KnoxCall::Client.new(
      tenant: "acme", base_url: api, proxy_base_url: proxy,
      api_key: "kc_live_x", retry_base_delay: 0.001, **opts
    )
  end

  def entry(host, base, slug, **extra)
    { host: host, base_path: base, slug: slug, route_id: "r-#{slug}", requires_clients: false,
      allowed_methods: nil, updated_at: nil }.merge(extra)
  end

  def manifest_body(routes, version: "sha256:#{routes.map { |r| r[:slug] }.join(',')}")
    JSON.generate(data: { version: version, ttl_seconds: 60, environment: "production", sandbox: false,
                          routes: routes },
                  meta: { request_id: "req_m" })
  end

  # Any query (the client's environment rides along as ?environment=).
  def stub_manifest(*bodies)
    stub = stub_request(:get, %r{\A#{Regexp.escape(api)}/v1/wrap/intercept-manifest(\?.*)?\z})
    bodies.each { |b| stub = stub.to_return(status: 200, body: b, headers: json_ct) }
    stub
  end

  def header(req, name)
    pair = req.headers.to_a.find { |k, _| k.to_s.casecmp(name).zero? }
    v = pair&.last
    v.is_a?(Array) ? v.first : v
  end

  let(:hubspot_crm) { entry("api.hubapi.com", "/crm/v3", "hubspot-crm") }

  before { KnoxCall::Warnings._reset_for_tests }

  # ── the explicit transport: faraday_connection(routes: :auto) ───────────────

  describe "faraday_connection(routes: :auto)" do
    it "sends a covered request through the Route: rebased path, query kept, SDK key never lifted" do
      manifest = stub_manifest(manifest_body([hubspot_crm]))
      captured = nil
      route = stub_request(:post, "#{proxy}/objects/contacts").with(query: { "limit" => "1", "after" => "x" })
                                                                .with { |req| captured = req; true }
                                                                .to_return(status: 200, body: "{}", headers: json_ct)
      reroutes = []
      conn = new_client(environment: "staging").wrap.faraday_connection(routes: :auto, on_reroute: ->(i) { reroutes << i })
      conn.knoxcall.ready
      expect(conn.knoxcall.manifest["version"]).to eq("sha256:hubspot-crm")

      resp = conn.post("https://api.hubapi.com/crm/v3/objects/contacts?limit=1&after=x", '{"properties":{}}',
                       "Authorization" => "Bearer pat-provider-secret",
                       "Content-Type" => "application/json",
                       "X-Custom" => "1")
      expect(resp.status).to eq(200)
      expect(manifest).to have_been_requested.once
      expect(WebMock).to have_requested(:get, "#{api}/v1/wrap/intercept-manifest").with(query: { "environment" => "staging" })
      expect(route).to have_been_requested.once
      expect(header(captured, "x-knoxcall-route")).to eq("hubspot-crm")
      # The reroute marker the API Log renders as "SDK intercept" (PARITY §21.2).
      expect(header(captured, "x-knoxcall-origin")).to eq("sdk-intercept")
      expect(header(captured, "x-knoxcall-environment")).to eq("staging")
      expect(header(captured, "authorization")).to eq("Bearer kc_live_x")
      expect(header(captured, "x-knox-upstream-authorization")).to be_nil
      expect(header(captured, "x-knox-proxy-url")).to be_nil
      expect(header(captured, "x-custom")).to eq("1")
      expect(header(captured, "content-type")).to eq("application/json")
      expect(captured.body).to eq('{"properties":{}}')
      expect(reroutes.length).to eq(1)
      expect(reroutes.first).to include(host: "api.hubapi.com", mode: :route, slug: "hubspot-crm", reason: :manifest)
      expect(reroutes.first[:url]).to start_with("https://api.hubapi.com/crm/v3/objects/contacts?") # Faraday re-orders the query
    end

    it "sends a host with no Route through the ephemeral proxy, and a path outside every base too (hook once)" do
      stub_manifest(manifest_body([hubspot_crm]))
      captured = []
      ephemeral = stub_request(:post, "#{api}/v1/proxy").with { |req| captured << req; true }
                                                        .to_return(status: 200, body: "{}", headers: json_ct)
      unmatched = []
      reroutes = []
      conn = new_client.wrap.faraday_connection(routes: :auto, on_unmatched_path: ->(i) { unmatched << i },
                                                                on_reroute: ->(i) { reroutes << i })

      conn.post("https://api.resend.com/emails", "{}", "Authorization" => "Bearer re_secret")
      expect(header(captured[0], "x-knox-proxy-url")).to eq("https://api.resend.com/emails")
      expect(header(captured[0], "x-knox-proxy-mode")).to eq("transparent")
      expect(header(captured[0], "x-knox-upstream-authorization")).to eq("Bearer re_secret")
      # The reroute marker is a ROUTE-mode fact (PARITY §21.2); an ephemeral hop
      # is a different log and carries nothing.
      expect(header(captured[0], "x-knoxcall-origin")).to be_nil
      expect(reroutes.last).to include(mode: :ephemeral, reason: :no_route)

      3.times { |i| conn.post("https://api.hubapi.com/oauth/v#{i < 2 ? 1 : 2}/token", "grant_type=refresh_token") }
      expect(ephemeral).to have_been_requested.times(4)
      expect(unmatched).to eq([{ host: "api.hubapi.com", url: "https://api.hubapi.com/oauth/v1/token" }])
      expect(reroutes.last).to include(mode: :ephemeral, reason: :no_base_path_match)
    end

    it "with routes: :off never polls the manifest and stays ephemeral-only" do
      manifest = stub_manifest(manifest_body([hubspot_crm]))
      ephemeral = stub_request(:get, "#{api}/v1/proxy").to_return(status: 200, body: "{}", headers: json_ct)
      conn = new_client.wrap.faraday_connection
      expect(conn.knoxcall.manifest).to be_nil
      conn.get("https://api.hubapi.com/crm/v3/objects", nil, "Authorization" => "Bearer pat")
      expect(manifest).not_to have_been_requested
      expect(ephemeral).to have_been_requested.once
    end

    it "never intercepts the client's own hosts or any knoxcall.com host, even as the explicit transport" do
      stub_manifest(manifest_body([]))
      own = stub_request(:get, "#{api}/v1/anything").to_return(status: 200, body: "{}")
      platform = stub_request(:get, "https://acme.knoxcall.com/x").to_return(status: 200, body: "{}")
      ephemeral = stub_request(:get, "#{api}/v1/proxy").to_return(status: 200, body: "{}")
      conn = new_client.wrap.faraday_connection(routes: :auto)
      conn.get("#{api}/v1/anything", nil, "Authorization" => "Bearer x")
      conn.get("https://acme.knoxcall.com/x")
      expect(own).to have_been_requested.once
      expect(platform).to have_been_requested.once
      expect(ephemeral).not_to have_been_requested
    end

    it "KNOXCALL_INTERCEPT=off sends everything direct, per request" do
      stub_manifest(manifest_body([hubspot_crm]))
      direct = stub_request(:post, "https://api.hubapi.com/crm/v3/objects").to_return(status: 200, body: "{}")
      route = stub_request(:post, "#{proxy}/objects").to_return(status: 200, body: "{}")
      conn = new_client.wrap.faraday_connection(routes: :auto)
      conn.knoxcall.ready
      begin
        ENV["KNOXCALL_INTERCEPT"] = "off"
        conn.post("https://api.hubapi.com/crm/v3/objects", "x", "Authorization" => "Bearer sk_provider")
      ensure
        ENV.delete("KNOXCALL_INTERCEPT")
      end
      expect(direct).to have_been_requested.once
      expect(WebMock).to have_requested(:post, "https://api.hubapi.com/crm/v3/objects")
        .with(headers: { "Authorization" => "Bearer sk_provider" })
      expect(route).not_to have_been_requested
      conn.post("https://api.hubapi.com/crm/v3/objects", "x")
      expect(route).to have_been_requested.once
    end

    describe "a KnoxCall-origin 401 in route mode" do
      it "refreshes the manifest once and resends through the new decision when it changed" do
        manifest = stub_manifest(manifest_body([hubspot_crm]), manifest_body([], version: "sha256:none"))
        route = stub_request(:post, "#{proxy}/objects").to_return(status: 401, body: '{"error":"Unauthorized"}', headers: json_ct)
        captured = nil
        ephemeral = stub_request(:post, "#{api}/v1/proxy").with { |req| captured = req; true }
                                                          .to_return(status: 200, body: "{}", headers: json_ct)
        refused = []
        conn = new_client.wrap.faraday_connection(routes: :auto, on_refused: ->(i) { refused << i })

        resp = conn.post("https://api.hubapi.com/crm/v3/objects", '{"a":1}', "Authorization" => "Bearer pat")
        expect(resp.status).to eq(200)
        # the refusal + Call's own one re-mint, never a third
        expect(route).to have_been_requested.twice
        expect(manifest).to have_been_requested.twice
        expect(ephemeral).to have_been_requested.once
        expect(captured.body).to eq('{"a":1}')
        expect(header(captured, "x-knox-upstream-authorization")).to eq("Bearer pat")
        expect(refused).to eq([{ host: "api.hubapi.com", url: "https://api.hubapi.com/crm/v3/objects",
                                 slug: "hubspot-crm", status: 401, redecided: :ephemeral }])
      end

      it "returns the refusal as-is after exactly one refresh when nothing changed" do
        manifest = stub_manifest(manifest_body([hubspot_crm]))
        route = stub_request(:get, "#{proxy}/objects").to_return(status: 401, body: '{"error":"Unauthorized"}', headers: json_ct)
        ephemeral = stub_request(:get, "#{api}/v1/proxy").to_return(status: 200, body: "{}")
        refused = []
        conn = new_client.wrap.faraday_connection(routes: :auto, on_refused: ->(i) { refused << i })
        expect(conn.get("https://api.hubapi.com/crm/v3/objects").status).to eq(401)
        expect(route).to have_been_requested.twice
        expect(manifest).to have_been_requested.twice
        expect(ephemeral).not_to have_been_requested
        expect(refused.first[:redecided]).to be_nil
      end
    end

    # Founder decision 2026-09-26: an AUTHENTICATED key gets a real 404 for a
    # route that does not resolve. A stale manifest naming a Route deleted since
    # the poll is exactly that, so the 404 route_not_found envelope is a refresh
    # trigger too (PARITY §21.1). No re-mint is spent on it — call's rule is
    # 401-only — so the Route is called ONCE.
    describe "a KnoxCall-origin 404 route_not_found in route mode" do
      let(:route_not_found) { '{"error":{"type":"route_not_found","message":"Route \'hubspot-crm\' not found.","request_id":"req_x"}}' }
      let(:knox_block) { json_ct.merge("X-Knox-Origin" => "knoxcall", "X-Knox-Error" => "route_not_found", "X-Knox-Plane" => "route") }

      it "refreshes the manifest once and resends through the new decision when it changed" do
        manifest = stub_manifest(manifest_body([hubspot_crm]), manifest_body([], version: "sha256:none"))
        route = stub_request(:post, "#{proxy}/objects").to_return(status: 404, body: route_not_found, headers: knox_block)
        captured = nil
        ephemeral = stub_request(:post, "#{api}/v1/proxy").with { |req| captured = req; true }
                                                          .to_return(status: 200, body: "{}", headers: json_ct)
        refused = []
        conn = new_client.wrap.faraday_connection(routes: :auto, on_refused: ->(i) { refused << i })

        resp = conn.post("https://api.hubapi.com/crm/v3/objects", '{"a":1}', "Authorization" => "Bearer pat")
        expect(resp.status).to eq(200)
        expect(route).to have_been_requested.once # no re-mint on a 404
        expect(manifest).to have_been_requested.twice
        expect(ephemeral).to have_been_requested.once
        expect(captured.body).to eq('{"a":1}')
        expect(refused).to eq([{ host: "api.hubapi.com", url: "https://api.hubapi.com/crm/v3/objects",
                                 slug: "hubspot-crm", status: 404, redecided: :ephemeral }])
      end

      it "leaves a 404 of an environment_* type as-is — a refresh cannot fix an environment" do
        body = '{"error":{"type":"environment_not_configured","message":"Environment \'staging\' is not configured for this route.","request_id":"r"}}'
        manifest = stub_manifest(manifest_body([hubspot_crm]))
        route = stub_request(:get, "#{proxy}/objects")
                .to_return(status: 404, body: body, headers: json_ct.merge("X-Knox-Origin" => "knoxcall", "X-Knox-Error" => "environment_not_configured"))
        refused = []
        conn = new_client.wrap.faraday_connection(routes: :auto, on_refused: ->(i) { refused << i })
        resp = conn.get("https://api.hubapi.com/crm/v3/objects")
        expect(resp.status).to eq(404)
        expect(resp.body).to eq(body)
        expect(route).to have_been_requested.once
        expect(manifest).to have_been_requested.once
        expect(refused).to eq([])
      end

      it "never refreshes on an UPSTREAM 404 relayed by the data plane, even with a body that imitates the envelope" do
        ["X-Knox-Upstream-Status", "X-Knox-Destination-Status"].each do |h|
          WebMock.reset!
          manifest = stub_manifest(manifest_body([hubspot_crm]))
          route = stub_request(:get, "#{proxy}/objects").to_return(status: 404, body: route_not_found, headers: json_ct.merge(h => "404"))
          conn = new_client.wrap.faraday_connection(routes: :auto)
          resp = conn.get("https://api.hubapi.com/crm/v3/objects")
          expect(resp.status).to eq(404)
          expect(resp.body).to eq(route_not_found)
          expect(route).to have_been_requested.once
          expect(manifest).to have_been_requested.once
        end
      end
    end

    it "never re-mints or refreshes on an UPSTREAM 401 relayed by the data plane (either header)" do
      ["X-Knox-Upstream-Status", "X-Knox-Destination-Status"].each do |h|
        WebMock.reset!
        manifest = stub_manifest(manifest_body([hubspot_crm]))
        route = stub_request(:get, "#{proxy}/objects").to_return(status: 401, body: "{}", headers: json_ct.merge(h => "401"))
        conn = new_client.wrap.faraday_connection(routes: :auto)
        expect(conn.get("https://api.hubapi.com/crm/v3/objects").status).to eq(401)
        expect(route).to have_been_requested.once
        expect(manifest).to have_been_requested.once
      end
    end

    it "treats X-Knox-Promoted-Route as a signal: fires on_promoted and refreshes the manifest" do
      manifest = stub_manifest(manifest_body([]))
      stub_request(:get, "#{api}/v1/proxy").to_return(status: 200, body: "{}", headers: json_ct.merge("X-Knox-Promoted-Route" => "resend"))
      promoted = []
      conn = new_client.wrap.faraday_connection(routes: :auto, on_promoted: ->(i) { promoted << i })
      conn.knoxcall.ready
      conn.knoxcall.store.min_refresh_gap = 0 # the hint would otherwise sit inside the start refresh's gap
      conn.get("https://api.resend.com/emails")
      expect(promoted).to eq([{ host: "api.resend.com", slug: "resend" }])
      conn.get("https://api.resend.com/emails") # the NEXT request pays the refresh
      expect(manifest).to have_been_requested.twice
    end

    describe "when KnoxCall is unreachable (D4)" do
      before do
        stub_manifest(manifest_body([hubspot_crm]))
        stub_request(:post, "#{api}/v1/proxy").to_raise(Errno::ECONNREFUSED)
        stub_request(:get, "#{proxy}/objects").to_raise(Errno::ECONNREFUSED)
      end

      it "fails closed by default: transit raises, the base transport is never touched" do
        direct = stub_request(:post, "https://api.resend.com/emails").to_return(status: 200, body: "{}")
        conn = new_client.wrap.faraday_connection(routes: :auto)
        expect { conn.post("https://api.resend.com/emails", "x=1", "Authorization" => "Bearer re_secret") }
          .to raise_error(Faraday::ConnectionFailed)
        expect(direct).not_to have_been_requested
      end

      it "sends the ORIGINAL request direct when transit opted in, and fires on_fallback" do
        captured = nil
        direct = stub_request(:post, "https://api.resend.com/emails").with { |req| captured = req; true }
                                                                     .to_return(status: 200, body: "{}")
        fallbacks = []
        conn = new_client.wrap.faraday_connection(routes: :auto, unavailable: :direct, on_fallback: ->(i) { fallbacks << i })
        resp = conn.post("https://api.resend.com/emails", "x=1", "Authorization" => "Bearer re_secret")
        expect(resp.status).to eq(200)
        expect(direct).to have_been_requested.once
        expect(header(captured, "authorization")).to eq("Bearer re_secret")
        expect(captured.body).to eq("x=1")
        expect(fallbacks.length).to eq(1)
        expect(fallbacks.first).to include(host: "api.resend.com")
        expect(fallbacks.first[:error]).to be_a(KnoxCall::NetworkError)
      end

      it "honours the per-host opt-in for that host only" do
        direct = stub_request(:post, "https://api.resend.com/emails").to_return(status: 200, body: "{}")
        other = stub_request(:post, "https://api.other.example/x").to_return(status: 200, body: "{}")
        conn = new_client.wrap.faraday_connection(routes: :auto, hosts: { "api.resend.com" => { unavailable: :direct } })
        expect(conn.post("https://api.resend.com/emails", "x").status).to eq(200)
        expect(direct).to have_been_requested.once
        expect { conn.post("https://api.other.example/x", "x") }.to raise_error(Faraday::ConnectionFailed)
        expect(other).not_to have_been_requested
      end

      it "escrow never goes direct, even with both opt-ins" do
        direct = stub_request(:post, "https://api.resend.com/emails").to_return(status: 200, body: "{}")
        conn = new_client.wrap.faraday_connection(
          routes: :auto, unavailable: :direct,
          hosts: { "api.resend.com" => { credential: { secret: "resend-key" }, unavailable: :direct } }
        )
        expect { conn.post("https://api.resend.com/emails", "x") }.to raise_error(Faraday::ConnectionFailed)
        expect(direct).not_to have_been_requested
      end

      it "route mode never goes direct" do
        direct = stub_request(:get, "https://api.hubapi.com/crm/v3/objects").to_return(status: 200, body: "{}")
        conn = new_client.wrap.faraday_connection(routes: :auto, unavailable: :direct)
        expect { conn.get("https://api.hubapi.com/crm/v3/objects") }.to raise_error(Faraday::ConnectionFailed)
        expect(direct).not_to have_been_requested
      end
    end

    it "warns once for requires_clients and ambiguous entries, at the refresh that added them" do
      stub_manifest(manifest_body([
        entry("api.openai.com", "/v1", "openai", requires_clients: true, allowed_methods: %w[GET POST]),
        entry("dup.example", "/", "a-first", ambiguous: true),
        entry("dup.example", "/", "b-second", ambiguous: true)
      ]))
      conn = new_client.wrap.faraday_connection(routes: :auto)
      expect { conn.knoxcall.ready; conn.knoxcall.refresh }
        .to output(a_string_matching(/route "openai".*requires a registered client/)
                     .and(a_string_matching(/more than one intercept-enabled route covers dup\.example\//)))
        .to_stderr
      expect { conn.knoxcall.refresh }.not_to output.to_stderr
    end

    it "uses a per-host escrow credential for that host and transit for the rest" do
      stub_manifest(manifest_body([]))
      captured = []
      stub_request(:any, "#{api}/v1/proxy").with { |req| captured << req; true }.to_return(status: 200, body: "{}")
      conn = new_client.wrap.faraday_connection(routes: :auto,
                                                hosts: { "api.resend.com" => { credential: { secret: "resend-key", scheme: "none" } } })
      conn.post("https://api.resend.com/emails", "{}", "Authorization" => "Bearer placeholder")
      conn.get("https://api.other.example/x", nil, "Authorization" => "Bearer other_secret")
      expect(header(captured[0], "x-knox-upstream-auth-secret")).to eq("resend-key")
      expect(header(captured[0], "x-knox-upstream-auth-scheme")).to eq("none")
      expect(header(captured[0], "x-knox-upstream-authorization")).to be_nil
      expect(header(captured[1], "x-knox-upstream-authorization")).to eq("Bearer other_secret")
      expect(header(captured[1], "x-knox-upstream-auth-secret")).to be_nil
    end

    it "fails loud on a misconfiguration rather than silently degrading" do
      knox = new_client
      expect { knox.wrap.faraday_connection(hosts: ["https://x.example/path"]) }.to raise_error(KnoxCall::WrapSandboxMismatchError, /bare DNS hostname/)
      expect { knox.wrap.faraday_connection(hosts: { "h.example" => { credential: { secret: "" } } }) }.to raise_error(TypeError, /non-empty/)
      expect { knox.wrap.faraday_connection(credential: {}) }.to raise_error(TypeError)
      expect { knox.wrap.faraday_connection(on_nonsense: -> {}) }.to raise_error(ArgumentError, /on_nonsense/)
    end

    it "keeps the legacy explicit route: and auto_switch: behaviour with routes: :off" do
      stub_request(:post, "#{api}/v1/proxy").to_return(status: 200, body: "{}", headers: json_ct.merge("X-Knox-Promoted-Route" => "stripe-api"))
      route = stub_request(:post, "#{proxy}/v1/charges").to_return(status: 200, body: "{}", headers: json_ct)
      conn = new_client.wrap.faraday_connection(auto_switch: true)
      conn.post("https://api.stripe.com/v1/charges", "", "Authorization" => "Bearer sk_live_x")
      conn.post("https://api.stripe.com/v1/charges", "", "Authorization" => "Bearer sk_live_x")
      expect(route).to have_been_requested.once
    end
  end

  # ── the middleware for SDK-built stacks ──────────────────────────────────────

  describe "faraday_middleware" do
    it "answers covered and listed hosts from KnoxCall and lets everything else reach the SDK's adapter" do
      stub_manifest(manifest_body([hubspot_crm]))
      route = stub_request(:get, "#{proxy}/objects").to_return(status: 201, body: '{"routed":true}', headers: json_ct.merge("X-Foo" => "bar"))
      ephemeral = stub_request(:get, "#{api}/v1/proxy").to_return(status: 200, body: "{}")
      direct = stub_request(:get, "https://unlisted.example/x").to_return(status: 200, body: "direct")
      mw = new_client.wrap.faraday_middleware(hosts: ["api.resend.com"])
      conn = Faraday.new do |f|
        f.use(*mw)
        f.adapter :net_http
      end

      resp = conn.get("https://api.hubapi.com/crm/v3/objects")
      expect(resp.status).to eq(201)
      expect(resp.body).to eq('{"routed":true}')
      expect(resp.headers["x-foo"]).to eq("bar")
      conn.get("https://api.resend.com/emails")
      expect(conn.get("https://unlisted.example/x").body).to eq("direct")
      expect(route).to have_been_requested.once
      expect(ephemeral).to have_been_requested.once
      expect(direct).to have_been_requested.once
      expect(mw.last[:pipeline].manifest["version"]).to eq("sha256:hubspot-crm")
    end
  end

  # ── the opt-in process-wide seam ─────────────────────────────────────────────

  describe "intercept!" do
    let(:knox) { new_client }
    let(:handles) { [] }

    after { handles.each(&:uninstall) }

    def install(**opts)
      knox.wrap.intercept!(**opts).tap { |h| handles << h }
    end

    it "reaches an untouched Net::HTTP caller: Route for a covered host, ephemeral for a listed one, direct otherwise" do
      stub_manifest(manifest_body([hubspot_crm]))
      captured = nil
      route = stub_request(:post, "#{proxy}/objects/contacts").with(query: { "limit" => "1" })
                                                                .with { |req| captured = req; true }
                                                                .to_return(status: 200, body: '{"routed":true}', headers: json_ct)
      ephemeral = stub_request(:get, "#{api}/v1/proxy").to_return(status: 200, body: "{}")
      direct = stub_request(:get, "https://unlisted.example/x").to_return(status: 200, body: "direct")

      handle = install(hosts: ["api.resend.com"])
      handle.ready
      expect(handle.manifest["version"]).to eq("sha256:hubspot-crm")

      uri = URI("https://api.hubapi.com/crm/v3/objects/contacts?limit=1")
      res = Net::HTTP.start(uri.host, uri.port, use_ssl: true) do |http|
        req = Net::HTTP::Post.new(uri)
        req["Authorization"] = "Bearer pat-provider-secret"
        req["Content-Type"] = "application/json"
        req.body = '{"properties":{}}'
        http.request(req)
      end
      expect(res).to be_a(Net::HTTPResponse)
      expect(res.code).to eq("200")
      expect(res.body).to eq('{"routed":true}')
      expect(route).to have_been_requested.once
      expect(header(captured, "x-knoxcall-route")).to eq("hubspot-crm")
      expect(header(captured, "x-knox-upstream-authorization")).to be_nil
      expect(header(captured, "content-type")).to eq("application/json")
      expect(captured.body).to eq('{"properties":{}}')

      expect(Net::HTTP.get_response(URI("https://api.resend.com/emails")).code).to eq("200")
      expect(ephemeral).to have_been_requested.once
      expect(Net::HTTP.get_response(URI("https://unlisted.example/x")).body).to eq("direct")
      expect(direct).to have_been_requested.once
    end

    it "refuses a second install, and uninstall restores pass-through" do
      stub_manifest(manifest_body([hubspot_crm]))
      route = stub_request(:get, "#{proxy}/objects").to_return(status: 200, body: "{}")
      direct = stub_request(:get, "https://api.hubapi.com/crm/v3/objects").to_return(status: 200, body: "{}")
      handle = install
      expect { knox.wrap.intercept! }.to raise_error(KnoxCall::Error, /already installed/)
      Net::HTTP.get_response(URI("https://api.hubapi.com/crm/v3/objects"))
      expect(route).to have_been_requested.once
      handle.uninstall
      handle.uninstall # idempotent
      Net::HTTP.get_response(URI("https://api.hubapi.com/crm/v3/objects"))
      expect(direct).to have_been_requested.once
      expect(route).to have_been_requested.once
      install # installable again
    end

    it "with require_context: true only intercepts inside routed { }" do
      ephemeral = stub_request(:get, "#{api}/v1/proxy").to_return(status: 200, body: "{}")
      direct = stub_request(:get, "https://api.resend.com/emails").to_return(status: 200, body: "{}")
      install(hosts: ["api.resend.com"], routes: :off, require_context: true)
      Net::HTTP.get_response(URI("https://api.resend.com/emails"))
      expect(direct).to have_been_requested.once
      expect(ephemeral).not_to have_been_requested
      knox.wrap.routed { Net::HTTP.get_response(URI("https://api.resend.com/emails")) }
      expect(ephemeral).to have_been_requested.once
    end

    it "rejects an unknown stack and a non-bare host at install" do
      expect { knox.wrap.intercept!(stacks: [:curb]) }.to raise_error(ArgumentError, /curb/)
      expect { knox.wrap.intercept!(hosts: ["https://x.example"]) }.to raise_error(KnoxCall::WrapSandboxMismatchError)
      expect(KnoxCall::Intercept.installed).to be_nil
    end
  end

  # ── the conditional poll on the wire (PARITY §21.1 "Conditional poll") ──────
  # The store-level walk of sdk/fixtures/intercept-store-conditional.json lives
  # in intercept_store_spec.rb; here the same contract is proven at the SDK's
  # HTTP boundary — which header leaves, in which form, and what a 304 becomes —
  # through the real intercept_manifest and the real request pipeline.
  describe "intercept_manifest(if_none_match:)" do
    let(:knox) { new_client }
    let(:fixture) do
      JSON.parse(File.read(File.expand_path("../../fixtures/intercept-store-conditional.json", __dir__)))
    end
    let(:manifest_url) { %r{\A#{Regexp.escape(api)}/v1/wrap/intercept-manifest(\?.*)?\z} }

    # As the server does (src/client-api/wrap.ts): ETag W/"<version>" on every
    # answer, 304 with no body when If-None-Match carries it.
    def stub_conditional_manifest(&routes)
      stub_request(:get, manifest_url).to_return do |req|
        body = manifest_body(routes.call)
        etag = %(W/"#{JSON.parse(body)['data']['version']}")
        if header(req, "If-None-Match").to_s.split(",").map(&:strip).include?(etag)
          { status: 304, headers: { "ETag" => etag } }
        else
          { status: 200, body: body, headers: json_ct.merge("ETag" => etag) }
        end
      end
    end

    it "formats every fixture step's held version as the server's weak ETag" do
      fixture["steps"].each do |step|
        held = step["expect"]["fetch_if_none_match"]
        if held.nil?
          expect(step["expect"]["wire_if_none_match"]).to be_nil, step["name"]
        else
          expect(KnoxCall::Resources::Wrap.manifest_etag(held)).to eq(step["expect"]["wire_if_none_match"]), step["name"]
        end
      end
    end

    it "sends If-None-Match as W/\"<version>\" and returns nil on 304; the unconditional call sends no header" do
      stub_conditional_manifest { [hubspot_crm] }
      etag = %(W/"sha256:hubspot-crm")

      first = knox.wrap.intercept_manifest
      expect(first["routes"].map { |r| r["slug"] }).to eq(["hubspot-crm"])
      expect(knox.wrap.intercept_manifest(if_none_match: first["version"])).to be_nil
      stale = knox.wrap.intercept_manifest(if_none_match: "sha256:stale")
      expect(stale["version"]).to eq(first["version"])
      # if_none_match: nil is the unconditional call, not a header with no value.
      expect(knox.wrap.intercept_manifest(if_none_match: nil)["version"]).to eq(first["version"])

      expect(WebMock).to have_requested(:get, manifest_url).times(4)
      expect(WebMock).to(have_requested(:get, manifest_url).with { |req| header(req, "If-None-Match").nil? }.times(2))
      expect(WebMock).to have_requested(:get, manifest_url).with(headers: { "If-None-Match" => etag }).once
      expect(WebMock).to have_requested(:get, manifest_url).with(headers: { "If-None-Match" => %(W/"sha256:stale") }).once
    end

    it "still gets the one transparent re-auth on a 401, and the retry carries If-None-Match" do
      etag = %(W/"sha256:hubspot-crm")
      stub_request(:get, manifest_url)
        .to_return(status: 200, body: manifest_body([hubspot_crm]), headers: json_ct)
        .then.to_return(status: 401, body: '{"error":{"type":"authentication_error","message":"expired"}}', headers: json_ct)
        .then.to_return(status: 304, headers: { "ETag" => etag })

      first = knox.wrap.intercept_manifest
      expect(knox.wrap.intercept_manifest(if_none_match: first["version"])).to be_nil
      expect(WebMock).to have_requested(:get, manifest_url).times(3) # unconditional, the 401, the re-authed retry
      expect(WebMock).to have_requested(:get, manifest_url).with(headers: { "If-None-Match" => etag }).times(2)
    end

    it "polls conditionally through faraday_connection(routes: :auto): a forced refresh carries the held version, " \
       "a 304 keeps the manifest, a change replaces it and the next poll carries the new version" do
      routes = [hubspot_crm]
      stub_conditional_manifest { routes }
      conn = knox.wrap.faraday_connection(routes: :auto)
      conn.knoxcall.ready
      v1 = conn.knoxcall.manifest["version"]
      expect(v1).to eq("sha256:hubspot-crm")

      conn.knoxcall.refresh # forced, as a refusal-driven refresh is: still conditional → 304
      expect(conn.knoxcall.manifest["routes"].map { |r| r["slug"] }).to eq(["hubspot-crm"])

      routes = [entry("api.hubapi.com", "/", "hubspot")]
      conn.knoxcall.refresh # the change: 200 with a new version
      expect(conn.knoxcall.manifest["version"]).to eq("sha256:hubspot")
      conn.knoxcall.refresh # → 304 against the NEW version
      expect(conn.knoxcall.manifest["version"]).to eq("sha256:hubspot")

      expect(WebMock).to have_requested(:get, manifest_url).times(4)
      expect(WebMock).to(have_requested(:get, manifest_url).with { |req| header(req, "If-None-Match").nil? }.once)
      expect(WebMock).to have_requested(:get, manifest_url).with(headers: { "If-None-Match" => %(W/"sha256:hubspot-crm") }).times(2)
      expect(WebMock).to have_requested(:get, manifest_url).with(headers: { "If-None-Match" => %(W/"sha256:hubspot") }).once
    end

    it "keeps a 304's old shape without the opt-in" do
      stub_request(:get, manifest_url).to_return(status: 304, headers: { "ETag" => 'W/"x"' })
      expect(knox.request("GET", "/v1/wrap/intercept-manifest")).to be_nil
      expect(knox.request("GET", "/v1/wrap/intercept-manifest", allow_not_modified: true))
        .to equal(KnoxCall::Client::NOT_MODIFIED)
    end
  end
end
