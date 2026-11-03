# Uncovered-egress observations (PARITY §21.3) — the Ruby mirror of
# sdk/knoxcall-node/test/egress-observations.test.ts. Three layers: the
# classifier, driven by the CROSS-LANGUAGE fixture
# sdk/fixtures/egress-observation.json; the reporter against an injected
# report lambda; and the seams (wrap.intercept!, faraday_middleware,
# faraday_connection) with WebMock on the wire — so the report body is
# asserted to carry the credential header's NAME and never its VALUE, never
# the query.

require "faraday"
require "json"

RSpec.describe "KnoxCall uncovered-egress observations" do
  fixture = JSON.parse(File.read(File.expand_path("../../fixtures/egress-observation.json", __dir__)))

  let(:api) { "https://api.example.test" }
  let(:proxy) { "https://acme.example.test" }
  let(:json_ct) { { "Content-Type" => "application/json" } }
  let(:obs_url) { "#{api}/v1/wrap/egress-observations" }
  let(:hubspot_root) { entry("api.hubapi.com", "/", "hubspot") }

  def new_client(**opts)
    KnoxCall::Client.new(tenant: "acme", base_url: api, proxy_base_url: proxy, api_key: "kc_live_x",
                         retry_base_delay: 0.001, **opts)
  end

  def entry(host, base, slug)
    { host: host, base_path: base, slug: slug, route_id: "r-#{slug}", requires_clients: false, allowed_methods: nil,
      updated_at: nil }
  end

  def manifest_body(routes)
    JSON.generate(data: { version: "sha256:#{routes.map { |r| r[:slug] }.join(',')}", ttl_seconds: 60,
                          environment: "production", sandbox: false, routes: routes },
                  meta: { request_id: "req_m" })
  end

  def stub_manifest(routes = [])
    stub_request(:get, %r{\A#{Regexp.escape(api)}/v1/wrap/intercept-manifest(\?.*)?\z})
      .to_return(status: 200, body: manifest_body(routes), headers: json_ct)
  end

  def stub_report(captured = [], accepted: 1)
    stub_request(:post, obs_url).with { |req| captured << req; true }
                                .to_return(status: 202, headers: json_ct,
                                           body: JSON.generate(data: { accepted: accepted, dropped: 0, reasons: {} },
                                                               meta: { request_id: "o" }))
  end

  def header(req, name)
    pair = req.headers.to_a.find { |k, _| k.to_s.casecmp(name).zero? }
    v = pair&.last
    v.is_a?(Array) ? v.first : v
  end

  def wait_until(timeout: 3.0)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    until yield
      raise "condition not met in time" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

      sleep 0.01
    end
  end

  around do |example|
    ENV.delete("KNOXCALL_INTERCEPT")
    ENV.delete("KNOXCALL_OBSERVE_UNCOVERED")
    KnoxCall::Warnings._reset_for_tests
    example.run
  ensure
    ENV.delete("KNOXCALL_INTERCEPT")
    ENV.delete("KNOXCALL_OBSERVE_UNCOVERED")
  end

  # ── 1. the classifier: shared fixtures ───────────────────────────────────────

  describe "shared fixtures" do
    it "is non-trivial and the SDK's lists are the fixture's lists" do
      expect(fixture["header_cases"].length).to be > 20
      expect(fixture["cases"].length).to be > 3
      expect(KnoxCall::EgressObservations::CREDENTIAL_HEADER_ALLOWLIST).to eq(fixture["credential_headers"]["allowlist"])
      expect(KnoxCall::EgressObservations::CREDENTIAL_HEADER_SUFFIXES).to eq(fixture["credential_headers"]["suffixes"])
    end

    fixture["header_cases"].each do |c|
      it "header #{c['name'].inspect} #{c['counts'] ? 'counts' : 'does not count'}" do
        expect(KnoxCall::EgressObservations.credential_header_name?(c["name"])).to eq(c["counts"])
      end
    end

    fixture["pick_cases"].each do |c|
      it "picks #{c['expect'].inspect} among #{c['headers'].inspect}" do
        expect(KnoxCall::EgressObservations.credential_header_name(c["headers"].to_h { |h| [h, "value"] })).to eq(c["expect"])
      end
    end

    fixture["first_segment_cases"].each do |c|
      it "first segment of #{c['url']} is #{c['expect']}" do
        expect(KnoxCall::EgressObservations.first_segment(c["url"])).to eq(c["expect"])
      end
    end

    fixture["segment_redaction_cases"].each do |c|
      it "segment #{c['segment'][0, 40]} #{c['redacted'] ? 'is reported as /' : 'passes unchanged'}" do
        expect(KnoxCall::EgressObservations.first_segment_looks_like_credential?(c["segment"])).to eq(c["redacted"])
      end
    end

    fixture["host_cases"].each do |c|
      it "host of #{c['url']} is #{c['expect']}" do
        expect(KnoxCall::WrapTransport.normalize_host(URI.parse(c["url"]).host)).to eq(c["expect"])
      end
    end

    fixture["cases"].each do |c|
      it c["name"] do
        got = KnoxCall::EgressObservations.observation_for(c["url"], c["method"], c["headers"])
        if c["expect"].nil?
          expect(got).to be_nil
        else
          expect(got).to eq(c["expect"].transform_keys(&:to_sym))
          c["headers"].each_value { |v| expect(got.inspect).not_to include(v) unless v.strip.empty? } # names, never values
        end
      end
    end
  end

  # ── 2. the reporter ──────────────────────────────────────────────────────────

  describe KnoxCall::EgressObservationReporter do
    def obs(i, method: "GET", seg: "/v1", header: "authorization")
      { host: "h#{i}.example", first_segment: seg, method: method, header_name: header }
    end

    def sink(calls, fail: nil)
      lambda do |observations|
        raise fail if fail

        calls << observations
        { "accepted" => observations.length, "dropped" => 0, "reasons" => {} }
      end
    end

    it "aggregates by (host, segment, method, header) with counts and ISO-8601 UTC timestamps" do
      t = 1_700_000_000.0
      calls = []
      r = described_class.new(sink(calls), now: -> { t }, rand: -> { 0.5 })
      r.record(obs(1))
      t += 1
      r.record(obs(1))
      t += 1
      r.record(obs(1))
      r.record(obs(1, method: "POST"))
      r.record(obs(1, seg: "/v2"))
      r.record(obs(1, header: "x-api-key"))
      expect(r.size).to eq(4)
      r.flush
      expect(calls.length).to eq(1)
      expect(calls[0][0]).to eq(host: "h1.example", first_segment: "/v1", method: "GET", header_name: "authorization",
                                count: 3, first_seen: "2023-11-14T22:13:20.000Z", last_seen: "2023-11-14T22:13:22.000Z")
      expect(r.size).to eq(0)
      r.stop
    end

    it "flushes at 200 keys in the background and never more than 200 per request" do
      calls = []
      r = described_class.new(sink(calls), rand: -> { 0.5 })
      199.times { |i| r.record(obs(i)) }
      expect(calls).to be_empty
      r.record(obs(199))
      wait_until { calls.length == 1 }
      expect(calls[0].length).to eq(200)
      r.stop

      big = []
      rb = described_class.new(sink(big), flush_at_keys: 10_000)
      450.times { |i| rb.record(obs(i)) }
      rb.flush
      expect(big.map(&:length)).to eq([200, 200, 50])
      rb.stop
    end

    it "flushes on a jittered timer thread that is re-armed only by the next record" do
      calls = []
      r = described_class.new(sink(calls), flush_interval: 0.05, rand: -> { 0.5 })
      r.record(obs(1))
      expect(calls).to be_empty
      wait_until { calls.length == 1 }
      r.record(obs(2))
      wait_until { calls.length == 2 }
      r.stop
    end

    it "holds at most 1 000 distinct keys; beyond that new keys are dropped with one warning" do
      calls = []
      r = described_class.new(sink(calls), flush_at_keys: 10_000)
      expect do
        1_005.times { |i| r.record(obs(i)) }
        r.record(obs(3)) # an EXISTING key still counts
      end.to output(/1000/).to_stderr
      expect(r.size).to eq(1_000)
      expect(r.pending.find { |o| o[:host] == "h3.example" }[:count]).to eq(2)
      expect { r.record(obs(2_000)) }.not_to output.to_stderr # warned once
      r.stop
    end

    it "a 403 stops reporting for good with one warning; later records are dropped at the door" do
      calls = []
      r = described_class.new(sink(calls, fail: KnoxCall::PermissionDeniedError.new("insufficient scope", 403)))
      r.record(obs(1))
      expect { r.flush }.to output(/routes:read/).to_stderr
      expect(r.forbidden?).to be(true)
      r.record(obs(2))
      expect(r.size).to eq(0)
      expect { r.flush; r.stop }.not_to output.to_stderr
      expect(calls).to be_empty
    end

    it "any other failure drops the batch with one warning, never retries it, and keeps later flushes going" do
      calls = []
      fail = KnoxCall::NetworkError.new("ECONNREFUSED")
      r = described_class.new(sink(calls, fail: nil))
      r.instance_variable_set(:@report, ->(o) { raise fail if fail; calls << o; { "accepted" => o.length, "dropped" => 0 } })
      r.record(obs(1))
      expect { r.flush }.to output(/dropped/).to_stderr
      expect(r.size).to eq(0)
      expect(r.forbidden?).to be(false)
      fail = nil
      r.record(obs(2))
      r.flush
      expect(calls.map { |c| c.map { |o| o[:host] } }).to eq([["h2.example"]])
      fail = KnoxCall::NetworkError.new("again")
      r.record(obs(3))
      expect { r.flush }.not_to output.to_stderr # warned once
      r.stop
    end

    it "on_flush reports the server's counts per accepted request; a raising hook never breaks the reporter" do
      seen = []
      hook = lambda do |info|
        seen << info
        raise "hook bug"
      end
      r = described_class.new(->(o) { { "accepted" => o.length - 1, "dropped" => 1 } }, on_flush: hook)
      r.record(obs(1))
      r.record(obs(2))
      r.flush
      expect(seen).to eq([{ accepted: 1, dropped: 1 }])
      expect(r.size).to eq(0)
      r.stop
    end

    it "stop flushes once more, after which records are ignored" do
      calls = []
      r = described_class.new(sink(calls))
      r.record(obs(1))
      r.stop
      expect(calls.length).to eq(1)
      r.record(obs(2))
      expect(r.size).to eq(0)
      r.stop # idempotent
    end
  end

  # ── 3. the seams ─────────────────────────────────────────────────────────────

  describe "intercept! (the Net::HTTP seam)" do
    let(:knox) { new_client }
    let(:handles) { [] }

    after { handles.each(&:uninstall) }

    def install(**opts)
      knox.wrap.intercept!(**opts).tap { |h| handles << h }
    end

    def post_direct(url, headers)
      uri = URI(url)
      Net::HTTP.start(uri.host, uri.port, use_ssl: true) do |http|
        req = Net::HTTP::Post.new(uri)
        headers.each { |k, v| req[k] = v }
        req.body = '{"email":"never-appears@example.com"}'
        http.request(req)
      end
    end

    it "records a direct :unlisted credentialed call and flushes names, never values — the query never reaches the wire" do
      stub_manifest([hubspot_root])
      captured = []
      report = stub_report(captured)
      direct = stub_request(:post, "https://a.klaviyo.com/api/profiles/").with(query: hash_including({}))
                                                                          .to_return(status: 200, body: "direct")
      flushes = []
      handle = install(hosts: ["api.resend.com"], on_observation_flush: ->(i) { flushes << i })
      handle.ready

      res = post_direct("https://a.klaviyo.com/api/profiles/?x=1&token=leak-in-query",
                        "Authorization" => "Klaviyo-API-Key pk_live_should_never_appear", "Content-Type" => "application/json")
      expect(res.body).to eq("direct") # the application's request is untouched
      post_direct("https://a.klaviyo.com/api/profiles/?x=2", "authorization" => "Klaviyo-API-Key pk_live_2")
      expect(direct).to have_been_requested.twice
      expect(handle.pipeline.observer.size).to eq(1)
      expect(report).not_to have_been_requested # nothing leaves the process on the request's own path

      handle.uninstall # the final flush, synchronously
      expect(report).to have_been_requested.once
      req = captured.first
      expect(header(req, "authorization")).to eq("Bearer kc_live_x") # the SDK's OWN credential
      expect(header(req, "x-idempotency-key")).not_to be_nil # the shared request path
      body = JSON.parse(req.body)
      expect(body["sdk"]).to eq("ruby/#{KnoxCall::VERSION}")
      expect(body["observations"].length).to eq(1)
      o = body["observations"].first
      expect(o.slice("host", "first_segment", "method", "header_name", "count"))
        .to eq("host" => "a.klaviyo.com", "first_segment" => "/api", "method" => "POST", "header_name" => "authorization", "count" => 2)
      expect(o["first_seen"]).to match(/\A\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z\z/)
      expect(o["last_seen"]).to be >= o["first_seen"]
      %w[pk_live x=1 x=2 leak-in-query never-appears profiles].each { |leak| expect(req.body).not_to include(leak) }
      expect(flushes).to eq([{ accepted: 1, dropped: 0 }])
    end

    it "records nothing without a credential header, for own hosts, route-around, rerouted or kill-switched calls" do
      stub_manifest([hubspot_root])
      report = stub_report
      stub_request(:any, %r{\Ahttps://unlisted\.example/}).to_return(status: 200, body: "direct")
      stub_request(:get, "#{api}/v1/anything").to_return(status: 200, body: "{}")
      stub_request(:get, "https://acme.knoxcall.com/x").to_return(status: 200, body: "{}")
      stub_request(:post, "https://api.stripe.com/v1/tokens").to_return(status: 200, body: "{}")
      route = stub_request(:get, "#{proxy}/crm/v3/objects").to_return(status: 200, body: "{}")
      ephemeral = stub_request(:post, "#{api}/v1/proxy").to_return(status: 200, body: "{}")
      handle = install(hosts: ["api.resend.com", "api.stripe.com"])
      handle.ready

      get = lambda do |url, hdrs|
        uri = URI(url)
        Net::HTTP.start(uri.host, uri.port, use_ssl: true) do |http|
          req = Net::HTTP::Get.new(uri)
          hdrs.each { |k, v| req[k] = v }
          http.request(req)
        end
      end
      get.call("https://unlisted.example/x", "Accept" => "*/*", "X-Request-Id" => "1")        # no credential
      get.call("#{api}/v1/anything", "Authorization" => "Bearer kc_live_x")                     # own_host
      get.call("https://acme.knoxcall.com/x", "Authorization" => "Bearer kc_live_x")           # platform host
      post_direct("https://api.stripe.com/v1/tokens", "Authorization" => "Bearer sk_live_x")   # route_around
      get.call("https://api.hubapi.com/crm/v3/objects", "Authorization" => "Bearer t")         # route
      post_direct("https://api.resend.com/emails", "Authorization" => "Bearer re")             # ephemeral
      ENV["KNOXCALL_INTERCEPT"] = "off"
      get.call("https://unlisted.example/x", "Authorization" => "Bearer u")                     # kill_switch
      ENV.delete("KNOXCALL_INTERCEPT")

      expect(route).to have_been_requested.once
      expect(ephemeral).to have_been_requested.once
      expect(handle.pipeline.observer.size).to eq(0)
      handle.uninstall
      expect(report).not_to have_been_requested
    end

    it "the flush rides request under the suppress flag while the seam is installed: never re-intercepted, never observed" do
      stub_manifest([hubspot_root])
      captured = []
      report = stub_report(captured)
      stub_request(:get, "https://a.klaviyo.com/api/x").to_return(status: 200, body: "direct")
      handle = install(hosts: ["api.resend.com"])
      handle.ready
      Net::HTTP.start("a.klaviyo.com", 443, use_ssl: true) do |http|
        req = Net::HTTP::Get.new(URI("https://a.klaviyo.com/api/x"))
        req["X-Api-Key"] = "k"
        http.request(req)
      end
      handle.pipeline.observer.flush # while STILL installed
      expect(report).to have_been_requested.once
      expect(JSON.parse(captured.first.body)["observations"].map { |o| o["host"] }).to eq(["a.klaviyo.com"])
      expect(handle.pipeline.observer.size).to eq(0) # the report and the manifest poll were not observed
      expect(WebMock).not_to have_requested(:post, "#{api}/v1/proxy")
    end

    it "opt-out: observe_uncovered: false, KNOXCALL_OBSERVE_UNCOVERED=off and KNOXCALL_INTERCEPT=off each disable it" do
      stub_manifest([])
      report = stub_report
      stub_request(:get, "https://h.example/v1/x").to_return(status: 200, body: "direct")
      get = lambda do
        Net::HTTP.start("h.example", 443, use_ssl: true) do |http|
          req = Net::HTTP::Get.new(URI("https://h.example/v1/x"))
          req["Authorization"] = "Bearer x"
          http.request(req)
        end
      end

      handle = install(observe_uncovered: false)
      expect(handle.pipeline.observer).to be_nil
      handle.uninstall

      %w[off FALSE 0].each do |v|
        ENV["KNOXCALL_OBSERVE_UNCOVERED"] = v
        handle = install
        expect(handle.pipeline.observer).to be_nil
        handle.uninstall
        ENV.delete("KNOXCALL_OBSERVE_UNCOVERED")
      end

      ENV["KNOXCALL_INTERCEPT"] = "off"
      handle = install
      get.call
      expect(handle.pipeline.observer.size).to eq(0) # everything is direct; nothing is worth reporting
      handle.uninstall
      ENV.delete("KNOXCALL_INTERCEPT")
      expect(report).not_to have_been_requested

      handle = install # the control: on by default
      get.call
      expect(handle.pipeline.observer.size).to eq(1)
      handle.uninstall
      expect(report).to have_been_requested.once
    end

    it "a 403 from the endpoint stops reporting for the handle with one warning" do
      stub_manifest([])
      report = stub_request(:post, obs_url).to_return(status: 403, headers: json_ct,
                                                      body: '{"error":{"type":"forbidden","message":"insufficient scope","request_id":"r"}}')
      stub_request(:get, %r{\Ahttps://[hk]\d+\.example/}).to_return(status: 200, body: "direct")
      handle = install
      get = lambda do |host|
        Net::HTTP.start(host, 443, use_ssl: true) do |http|
          req = Net::HTTP::Get.new(URI("https://#{host}/v1/x"))
          req["Authorization"] = "Bearer x"
          http.request(req)
        end
      end
      expect do
        200.times { |i| get.call("h#{i}.example") } # the 200th triggers a background flush
        wait_until { handle.pipeline.observer.forbidden? }
      end.to output(/routes:read/).to_stderr_from_any_process
      200.times { |i| expect(get.call("k#{i}.example").body).to eq("direct") } # the application never noticed
      expect(handle.pipeline.observer.size).to eq(0)
      handle.uninstall
      expect(report).to have_been_requested.once
    end

    it "a network error is dropped with one warning, never surfaces into the application's call, and later flushes still go" do
      stub_manifest([])
      stub_request(:post, obs_url).to_raise(Errno::ECONNREFUSED)
      stub_request(:get, %r{\Ahttps://(h\.|later\.)example/}).to_return(status: 200, body: "direct")
      handle = install
      get = lambda do |host|
        Net::HTTP.start(host, 443, use_ssl: true) do |http|
          req = Net::HTTP::Get.new(URI("https://#{host}/v1/x"))
          req["Authorization"] = "Bearer x"
          http.request(req)
        end
      end
      expect(get.call("h.example").body).to eq("direct")
      expect { handle.pipeline.observer.flush }.to output(/dropped/).to_stderr
      expect(handle.pipeline.observer.forbidden?).to be(false)
      captured = []
      report = stub_report(captured) # the later stub wins
      get.call("later.example")
      handle.uninstall
      # The failed batch went through request()'s own transport retries (3
      # attempts — the shared path) and was then dropped: the reporter never
      # re-sends it. Only the later batch reaches the (now healthy) stub.
      expect(captured.length).to eq(1)
      expect(JSON.parse(captured.first.body)["observations"].map { |o| o["host"] }).to eq(["later.example"])
    end
  end

  describe "faraday_middleware and faraday_connection" do
    let(:knox) { new_client }

    it "the middleware observes an unlisted credentialed call on an SDK-built stack; a routes: :auto connection never does (every host is listed)" do
      stub_manifest([])
      captured = []
      report = stub_report(captured)
      direct = stub_request(:get, "https://unlisted.example/x").with(query: hash_including({}))
                                                                .to_return(status: 200, body: "direct")
      klass, options = knox.wrap.faraday_middleware(hosts: ["api.resend.com"])
      conn = Faraday.new do |f|
        f.use(klass, options)
        f.adapter :net_http
      end
      resp = conn.get("https://unlisted.example/x?q=1") { |r| r.headers["Authorization"] = "Bearer never" }
      expect(resp.body).to eq("direct")
      expect(direct).to have_been_requested.once
      expect(options[:pipeline].observer.size).to eq(1)
      options[:pipeline].stop
      expect(report).to have_been_requested.once
      body = JSON.parse(captured.first.body)
      expect(body["observations"].first.slice("host", "first_segment", "method", "header_name"))
        .to eq("host" => "unlisted.example", "first_segment" => "/x", "method" => "GET", "header_name" => "authorization")
      expect(captured.first.body).not_to include("never")
      expect(captured.first.body).not_to include("q=1")

      ephemeral = stub_request(:get, "#{api}/v1/proxy").to_return(status: 200, body: "{}")
      auto = knox.wrap.faraday_connection(routes: :auto)
      auto.get("https://anything.example/v1/x", nil, "Authorization" => "Bearer x")
      expect(ephemeral).to have_been_requested.once
      expect(auto.knoxcall.observer).not_to be_nil
      expect(auto.knoxcall.observer.size).to eq(0)
      auto.knoxcall.stop
      expect(knox.wrap.faraday_connection.knoxcall.observer).to be_nil # routes: :off
      expect(knox.wrap.faraday_connection(routes: :auto, observe_uncovered: false).knoxcall.observer).to be_nil
      expect(report).to have_been_requested.once
    end
  end

  describe "wrap.report_egress_observations" do
    it "POSTs {sdk, observations} to /v1/wrap/egress-observations through request and unwraps the envelope" do
      captured = []
      stub_request(:post, obs_url).with { |req| captured << req; true }
                                  .to_return(status: 202, headers: json_ct,
                                             body: '{"data":{"accepted":1,"dropped":1,"reasons":{"unknown_host":1}},"meta":{"request_id":"o"}}')
      observations = [{ host: "h.example", first_segment: "/v1", method: "GET", header_name: "authorization", count: 3,
                        first_seen: "2026-09-26T00:00:00.000Z", last_seen: "2026-09-26T00:01:00.000Z" }]
      res = new_client.wrap.report_egress_observations(observations)
      expect(res).to eq("accepted" => 1, "dropped" => 1, "reasons" => { "unknown_host" => 1 })
      expect(captured.first.method).to eq(:post)
      expect(header(captured.first, "authorization")).to eq("Bearer kc_live_x")
      expect(JSON.parse(captured.first.body)).to eq("sdk" => "ruby/#{KnoxCall::VERSION}",
                                                    "observations" => JSON.parse(JSON.generate(observations)))
      new_client.wrap.report_egress_observations(observations, sdk: "custom/9.9.9")
      expect(JSON.parse(captured.last.body)["sdk"]).to eq("custom/9.9.9")
    end
  end
end
