# frozen_string_literal: true

# The DPoP server nonce (RFC 9449 §8) — PARITY §7.1, client Phase 4.3.
#
# Four behaviours, and the fourth is the one that is easy to get wrong:
#
#   1. remember the most recent DPoP-Nonce per ORIGIN;
#   2. send it as the proof's nonce claim on every later request there;
#   3. on the server's "use a nonce" refusal, re-sign ONCE with the nonce that
#      refusal carried, with a new jti, and never loop;
#   4. that refusal is NOT an authentication failure. A 401 normally purges the
#      cached token and spends the one re-auth; a use_dpop_nonce 401 must do
#      neither, or every nonce rotation costs a token mint — and the retry would
#      then succeed anyway, which is what would hide it.

require "json"

RSpec.describe "KnoxCall DPoP server nonce" do
  let(:api) { "https://api.example.test" }
  let(:proxy) { "https://acme.example.test" }
  let(:json_ct) { { "Content-Type" => "application/json" } }

  def new_client(**opts)
    KnoxCall::Client.new(
      tenant: "acme", base_url: api, proxy_base_url: proxy,
      client_id: "tk_id", client_secret: "shh", dpop: "always",
      retry_base_delay: 0.001, **opts
    )
  end

  # Unpadded base64url via unpack, NOT the base64 gem -- base64 left the
  # default gems in Ruby 3.4, and lib/knoxcall/dpop.rb encodes the same way
  # (pack("m0") + tr) for exactly that reason.
  def claims(proof)
    payload = proof.split(".")[1].tr("-_", "+/")
    payload += "=" * ((4 - payload.length % 4) % 4)
    JSON.parse(payload.unpack1("m"))
  end

  def token_body
    JSON.generate(access_token: "kc_at_x", token_type: "DPoP", expires_in: 3600)
  end

  # ── the store ──────────────────────────────────────────────────────────────

  describe KnoxCall::DpopNonce do
    it "derives the origin, dropping path, query and default ports" do
      expect(described_class.origin_of("https://api.knoxcall.com/v1/routes")).to eq("https://api.knoxcall.com")
      expect(described_class.origin_of("https://api.knoxcall.com/v1/routes?a=1#f")).to eq("https://api.knoxcall.com")
      expect(described_class.origin_of("https://API.KnoxCall.com/v1")).to eq("https://api.knoxcall.com")
      expect(described_class.origin_of("http://localhost:3000/v1")).to eq("http://localhost:3000")
      expect(described_class.origin_of("https://api.knoxcall.com:8443/v1")).to eq("https://api.knoxcall.com:8443")
      expect(described_class.origin_of("/just/a/path")).to be_nil
      expect(described_class.origin_of("")).to be_nil
    end

    it "is keyed by origin, not by URL" do
      s = described_class::Store.new
      s.remember("https://api.knoxcall.com/oauth/token", { "dpop-nonce" => "A" })
      expect(s.get("https://api.knoxcall.com/v1/routes?x=1")).to eq("A")
      # A DIFFERENT origin has not answered yet. The management API and a
      # tenant's data plane issue different values; sending one to the other
      # would be refused.
      expect(s.get("https://acme.knoxcall.com/api/anything")).to be_nil
      s.remember("https://acme.knoxcall.com/api/x", { "dpop-nonce" => "B" })
      expect(s.get("https://acme.knoxcall.com/api/y")).to eq("B")
      expect(s.get("https://api.knoxcall.com/v1/routes")).to eq("A")
    end

    it "last write wins, and a blank never erases what we hold" do
      s = described_class::Store.new
      s.remember("https://api.test/x", { "dpop-nonce" => "first" })
      s.remember("https://api.test/x", { "dpop-nonce" => "second" })
      [{}, { "dpop-nonce" => "" }, { "dpop-nonce" => "   " }, nil].each do |h|
        expect(s.remember("https://api.test/x", h)).to be_nil
        expect(s.get("https://api.test/x")).to eq("second")
      end
    end

    it "does not remember a hostless URL" do
      s = described_class::Store.new
      expect(s.remember("/just/a/path", { "dpop-nonce" => "x" })).to be_nil
      expect(s.snapshot).to eq({})
    end

    it "recognises the authorization server's 400 and a resource server's header ALONE" do
      # The tenant data plane keeps its deliberately opaque body, so the header
      # is the only signal there.
      expect(described_class.refusal?(status: 400, code: "use_dpop_nonce")).to be(true)
      expect(described_class.refusal?(status: 401,
                                      headers: { "www-authenticate" => 'DPoP error="use_dpop_nonce"' })).to be(true)
      expect(described_class.refusal?(status: 401,
                                      headers: { "www-authenticate" => 'DPoP ERROR="USE_DPOP_NONCE"' })).to be(true)
    end

    it "treats nothing else as a nonce refusal" do
      expect(described_class.refusal?(status: 401, code: "invalid_token")).to be(false)
      expect(described_class.refusal?(status: 401,
                                      headers: { "www-authenticate" => 'DPoP error="invalid_token"' })).to be(false)
      expect(described_class.refusal?(status: 403, code: "use_dpop_nonce")).to be(false)
      expect(described_class.refusal?(status: 500, code: "use_dpop_nonce")).to be(false)
      expect(described_class.refusal?(status: 200)).to be(false)
    end
  end

  # ── end to end ─────────────────────────────────────────────────────────────

  it "sends the mint's nonce on the next call, and the call's on the one after" do
    stub_request(:post, "#{api}/oauth/token")
      .to_return(status: 200, body: token_body, headers: json_ct.merge("DPoP-Nonce" => "NONCE-1"))
    stub_request(:get, "#{api}/v1/routes")
      .to_return({ status: 200, body: JSON.generate(data: [], meta: {}), headers: json_ct.merge("DPoP-Nonce" => "NONCE-2") },
                 { status: 200, body: JSON.generate(data: [], meta: {}), headers: json_ct })

    client = new_client
    client.routes.list
    client.routes.list

    proofs = []
    WebMock::RequestRegistry.instance.requested_signatures.each { |sig, _| proofs << sig }
    mint = proofs.find { |p| p.uri.to_s.include?("/oauth/token") }
    expect(claims(mint.headers["Dpop"])).not_to have_key("nonce")

    calls = a_request(:get, "#{api}/v1/routes")
    expect(calls).to have_been_made.twice
    # The first call carries the mint's nonce; the second carries the one the
    # first RESPONSE returned.
    expect(WebMock).to have_requested(:get, "#{api}/v1/routes")
      .with { |req| claims(req.headers["Dpop"])["nonce"] == "NONCE-1" }
    expect(WebMock).to have_requested(:get, "#{api}/v1/routes")
      .with { |req| claims(req.headers["Dpop"])["nonce"] == "NONCE-2" }
  end

  it "re-signs once on a resource-server refusal, and does NOT re-mint" do
    stub_request(:post, "#{api}/oauth/token")
      .to_return(status: 200, body: token_body, headers: json_ct.merge("DPoP-Nonce" => "STALE"))
    stub_request(:get, "#{api}/v1/routes")
      .to_return({ status: 401,
                   body: JSON.generate(error: { type: "use_dpop_nonce", message: "nonce required" }),
                   headers: json_ct.merge("WWW-Authenticate" => 'DPoP error="use_dpop_nonce"',
                                          "DPoP-Nonce" => "FRESH") },
                 { status: 200, body: JSON.generate(data: [], meta: {}), headers: json_ct })

    new_client.routes.list

    expect(a_request(:get, "#{api}/v1/routes")).to have_been_made.twice
    expect(WebMock).to have_requested(:get, "#{api}/v1/routes")
      .with { |req| claims(req.headers["Dpop"])["nonce"] == "STALE" }
    expect(WebMock).to have_requested(:get, "#{api}/v1/routes")
      .with { |req| claims(req.headers["Dpop"])["nonce"] == "FRESH" }
    # Behaviour 4: the nonce refusal must not have purged the token.
    expect(a_request(:post, "#{api}/oauth/token")).to have_been_made.once
  end

  it "still purges and re-mints on a real 401" do
    stub_request(:post, "#{api}/oauth/token")
      .to_return(status: 200, body: token_body, headers: json_ct)
    stub_request(:get, "#{api}/v1/routes")
      .to_return({ status: 401, body: JSON.generate(error: { type: "invalid_token", message: "nope" }),
                   headers: json_ct },
                 { status: 200, body: JSON.generate(data: [], meta: {}), headers: json_ct })

    new_client.routes.list
    expect(a_request(:post, "#{api}/oauth/token")).to have_been_made.twice
  end

  it "never loops, and never costs a mint" do
    stub_request(:post, "#{api}/oauth/token")
      .to_return(status: 200, body: token_body, headers: json_ct.merge("DPoP-Nonce" => "N"))
    stub_request(:get, "#{api}/v1/routes")
      .to_return(status: 401,
                 body: JSON.generate(error: { type: "use_dpop_nonce", message: "nonce required" }),
                 headers: json_ct.merge("WWW-Authenticate" => 'DPoP error="use_dpop_nonce"',
                                        "DPoP-Nonce" => "N"))

    expect { new_client.routes.list }.to raise_error(KnoxCall::AuthenticationError)
    # ONE nonce re-sign, then the error surfaces. It must not also spend the
    # re-auth: the token was deliberately not purged, so that retry would
    # resend an identical request.
    expect(a_request(:get, "#{api}/v1/routes")).to have_been_made.twice
    expect(a_request(:post, "#{api}/oauth/token")).to have_been_made.once
  end

  it "re-signs the MINT in place, with no outer retry loop to fall back on" do
    # Isolates the mint-level retry: `authenticate` drives the token fetch
    # directly. A test going through a normal request could NOT show this —
    # the request loop's own nonce branch also matches a 400 and would mask a
    # missing mint-level retry entirely.
    stub_request(:post, "#{api}/oauth/token")
      .to_return({ status: 400,
                   body: JSON.generate(error: "use_dpop_nonce", error_description: "nonce required"),
                   headers: json_ct.merge("DPoP-Nonce" => "FRESH") },
                 { status: 200, body: token_body, headers: json_ct })

    new_client.token

    expect(a_request(:post, "#{api}/oauth/token")).to have_been_made.twice
    expect(WebMock).to have_requested(:post, "#{api}/oauth/token")
      .with { |req| !claims(req.headers["Dpop"]).key?("nonce") }
    expect(WebMock).to have_requested(:post, "#{api}/oauth/token")
      .with { |req| claims(req.headers["Dpop"])["nonce"] == "FRESH" }
  end

  it "retries the data plane from the challenge header alone" do
    stub_request(:post, "#{api}/oauth/token")
      .to_return(status: 200, body: token_body, headers: json_ct.merge("DPoP-Nonce" => "STALE"))
    stub_request(:get, "#{proxy}/v1/things")
      .to_return({ status: 401, body: "Unauthorized",
                   headers: { "WWW-Authenticate" => 'DPoP error="use_dpop_nonce"', "DPoP-Nonce" => "FRESH" } },
                 { status: 200, body: JSON.generate(ok: true), headers: json_ct })

    resp = new_client.call("my-route", path: "/v1/things")
    expect(resp.code.to_i).to eq(200)
    expect(a_request(:get, "#{proxy}/v1/things")).to have_been_made.twice
    # The data plane is a DIFFERENT ORIGIN, so the mint's nonce is correctly
    # NOT sent on the first call; the retry uses the one its own refusal
    # carried.
    expect(WebMock).to have_requested(:get, "#{proxy}/v1/things")
      .with { |req| !claims(req.headers["Dpop"]).key?("nonce") }
    expect(WebMock).to have_requested(:get, "#{proxy}/v1/things")
      .with { |req| claims(req.headers["Dpop"])["nonce"] == "FRESH" }
    expect(a_request(:post, "#{api}/oauth/token")).to have_been_made.once
  end

  it "treats an UPSTREAM 401 as the upstream's answer, not a nonce refusal" do
    stub_request(:post, "#{api}/oauth/token")
      .to_return(status: 200, body: token_body, headers: json_ct)
    stub_request(:get, "#{proxy}/v1/things")
      .to_return(status: 401, body: "upstream says no",
                 headers: { "X-Knox-Upstream-Status" => "401",
                            "WWW-Authenticate" => 'DPoP error="use_dpop_nonce"' })

    resp = new_client.call("my-route", path: "/v1/things")
    expect(resp.code.to_i).to eq(401)
    expect(a_request(:get, "#{proxy}/v1/things")).to have_been_made.once
  end
end
