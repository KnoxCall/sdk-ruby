# KnoxCall.exchange_token — the credential-less RFC 8693 exchange against
# POST /v1/oauth/token (AIGW-26). Module-level: no constructed client required.
#
# Three behaviours a caller gets wrong, all asserted here:
#   1. The response is a BARE OAuth body, not the {data, meta} envelope.
#   2. `resource` is only sent when non-nil — sending it EMPTY is a refusal,
#      not "no resource", because dropping it silently would mint an UNCONFINED
#      token while the caller believes it is audience-restricted.
#   3. The path is /v1/oauth/token, NOT the root-host /oauth/token that mints
#      management tokens.
#   4. The HOST is the tenant data plane. Verified against a running server
#      2026-08-25: the same request answers 400 invalid_grant on
#      acme.knoxcall.com and 401 on api.knoxcall.com, so there is no default.

RSpec.describe "KnoxCall.exchange_token" do
  def ok_body
    {
      access_token: "kc_live_agt_deadbeef",
      issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
      token_type: "Bearer",
      expires_in: 900,
      scope: '{"providers":["anthropic"]}'
    }
  end

  it "POSTs the RFC 8693 grant without credentials and returns the bare body" do
    seen = {}
    stub_request(:post, "https://acme.knoxcall.com/v1/oauth/token")
      .with { |req|
        seen[:headers] = req.headers.transform_keys(&:downcase)
        seen[:body] = JSON.parse(req.body)
        true
      }
      .to_return(status: 200, body: JSON.generate(ok_body),
                 headers: { "Content-Type" => "application/json" })

    res = KnoxCall.exchange_token(subject_token: "header.payload.sig", tenant: "acme")

    # The subject token IS the credential — nothing else is sent.
    expect(seen[:headers]).not_to have_key("authorization")
    expect(seen[:body]["grant_type"]).to eq(KnoxCall::TOKEN_EXCHANGE_GRANT)
    expect(seen[:body]["subject_token_type"]).to eq(KnoxCall::ID_TOKEN_TYPE)
    expect(seen[:body]["audience"]).to eq(KnoxCall::KNOXCALL_AUDIENCE)
    expect(seen[:body]["subject_token"]).to eq("header.payload.sig")

    # Bare OAuth body — no envelope to unwrap.
    expect(res["access_token"]).to eq("kc_live_agt_deadbeef")
    expect(res["expires_in"]).to eq(900)
    expect(res).not_to have_key("data")
  end

  it "omits resource unless one was asked for" do
    seen = {}
    stub_request(:post, "https://acme.knoxcall.com/v1/oauth/token")
      .with { |req| seen[:body] = JSON.parse(req.body); true }
      .to_return(status: 200, body: JSON.generate(ok_body))

    KnoxCall.exchange_token(subject_token: "a.b.c", tenant: "acme")
    expect(seen[:body]).not_to have_key("resource")
  end

  it "forwards an empty resource verbatim" do
    # It must reach the server and be refused invalid_target. Treating "" as
    # absent would hand back an UNCONFINED agent token to a caller who asked
    # for a confined one.
    seen = {}
    stub_request(:post, "https://acme.knoxcall.com/v1/oauth/token")
      .with { |req| seen[:body] = JSON.parse(req.body); true }
      .to_return(status: 200, body: JSON.generate(ok_body))

    KnoxCall.exchange_token(subject_token: "a.b.c", resource: "", tenant: "acme")
    expect(seen[:body]).to have_key("resource")
    expect(seen[:body]["resource"]).to eq("")
  end

  it "raises TokenExchangeError carrying the RFC 6749 code" do
    stub_request(:post, "https://acme.knoxcall.com/v1/oauth/token").to_return(
      status: 400,
      body: '{"error":"invalid_grant","error_description":"No tenant bindings registered for issuer https://x"}'
    )

    expect { KnoxCall.exchange_token(subject_token: "a.b.c", tenant: "acme") }
      .to raise_error(KnoxCall::TokenExchangeError) { |e|
        expect(e).to be_a(KnoxCall::Error)
        expect(e.status_code).to eq(400)
        expect(e.error_type).to eq("invalid_grant")
        expect(e.message).to include("No tenant bindings")
      }
  end

  it "raises when a 200 carries no access_token" do
    stub_request(:post, "https://acme.knoxcall.com/v1/oauth/token")
      .to_return(status: 200, body: '{"token_type":"Bearer"}')

    expect { KnoxCall.exchange_token(subject_token: "a.b.c", tenant: "acme") }
      .to raise_error(KnoxCall::TokenExchangeError) { |e|
        expect(e.error_type).to eq("token_exchange_failed")
      }
  end

  it "does not mask a non-JSON error page as a parse failure" do
    stub_request(:post, "https://acme.knoxcall.com/v1/oauth/token")
      .to_return(status: 502, body: "<html>502</html>")

    expect { KnoxCall.exchange_token(subject_token: "a.b.c", tenant: "acme") }
      .to raise_error(KnoxCall::TokenExchangeError) { |e|
        expect(e.status_code).to eq(502)
      }
  end

  it "honors a custom base_url and strips its trailing slash" do
    staging = stub_request(:post, "https://api-staging.knoxcall.com/v1/oauth/token")
              .to_return(status: 200, body: JSON.generate(ok_body))

    KnoxCall.exchange_token(subject_token: "a.b.c", base_url: "https://api-staging.knoxcall.com/")
    expect(staging).to have_been_requested
  end

  it "derives the sandbox data-plane host" do
    sandbox = stub_request(:post, "https://sandbox-acme.knoxcall.com/v1/oauth/token")
              .to_return(status: 200, body: JSON.generate(ok_body))

    KnoxCall.exchange_token(subject_token: "a.b.c", tenant: "acme", sandbox: true)
    expect(sandbox).to have_been_requested
  end

  it "refuses to guess a host rather than 401ing against the management API" do
    # api.knoxcall.com answers 401 for this request - the endpoint is not
    # served there. A default would turn "wrong host" into "your CI token was
    # rejected", the hardest possible thing to debug.
    expect { KnoxCall.exchange_token(subject_token: "a.b.c") }
      .to raise_error(ArgumentError, /tenant/)
  end

  it "refuses a tenant slug that is not a DNS label" do
    # The slug becomes the host the workload OIDC token is sent to.
    ["evil.com#", "a b", "-lead", "trail-"].each do |bad|
      expect { KnoxCall.exchange_token(subject_token: "a.b.c", tenant: bad) }
        .to raise_error(ArgumentError, /DNS label/)
    end
  end
end
