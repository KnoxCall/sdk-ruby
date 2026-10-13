# PARITY §5 — where the data plane lives under a proxy base.
#
# On a KnoxCall cloud tenant host the proxy is served ONLY under /api
# (server.ts strips the prefix; every other path on that host is the
# dashboard). Until 2026-09-25 call sent base + path, so every documented
# `path: "/users"` example answered the dashboard HTML on a real tenant host,
# and the five live smokes passed only because each hard-coded
# `path: "/api/get"`. Measured on a local server that day: GET /api/get → 200
# with X-Knox-Upstream-Status; GET /get → the SPA branch, no upstream call.
# These pin the URL call builds for every base shape.

RSpec.describe "data-plane entry point (PARITY §5)" do
  around do |example|
    vars = %w[KNOXCALL_PROXY_BASE_URL KNOXCALL_BASE_URL KNOXCALL_API_BASE_URL KNOXCALL_TENANT KNOXCALL_ENVIRONMENT]
    vars.each { |k| ENV.delete(k) }
    example.run
  ensure
    vars.each { |k| ENV.delete(k) }
  end

  describe ".data_plane_path_prefix" do
    {
      "https://acme.knoxcall.com" => "/api",
      "https://acme.knoxcall.com/" => "/api",
      "https://sandbox-acme.knoxcall.com" => "/api",
      "http://sandbox-acme.knoxcall.com:3100" => "/api",
      "https://ACME.KnoxCall.com" => "/api",
      "https://acme.knoxcall.com/api" => "",
      "https://acme.knoxcall.com/proxy" => "",
      "https://api.knoxcall.com" => "",
      "https://sandbox.knoxcall.com" => "",
      "https://api-staging.knoxcall.com" => "",
      "https://sandbox-staging.knoxcall.com" => "",
      "https://www.knoxcall.com" => "",
      "https://staging.knoxcall.com" => "",
      "https://admin.knoxcall.com" => "",
      "https://a.b.knoxcall.com" => "",
      "https://knoxcall.com" => "",
      "https://acme.knoxcall.com.evil.test" => "",
      "http://localhost:3000" => "",
      "https://knox.example.com" => "",
      "not a url" => ""
    }.each do |base, want|
      it "#{base} → #{want.inspect}" do
        expect(KnoxCall::Client.data_plane_path_prefix(base)).to eq(want)
      end
    end
  end

  # Stubs exactly the URL call must build; anything else raises WebMock's
  # NetConnectNotAllowedError naming the URL the SDK actually sent.
  def expect_call(path, want, **opts)
    stub_request(:get, want).to_return(status: 200, body: "{}", headers: { "Content-Type" => "application/json" })
    KnoxCall::Client.new(tenant: "acme", access_token: "kc_live_pre", **opts).call("r_1", path: path)
    expect(a_request(:get, want)).to have_been_made.once
  end

  it "derived sandbox shape" do
    expect_call("/users", "https://sandbox-acme.knoxcall.com/api/users", base_url: "https://sandbox.knoxcall.com")
  end

  it "derived plain shape" do
    expect_call("/users", "https://acme.knoxcall.com/api/users", base_url: "https://api.knoxcall.com")
  end

  it "an explicit override naming a tenant host, any port (the live smoke harness)" do
    expect_call("/get", "http://sandbox-acme.knoxcall.com:3100/api/get",
                base_url: "http://sandbox.knoxcall.com:3100", proxy_base_url: "http://sandbox-acme.knoxcall.com:3100")
  end

  it "the KNOXCALL_PROXY_BASE_URL override behaves the same" do
    ENV["KNOXCALL_PROXY_BASE_URL"] = "https://sandbox-acme.knoxcall.com"
    expect_call("/get", "https://sandbox-acme.knoxcall.com/api/get", base_url: "https://sandbox.knoxcall.com")
  end

  it "an override that already carries the entry point is verbatim — never doubled" do
    expect_call("/get", "https://sandbox-acme.knoxcall.com/api/get",
                base_url: "https://sandbox.knoxcall.com", proxy_base_url: "https://sandbox-acme.knoxcall.com/api")
  end

  it "a loopback override is verbatim" do
    expect_call("/get", "http://localhost:3000/get", base_url: "http://localhost:3000", proxy_base_url: "http://localhost:3000")
  end

  it "a self-hosted base is verbatim" do
    expect_call("/get", "https://knox.example.com/get", base_url: "https://knox.example.com")
  end

  it "unslashed, bare and /api-prefixed upstream paths" do
    expect_call("users", "https://acme.knoxcall.com/api/users", base_url: "https://api.knoxcall.com")
    WebMock.reset!
    expect_call("/api/v2/tickets", "https://acme.knoxcall.com/api/api/v2/tickets", base_url: "https://api.knoxcall.com")
    WebMock.reset!
    expect_call("/", "https://acme.knoxcall.com/api/", base_url: "https://api.knoxcall.com")
  end

  it "bound routes inherit it" do
    stub_request(:get, "https://acme.knoxcall.com/api/users").to_return(status: 200, body: "{}")
    KnoxCall::Client.new(tenant: "acme", access_token: "kc_live_pre", base_url: "https://api.knoxcall.com").route("r_1").get("/users")
    expect(a_request(:get, "https://acme.knoxcall.com/api/users")).to have_been_made.once
  end
end
