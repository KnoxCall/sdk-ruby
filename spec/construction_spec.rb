# Tests for flat construction, env fallbacks, and bound routes — mirrors
# knoxcall-python's tests/test_construction.py (PARITY §2/§6).

RSpec.describe "KnoxCall construction" do
  let(:api)       { "https://api.example.test" }
  let(:proxy)     { "https://acme.example.test" }
  let(:token_url) { "#{api}/oauth/token" }

  around do |example|
    vars = %w[KNOXCALL_TENANT KNOXCALL_ENVIRONMENT KNOXCALL_ACCESS_TOKEN
              KNOXCALL_API_KEY KNOXCALL_CLIENT_ID KNOXCALL_CLIENT_SECRET
              KNOXCALL_BASE_URL KNOXCALL_API_BASE_URL KNOXCALL_PROXY_BASE_URL]
    vars.each { |k| ENV.delete(k) }
    example.run
  ensure
    vars.each { |k| ENV.delete(k) }
  end

  def new_client(**opts)
    KnoxCall::Client.new(
      tenant: "acme",
      base_url: "https://api.example.test",
      proxy_base_url: "https://acme.example.test",
      retry_base_delay: 0.001,
      **opts
    )
  end

  def token_body(token = "kc_live_aaaa")
    {
      status: 200,
      body: JSON.generate(access_token: token, token_type: "Bearer", expires_in: 3600),
      headers: { "Content-Type" => "application/json" }
    }
  end

  def headers_of(req)
    req.headers.transform_keys(&:downcase)
  end

  # -- Flat credential options ---------------------------------------------------

  describe "flat credential options" do
    it "mints via client_credentials exactly like a bootstrap object" do
      seen = {}
      stub_request(:post, token_url)
        .with { |req| seen[:auth] = headers_of(req)["authorization"]; seen[:form] = req.body; true }
        .to_return(token_body)
      stub_request(:get, "#{proxy}/x").to_return(status: 200, body: '{"ok":true}')

      new_client(client_id: "tk_x", client_secret: "sec").call("r_1", path: "/x")

      expect(seen[:auth]).to start_with("Basic ")
      expect(seen[:form]).to include("grant_type=client_credentials")
    end

    it "attaches a kc_ access_token/api_key as Bearer without hitting the token endpoint" do
      [{ access_token: "kc_live_pre" }, { api_key: "kc_live_pre" }].each do |cred|
        WebMock.reset!
        seen = {}
        stub_request(:get, "#{proxy}/x")
          .with { |req| seen.merge!(headers_of(req)); true }
          .to_return(status: 200)

        new_client(**cred).call("r_1", path: "/x")
        expect(seen["authorization"]).to eq("Bearer kc_live_pre")
        expect(a_request(:post, token_url)).not_to have_been_made
      end
    end

    it "raises ArgumentError for every conflicting credential combination" do
      bootstrap = KnoxCall::ClientCredentials.new(client_id: "tk_x", client_secret: "sec")
      conflicts = [
        { bootstrap: bootstrap, client_id: "tk_x" },
        { access_token: "kc_a", api_key: "kc_b" },
        { api_key: "kc_a", client_id: "tk_x", client_secret: "s" },
        { client_id: "tk_x" },  # missing client_secret
        { client_secret: "s" }  # missing client_id
      ]
      conflicts.each do |opts|
        expect { KnoxCall::Client.new(tenant: "acme", **opts) }.to raise_error(ArgumentError)
      end
    end
  end

  # -- Legacy-key transmission (PARITY §5) ----------------------------------------

  describe "legacy key transmission" do
    it "sends a legacy tk_ key as x-knoxcall-key on call(), never as Bearer" do
      seen = {}
      stub_request(:get, "#{proxy}/x")
        .with { |req| seen.merge!(headers_of(req)); true }
        .to_return(status: 200, body: '{"ok":true}')

      new_client(api_key: "tk_live_legacy").call("r_1", path: "/x")

      # proxy OAuth detection matches `Bearer kc_` only — tk_ must use the header
      expect(seen["x-knoxcall-key"]).to eq("tk_live_legacy")
      expect(seen).not_to have_key("authorization")
    end

    it "keeps ephemeral() on Authorization: Bearer even for legacy keys" do
      seen = {}
      stub_request(:post, "#{api}/v1/proxy")
        .with { |req| seen.merge!(headers_of(req)); true }
        .to_return(status: 200)

      new_client(api_key: "tk_live_legacy")
        .ephemeral("https://upstream.example.test/charge", method: "POST", body: { a: 1 })

      expect(seen["authorization"]).to eq("Bearer tk_live_legacy")
      expect(seen).not_to have_key("x-knoxcall-key")
    end
  end

  # -- Tenant env fallback / zero-arg ----------------------------------------------

  describe "tenant resolution" do
    it "resolves tenant from KNOXCALL_TENANT for zero-tenant construction" do
      ENV["KNOXCALL_TENANT"] = "envcorp"
      client = KnoxCall::Client.new(access_token: "kc_live_x")
      expect(client.tenant).to eq("envcorp")
      # proxy URL must derive from the env-resolved tenant
      expect(client.instance_variable_get(:@proxy_base_url)).to eq("https://envcorp.knoxcall.com")
    end

    it "lets an explicit tenant beat the env" do
      ENV["KNOXCALL_TENANT"] = "envcorp"
      client = KnoxCall::Client.new(tenant: "explicit", access_token: "kc_live_x")
      expect(client.tenant).to eq("explicit")
    end

    it "discovers the tenant from the token response and derives the proxy host" do
      stub_request(:post, "https://api.knoxcall.com/oauth/token").to_return(
        status: 200,
        body: JSON.generate(access_token: "kc_live_a", token_type: "Bearer",
                            expires_in: 3600, tenant: "discovered"),
        headers: { "Content-Type" => "application/json" }
      )
      proxied = stub_request(:get, "https://discovered.knoxcall.com/api/x").to_return(status: 200, body: "{}")

      client = KnoxCall::Client.new(client_id: "tk_x", client_secret: "s", retry_base_delay: 0.001)
      client.call("r_1", path: "/x")

      expect(proxied).to have_been_requested.once
      expect(client.tenant).to eq("discovered")
    end

    it "discovers via /v1/account for pre-acquired tokens, exactly once" do
      account = stub_request(:get, "https://api.knoxcall.com/v1/account").to_return(
        status: 200,
        body: JSON.generate(data: { slug: "fromaccount", name: "X" }),
        headers: { "Content-Type" => "application/json" }
      )
      stub_request(:get, %r{https://fromaccount\.knoxcall\.com/.*}).to_return(status: 200, body: "{}")

      client = KnoxCall::Client.new(access_token: "kc_live_pre", retry_base_delay: 0.001)
      client.call("r_1", path: "/x")
      client.call("r_1", path: "/y")

      expect(account).to have_been_requested.once
    end

    it "raises an actionable error when the tenant cannot be discovered" do
      stub_request(:get, "https://api.knoxcall.com/v1/account").to_return(
        status: 200,
        body: JSON.generate(data: { name: "no slug here" }),
        headers: { "Content-Type" => "application/json" }
      )

      client = KnoxCall::Client.new(access_token: "kc_live_pre", retry_base_delay: 0.001)
      expect { client.call("r_1", path: "/x") }
        .to raise_error(KnoxCall::Error, /KNOXCALL_TENANT/)
    end

    it "management requests need no tenant and trigger no discovery" do
      envelope = { "data" => [],
                   "meta" => { "total" => 0, "page" => 1, "per_page" => 20,
                               "total_pages" => 0, "request_id" => "req-0" } }
      stub_request(:post, "https://api.example.test/oauth/token").to_return(token_body)
      stub_request(:get, "https://api.example.test/v1/routes").to_return(
        status: 200, body: JSON.generate(envelope), headers: { "Content-Type" => "application/json" }
      )

      client = KnoxCall::Client.new(
        client_id: "tk_x", client_secret: "s",
        base_url: "https://api.example.test", retry_base_delay: 0.001
      )
      # The client core stays envelope-agnostic — unwrapping lives in the
      # resource layer (PARITY §4).
      expect(client.request("GET", "/v1/routes")).to eq(envelope)
      expect(client.tenant).to be_nil
    end

    it "supports zero-arg construction with a fully configured environment" do
      ENV["KNOXCALL_TENANT"] = "envcorp"
      ENV["KNOXCALL_CLIENT_ID"] = "tk_env"
      ENV["KNOXCALL_CLIENT_SECRET"] = "sec"
      expect(KnoxCall::Client.new.tenant).to eq("envcorp")
    end
  end

  # -- Env credential fill -----------------------------------------------------------

  describe "env credential fill" do
    it "skips env fill entirely when an explicit credential is passed" do
      ENV["KNOXCALL_ACCESS_TOKEN"] = "kc_live_env"
      stub_request(:post, token_url).to_return(token_body("kc_live_minted"))
      seen = {}
      stub_request(:get, "#{proxy}/x")
        .with { |req| seen.merge!(headers_of(req)); true }
        .to_return(status: 200)

      new_client(client_id: "tk_x", client_secret: "sec").call("r_1", path: "/x")

      expect(a_request(:post, token_url)).to have_been_made.once
      expect(seen["authorization"]).to eq("Bearer kc_live_minted")
    end

    it "lets KNOXCALL_ACCESS_TOKEN win over KNOXCALL_API_KEY without raising" do
      ENV["KNOXCALL_ACCESS_TOKEN"] = "kc_live_envtok"
      ENV["KNOXCALL_API_KEY"] = "kc_live_envkey"
      seen = {}
      stub_request(:get, "#{proxy}/x")
        .with { |req| seen.merge!(headers_of(req)); true }
        .to_return(status: 200)

      new_client.call("r_1", path: "/x")
      expect(seen["authorization"]).to eq("Bearer kc_live_envtok")
    end
  end

  # -- Base URL env vars ----------------------------------------------------------

  describe "base URL resolution" do
    it "prefers canonical KNOXCALL_BASE_URL over legacy KNOXCALL_API_BASE_URL" do
      ENV["KNOXCALL_BASE_URL"] = "https://canonical.example.test"
      ENV["KNOXCALL_API_BASE_URL"] = "https://legacy.example.test"
      client = KnoxCall::Client.new(tenant: "acme", access_token: "kc_live_x")
      expect(client.instance_variable_get(:@base_url)).to eq("https://canonical.example.test")
    end

    it "still accepts the legacy KNOXCALL_API_BASE_URL spelling" do
      ENV["KNOXCALL_API_BASE_URL"] = "https://legacy.example.test"
      client = KnoxCall::Client.new(tenant: "acme", access_token: "kc_live_x")
      expect(client.instance_variable_get(:@base_url)).to eq("https://legacy.example.test")
    end
  end

  # -- Sandbox / Test mode (PARITY §2) ----------------------------------------------

  describe "sandbox mode" do
    it "defaults the management base and data plane to the sandbox hosts" do
      mgmt = stub_request(:get, "https://sandbox.knoxcall.com/v1/routes").to_return(
        status: 200, body: '{"data":[],"meta":{"total":0,"page":1,"per_page":20,"total_pages":0,"request_id":"req-0"}}'
      )
      proxied = stub_request(:get, "https://sandbox-acme.knoxcall.com/api/x").to_return(status: 200, body: "{}")

      client = KnoxCall::Client.new(sandbox: true, tenant: "acme", api_key: "kc_test_x",
                                    retry_base_delay: 0.001)
      client.request("GET", "/v1/routes")
      # Data plane lives on the sandbox- prefixed per-tenant subdomain.
      client.call("r_1", path: "/x")

      expect(mgmt).to have_been_requested.once
      expect(proxied).to have_been_requested.once
    end

    it "lets an explicit base_url beat the sandbox default (self-hosted shape)" do
      proxied = stub_request(:get, "https://api.example.test/x").to_return(status: 200)

      client = KnoxCall::Client.new(sandbox: true, tenant: "acme", api_key: "kc_test_x",
                                    base_url: "https://api.example.test", retry_base_delay: 0.001)
      client.call("r_1", path: "/x")

      expect(proxied).to have_been_requested.once
    end

    it "lets KNOXCALL_BASE_URL beat the sandbox default" do
      ENV["KNOXCALL_BASE_URL"] = "https://canonical.example.test"
      mgmt = stub_request(:get, "https://canonical.example.test/v1/routes").to_return(
        status: 200, body: '{"data":[],"meta":{"total":0,"page":1,"per_page":20,"total_pages":0,"request_id":"req-0"}}'
      )

      client = KnoxCall::Client.new(sandbox: true, tenant: "acme", api_key: "kc_test_x",
                                    retry_base_delay: 0.001)
      client.request("GET", "/v1/routes")

      expect(mgmt).to have_been_requested.once
    end

    it "derives the sandbox- proxy shape from a discovered tenant" do
      stub_request(:get, "https://sandbox.knoxcall.com/v1/account").to_return(
        status: 200,
        body: JSON.generate(data: { slug: "fromaccount", name: "X" }),
        headers: { "Content-Type" => "application/json" }
      )
      proxied = stub_request(:get, "https://sandbox-fromaccount.knoxcall.com/api/x").to_return(status: 200)

      client = KnoxCall::Client.new(sandbox: true, access_token: "kc_test_pre", retry_base_delay: 0.001)
      client.call("r_1", path: "/x")

      expect(proxied).to have_been_requested.once
      expect(client.tenant).to eq("fromaccount")
    end
  end

  # -- Bound routes ----------------------------------------------------------------

  describe "bound routes" do
    it "injects route, environment, and bound headers" do
      seen = {}
      stub_request(:get, "#{proxy}/computers")
        .with { |req| seen.merge!(headers_of(req)); true }
        .to_return(status: 200, body: '{"ok":true}')

      printnode = new_client(access_token: "kc_live_x")
                  .route("r_1", environment: "production", headers: { "X-A" => "bound" })
      res = printnode.get("/computers")

      expect(res.code).to eq("200")
      expect(seen["x-knoxcall-route"]).to eq("r_1")
      expect(seen["x-knoxcall-environment"]).to eq("production")
      expect(seen["x-a"]).to eq("bound")
    end

    it "lets per-call values beat the bound defaults" do
      seen = {}
      stub_request(:post, "#{proxy}/printjobs")
        .with { |req| seen.merge!(headers_of(req)); true }
        .to_return(status: 200)

      bound = new_client(access_token: "kc_live_x")
              .route("r_1", environment: "production", headers: { "X-A" => "bound" })
      bound.post("/printjobs", body: { a: 1 }, environment: "staging", headers: { "X-A" => "call" })

      expect(seen["x-knoxcall-environment"]).to eq("staging")
      expect(seen["x-a"]).to eq("call")
    end

    it "exposes a generic request method" do
      del = stub_request(:delete, "#{proxy}/printjobs/42").to_return(status: 200)

      new_client(access_token: "kc_live_x").route("r_1").request("DELETE", "/printjobs/42")
      expect(del).to have_been_requested.once
    end
  end

  # -- Default environment (PARITY §2) --------------------------------------------

  describe "default environment" do
    def env_header_for(client)
      seen = {}
      stub_request(:get, "#{proxy}/x")
        .with { |req| seen[:env] = headers_of(req)["x-knoxcall-environment"]; true }
        .to_return(status: 200, body: '{"ok":true}')
      yield client
      seen[:env]
    end

    it "applies the client-level environment to call()" do
      client = new_client(access_token: "kc_live_x", environment: "production")
      expect(env_header_for(client) { |c| c.call("r_1", path: "/x") }).to eq("production")
    end

    it "resolves per-call > bound > client" do
      client = new_client(access_token: "kc_live_x", environment: "client-env")

      expect(env_header_for(client) { |c| c.route("r_1").get("/x") }).to eq("client-env")
      expect(env_header_for(client) { |c| c.route("r_1", environment: "bound-env").get("/x") }).to eq("bound-env")
      expect(
        env_header_for(client) { |c| c.route("r_1", environment: "bound-env").get("/x", environment: "call-env") }
      ).to eq("call-env")
    end

    it "falls back to KNOXCALL_ENVIRONMENT with the explicit option winning" do
      ENV["KNOXCALL_ENVIRONMENT"] = "staging"

      client = new_client(access_token: "kc_live_x")
      expect(env_header_for(client) { |c| c.call("r_1", path: "/x") }).to eq("staging")

      explicit = new_client(access_token: "kc_live_x", environment: "production")
      expect(env_header_for(explicit) { |c| c.call("r_1", path: "/x") }).to eq("production")
    end
  end
end
