# Error typing + Shape-C precedence (M4) and the typed OAuth2 / certificate
# secret creators (M3). Mirrors the Node SDK's errorFromResponse
# (sdk/knoxcall-node/src/error.ts) and secrets resource in Ruby idiom:
#
#   * 409 -> ConflictError, 422 -> ValidationError (previously fell through to
#     the generic APIError, so callers could not rescue them).
#   * The server's error envelope comes in three shapes; the flat Shape-C body
#     {error:"<code>", message:"<human>"} must surface the HUMAN message while
#     still recording the code. The old precedence returned the code as the
#     message and dropped the human text.
#   * Every error carries #code / #type / #request_id, with the X-Request-Id
#     response header preferred over the body id.
#
# Every mock here is the REAL server shape (src/client-api/helpers.ts).

RSpec.describe "KnoxCall error typing and typed secret creation" do
  ERR_API = "https://api.example.test".freeze

  # A pre-acquired kc_ token: no token-endpoint round trip, so stub #N is API
  # call #N (matches spec/resources_spec.rb).
  def new_client(**opts)
    KnoxCall::Client.new(
      tenant: "acme",
      base_url: ERR_API,
      proxy_base_url: "https://acme.example.test",
      api_key: "kc_live_x",
      retry_base_delay: 0.001,
      **opts
    )
  end

  def envelope(data)
    { data: data, meta: { request_id: "req-#{rand(10_000)}" } }
  end

  # Stub a >= 400 error response with an optional X-Request-Id header.
  def stub_error(method, url, status:, body:, headers: {})
    stub_request(method, url).to_return(
      status: status,
      body: JSON.generate(body),
      headers: { "Content-Type" => "application/json" }.merge(headers)
    )
  end

  # -- Status -> typed class (M4a) --------------------------------------------

  describe "status to typed error class" do
    it "maps 409 to ConflictError (previously a generic APIError)" do
      stub_error(:post, "#{ERR_API}/v1/secrets", status: 409,
                 body: { error: { type: "conflict", message: "A secret named 'db' already exists" } })

      expect { new_client.secrets.create(name: "db", value: "x") }
        .to raise_error(KnoxCall::ConflictError, /already exists/)
    end

    it "maps 422 to ValidationError and exposes the per-field breakdown" do
      stub_error(:post, "#{ERR_API}/v1/secrets", status: 422,
                 body: { error: { type: "validation_error", message: "name is required",
                                  request_id: "req-v1" },
                         fields: { name: ["is required"] } })

      begin
        new_client.secrets.create(value: "x")
        raise "expected ValidationError"
      rescue KnoxCall::ValidationError => e
        expect(e.message).to include("name is required")
        expect(e.status_code).to eq(422)
        expect(e.code).to eq("validation_error")
        expect(e.fields).to eq("name" => ["is required"])
      end
    end

    it "keeps ConflictError and ValidationError rescuable as APIError" do
      expect(KnoxCall::ConflictError.ancestors).to include(KnoxCall::APIError)
      expect(KnoxCall::ValidationError.ancestors).to include(KnoxCall::APIError)
    end

    it "maps 402 to PaymentRequiredError with the plan_limit code (billing/quota)" do
      stub_error(:post, "#{ERR_API}/v1/secrets", status: 402,
                 body: { error: { type: "plan_limit",
                                  message: "Your plan's secret quota is exhausted — upgrade to add more",
                                  request_id: "req-402" } })

      begin
        new_client.secrets.create(name: "db", value: "x")
        raise "expected PaymentRequiredError"
      rescue KnoxCall::PaymentRequiredError => e
        expect(e.message).to include("upgrade to add more")
        expect(e.status_code).to eq(402)
        expect(e.code).to eq("plan_limit")
        expect(e.type).to eq("plan_limit") # #type is an alias for #code
        expect(e.request_id).to eq("req-402")
      end
    end

    it "keeps PaymentRequiredError rescuable as APIError and distinct from PermissionDeniedError (403)" do
      expect(KnoxCall::PaymentRequiredError.ancestors).to include(KnoxCall::APIError)
      expect(KnoxCall::PaymentRequiredError).not_to equal(KnoxCall::PermissionDeniedError)
    end
  end

  # -- Shape-C precedence (M4b) -----------------------------------------------

  describe "flat Shape-C body {error:'<code>', message:'<human>'}" do
    it "surfaces the human message, not the bare code, and records the code" do
      stub_error(:post, "#{ERR_API}/v1/secrets", status: 409,
                 body: { error: "idempotency_key_reuse",
                         message: "An idempotency key was reused with a different request body" })

      begin
        new_client.secrets.create(name: "db", value: "x")
        raise "expected ConflictError"
      rescue KnoxCall::ConflictError => e
        expect(e.message).to include("An idempotency key was reused")
        expect(e.message).not_to include("idempotency_key_reuse") # the CODE never becomes the message
        expect(e.code).to eq("idempotency_key_reuse")
      end
    end

    it "prefers error_description, then message, over the bare error string" do
      stub_error(:get, "#{ERR_API}/v1/secrets", status: 400,
                 body: { error: "invalid_request",
                         error_description: "the environment filter is unknown" })

      expect { new_client.secrets.list }
        .to raise_error(KnoxCall::APIError, /the environment filter is unknown/) do |e|
          expect(e.code).to eq("invalid_request")
        end
    end
  end

  # -- Shape-A canonical envelope + accessors (M4c) ---------------------------

  describe "canonical Shape-A envelope {error:{type,message,request_id}}" do
    it "populates code, type, and request_id from the body" do
      stub_error(:get, "#{ERR_API}/v1/secrets", status: 403,
                 body: { error: { type: "forbidden", message: "missing scope secrets:read",
                                  request_id: "req-body-9" } })

      begin
        new_client.secrets.list
        raise "expected PermissionDeniedError"
      rescue KnoxCall::PermissionDeniedError => e
        expect(e.message).to include("missing scope secrets:read")
        expect(e.code).to eq("forbidden")
        expect(e.type).to eq("forbidden") # #type is an alias for #code
        expect(e.request_id).to eq("req-body-9")
      end
    end

    it "prefers the X-Request-Id response header over the body request_id" do
      stub_error(:get, "#{ERR_API}/v1/secrets", status: 404,
                 body: { error: { type: "not_found", message: "no such secret",
                                  request_id: "req-body" } },
                 headers: { "X-Request-Id" => "req-header" })

      begin
        new_client.secrets.list
        raise "expected NotFoundError"
      rescue KnoxCall::NotFoundError => e
        expect(e.request_id).to eq("req-header")
      end
    end
  end

  # -- Typed secret creators (M3) ---------------------------------------------

  describe "secrets.create_oauth2" do
    it "POSTs /v1/secrets/oauth2 with the required + supplied optional fields" do
      sent = nil
      stub_request(:post, "#{ERR_API}/v1/secrets/oauth2")
        .with { |req| sent = JSON.parse(req.body); true }
        .to_return(status: 201, body: JSON.generate(envelope({ id: "s_1", name: "gh",
                                                               secret_type: "oauth2" })))

      out = new_client.secrets.create_oauth2(
        name: "gh", provider: "github", client_id: "cid", client_secret: "csec",
        scopes: %w[repo user], token_url: "https://github.test/token", collection_id: "c_1"
      )

      expect(sent).to eq(
        "name" => "gh", "provider" => "github", "client_id" => "cid",
        "client_secret" => "csec", "scopes" => %w[repo user],
        "token_url" => "https://github.test/token", "collection_id" => "c_1"
      )
      expect(out).to eq("id" => "s_1", "name" => "gh", "secret_type" => "oauth2")
    end

    it "omits optional fields that were not given" do
      sent = nil
      stub_request(:post, "#{ERR_API}/v1/secrets/oauth2")
        .with { |req| sent = JSON.parse(req.body); true }
        .to_return(status: 201, body: JSON.generate(envelope({ id: "s_2" })))

      new_client.secrets.create_oauth2(name: "gl", provider: "gitlab", client_id: "cid2")

      expect(sent.keys).to contain_exactly("name", "provider", "client_id")
    end
  end

  describe "secrets.create_certificate" do
    it "POSTs /v1/secrets/certificate and defaults certificate_type to pem" do
      sent = nil
      stub_request(:post, "#{ERR_API}/v1/secrets/certificate")
        .with { |req| sent = JSON.parse(req.body); true }
        .to_return(status: 201, body: JSON.generate(envelope({ id: "s_3", secret_type: "certificate" })))

      out = new_client.secrets.create_certificate(
        name: "mtls", certificate_content: "-----BEGIN CERTIFICATE-----", private_key: "-----BEGIN KEY-----"
      )

      expect(sent).to eq(
        "name" => "mtls", "certificate_content" => "-----BEGIN CERTIFICATE-----",
        "certificate_type" => "pem", "private_key" => "-----BEGIN KEY-----"
      )
      expect(out).to eq("id" => "s_3", "secret_type" => "certificate")
    end

    it "passes an explicit certificate_type through" do
      sent = nil
      stub_request(:post, "#{ERR_API}/v1/secrets/certificate")
        .with { |req| sent = JSON.parse(req.body); true }
        .to_return(status: 201, body: JSON.generate(envelope({ id: "s_4" })))

      new_client.secrets.create_certificate(name: "pfx", certificate_content: "base64...",
                                            certificate_type: "pfx", passphrase: "pw")

      expect(sent["certificate_type"]).to eq("pfx")
      expect(sent["passphrase"]).to eq("pw")
    end
  end
end
